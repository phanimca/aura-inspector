# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import logging
import re

from colored_logger import logger
from aura_helper import AuraActionHelper
from scanners.base_scanner import BaseScanner, Severity

_log = logging.getLogger(__name__)


# Patterns in error messages that indicate the Apex class runs in system/without-sharing mode
_SYSTEM_MODE_PATTERNS = [
	r'without\s+sharing',
	r'System\.runAs',
	r'SELECT\s+\w+.*FROM\s+\w+',   # raw SOQL in error output
	r'DmlException',
	r'java\.lang\.',
	r'Salesforce\.com\s+error',
]

# Probe inputs designed to trigger different code paths in Apex controllers
_PROBE_PARAMS = [
	{'searchTerm': '%', 'query': '%', 'name': '%'},
	{'searchTerm': "' OR '1'='1", 'query': "' OR '1'='1"},
	{'searchTerm': '', 'query': '', 'name': ''},
	{'pageSize': 1000, 'currentPage': 0},
]

# Maximum records in a single response that we consider "suspiciously large"
_LARGE_RESULT_THRESHOLD = 20


class ApexScanner(BaseScanner):
	"""
	Probes custom Apex controllers for system-mode execution indicators:
	  - Large unrestricted result sets (no WITH SHARING / WITH USER_MODE)
	  - Internal error messages leaking SOQL or implementation details
	  - Wildcard query acceptance
	"""

	SCANNER_NAME = 'ApexScanner'

	def scan(self) -> list:
		_log.info('[ApexScanner] Starting Apex system-mode detection scan')
		custom_controllers = self.aura.get_custom_controllers()
		if custom_controllers:
			_log.info('[ApexScanner] Probing %d custom controllers', len(custom_controllers))
			for controller in custom_controllers[:15]:   # cap to limit traffic
				self._probe_controller(controller)
		else:
			_log.debug('[ApexScanner] No custom controllers found')
		self._test_self_registration_leak()
		return self.findings

	def _probe_controller(self, controller: str):
		"""Call a single custom controller with each probe input set."""
		for params in _PROBE_PARAMS[:2]:   # 2 probe sets per controller keeps traffic bounded
			action = AuraActionHelper.build_action('1;a', controller, params)
			try:
				response = self.aura.send_aura_bulk([action])
				if not response.actions_responses:
					continue
				resp = response.actions_responses[0]
				self._check_large_result(controller, params, resp)
				self._check_error_leak(controller, params, resp)
			except Exception:
				_log.debug('[ApexScanner] probe failed for %s', controller, exc_info=True)

	def _check_large_result(self, controller, params, resp):
		"""Flag if a success response returns an unexpectedly large record set."""
		if not (resp.is_success() and resp.return_value):
			return
		result = resp.return_value
		record_count = None
		if isinstance(result, list):
			record_count = len(result)
		elif isinstance(result, dict):
			for key in ('records', 'results', 'data', 'items'):
				if isinstance(result.get(key), list):
					record_count = len(result[key])
					break
		if record_count is not None and record_count > _LARGE_RESULT_THRESHOLD:
			self._add_finding(
				title=f'Custom Controller Returns Oversized Dataset ({controller.split("/")[-1]})',
				severity=Severity.HIGH,
				description=(
					f'Controller {controller} returned {record_count} records in a single guest '
					f'user call. This strongly suggests the Apex class runs without sharing '
					f'restrictions (no WITH SHARING or WITH USER_MODE keyword).'
				),
				evidence=f'controller={controller}, probe_params={list(params.keys())}, records_returned={record_count}',
				remediation=(
					'Add the "with sharing" keyword to the Apex class declaration.\n'
					'Replace raw SOQL with: [SELECT ... FROM Object WITH USER_MODE].\n'
					'Use Security.stripInaccessible(AccessType.READABLE, records) before returning data.'
				),
				owasp_ref='API3:2023 Broken Object Property Level Authorization',
				affected_objects=[controller],
			)

	def _check_error_leak(self, controller, params, resp):
		"""Flag if an error response contains internal implementation details."""
		if resp.is_success():
			return
		error_text = str(resp.error_message or '')
		for pattern in _SYSTEM_MODE_PATTERNS:
			if re.search(pattern, error_text, re.IGNORECASE):
				self._add_finding(
					title=f'Internal Error Leak in Custom Controller ({controller.split("/")[-1]})',
					severity=Severity.MEDIUM,
					description=(
						f'Controller {controller} returned an error message containing internal '
						f'system details matching pattern "{pattern}". '
						f'Error messages can guide attackers toward exploitable code paths.'
					),
					evidence=f'controller={controller}, matched_pattern={pattern}, error_preview={error_text[:200]}',
					remediation=(
						'Wrap controller logic in a try/catch block.\n'
						'Return a generic AuraHandledException message instead of raw exception text:\n'
						'  throw new AuraHandledException("An unexpected error occurred.");'
					),
					owasp_ref='API8:2023 Security Misconfiguration',
					affected_objects=[controller],
				)
				break   # one finding per controller per call

	def _test_self_registration_leak(self):
		"""Test if a custom self-registration controller leaks org configuration."""
		_log.debug('[ApexScanner] Testing self-registration controller')
		candidate_descriptors = [
			'c/SelfRegistration/ACTION$getAvailableOptions',
			'c/CommunitiesSelfRegController/ACTION$getAvailableOptions',
		]
		for descriptor in candidate_descriptors:
			action = AuraActionHelper.build_action('1;a', descriptor, {})
			try:
				response = self.aura.send_aura_bulk([action])
				if not response.actions_responses:
					continue
				resp = response.actions_responses[0]
				if resp.is_success() and resp.return_value:
					ret_str = json.dumps(resp.return_value)
					if any(k in ret_str for k in ('orgId', 'profileId', 'roleId', 'email')):
						self._add_finding(
							title='Self-Registration Controller Leaks Org/Profile IDs',
							severity=Severity.MEDIUM,
							description=(
								'The self-registration controller response contains internal Salesforce '
								'identifiers (orgId, profileId, or roleId). This aids attacker reconnaissance '
								'and may enable targeted profile enumeration.'
							),
							evidence=f'Descriptor: {descriptor}, response contains internal ID fields',
							remediation=(
								'Strip internal identifiers from the self-registration controller response.\n'
								'Return only the minimum fields required for the registration form.'
							),
							owasp_ref='API3:2023 Broken Object Property Level Authorization',
						)
						break
			except Exception:
				_log.debug('[ApexScanner] Self-registration probe failed: %s', descriptor, exc_info=True)

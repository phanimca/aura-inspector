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

from colored_logger import logger
from aura_helper import AuraActionHelper
from scanners.base_scanner import BaseScanner, Severity

_log = logging.getLogger(__name__)


# Standard Salesforce objects that should NEVER be visible to guest users
SENSITIVE_OBJECTS = [
	'User', 'Profile', 'Organization', 'LoginHistory', 'AuthSession',
	'SetupEntityAccess', 'PermissionSet', 'PermissionSetAssignment',
	'UserPermissionAccess', 'AuthProvider',
]

# Additional Aura controllers beyond what aura_helper already probes
EXTRA_CONTROLLERS = [
	'serviceComponent://ui.force.components.controllers.listView.ListViewDataProviderController/ACTION$getItems',
	'serviceComponent://ui.force.components.controllers.record.RecordDataProviderController/ACTION$getRecord',
	'aura://SearchController/ACTION$search',
	'aura://LightningExperienceThemeController/ACTION$getTheme',
]


class AuraFuzzer(BaseScanner):
	"""Fuzzes Aura endpoint controllers to detect over-privileged guest user access."""

	SCANNER_NAME = 'AuraFuzzer'

	def scan(self) -> list:
		_log.info('[AuraFuzzer] Starting Aura endpoint fuzzing')
		self._test_sensitive_object_exposure()
		self._test_list_view_controller()
		self._test_record_data_controller()
		self._test_search_wildcard()
		self._test_theme_controller_info_leak()
		return self.findings

	def _test_sensitive_object_exposure(self):
		"""Check if standard sensitive objects appear in the guest-accessible object list."""
		_log.debug('[AuraFuzzer] Checking sensitive object exposure')
		try:
			all_objects = self.aura.get_objects()
			if not all_objects:
				return
			exposed = [obj for obj in SENSITIVE_OBJECTS if obj in all_objects]
			if exposed:
				self._add_finding(
					title='Sensitive Salesforce Objects Accessible to Guest User',

					severity=Severity.CRITICAL,
					description=(
						f'The following sensitive standard objects are accessible to the unauthenticated '
						f'guest user profile: {", ".join(exposed)}. '
						f'Attackers can enumerate User, Profile, and AuthSession records without credentials.'
					),
					evidence=f'Objects visible to guest: {exposed}',
					remediation=(
						'1. Go to Setup > Digital Experiences > All Sites > [Site] > Workplaces > Guest User Profile.\n'
						'2. Under Object Settings, remove Read access for each listed object.\n'
						'3. Run Setup > Security > Health Check to confirm the change.'
					),
					owasp_ref='API1:2023 Broken Object Level Authorization',
					affected_objects=exposed,
				)
		except Exception:
			_log.debug('[AuraFuzzer] Sensitive object check failed', exc_info=True)

	def _test_list_view_controller(self):
		"""Test if ListViewDataProviderController returns records to an unauthenticated caller."""
		_log.debug('[AuraFuzzer] Testing ListViewDataProviderController')
		for obj_name in ['Account', 'Contact', 'Lead']:
			action = AuraActionHelper.build_action(
				'1;a',
				'serviceComponent://ui.force.components.controllers.listView.ListViewDataProviderController/ACTION$getItems',
				{
					'entityNameOrId': obj_name,
					'listViewId': None,
					'sortBy': None,
					'pageSize': 5,
					'currentPage': 0,
					'useConsistentActivities': False,
					'refreshListViewInfo': False,
				},
			)
			try:
				response = self.aura.send_aura_bulk([action])
				if not response.actions_responses:
					continue
				resp = response.actions_responses[0]
				if resp.is_success() and resp.return_value:
					records = resp.return_value.get('records', {})
					row_count = len(records.get('records', [])) if isinstance(records, dict) else 0
					if row_count > 0:
						self._add_finding(
							title=f'List View Returns {obj_name} Records to Guest User',
							severity=Severity.HIGH,
							description=(
								f'ListViewDataProviderController returned {row_count} {obj_name} records '
								f'without authentication. This allows mass enumeration of CRM data.'
							),
							evidence=f'Controller: ListViewDataProviderController, object: {obj_name}, rows returned: {row_count}',
							remediation=(
								'Set the org-wide default for this object to Private.\n'
								'Create an explicit Criteria-Based Sharing Rule for objects that genuinely '
								'need partial guest visibility (e.g., Status = "Public").'
							),
							owasp_ref='API1:2023 Broken Object Level Authorization',
							affected_objects=[obj_name],
						)
						break  # One finding is enough to illustrate the issue
			except Exception:
				_log.debug('[AuraFuzzer] ListViewDataProviderController probe failed', exc_info=True)

	def _test_record_data_controller(self):
		"""Test if RecordDataProviderController is callable by a guest user."""
		_log.debug('[AuraFuzzer] Testing RecordDataProviderController')
		action = AuraActionHelper.build_action(
			'1;a',
			'serviceComponent://ui.force.components.controllers.record.RecordDataProviderController/ACTION$getRecord',
			{'recordId': '0010000000000001AAA', 'fields': ['Account.Name']},
		)
		try:
			response = self.aura.send_aura_bulk([action])
			if not response.actions_responses:
				return
			resp = response.actions_responses[0]
			if resp.is_success() and resp.return_value:
				self._add_finding(
					title='RecordDataProviderController Accessible to Guest User',
					severity=Severity.HIGH,
					description=(
						'The RecordDataProviderController returned a success response for an unauthenticated '
						'guest user. This exposes a direct record-read attack surface for IDOR exploitation.'
					),
					evidence='RecordDataProviderController returned HTTP 200 SUCCESS for guest',
					remediation=(
						'Audit which objects are accessible via this controller to the guest profile.\n'
						'Enforce WITH USER_MODE in all Apex queries behind this controller.\n'
						'Review Field-Level Security for all fields returned.'
					),
					owasp_ref='API5:2023 Broken Function Level Authorization',
				)
		except Exception:
			_log.debug('[AuraFuzzer] RecordDataProviderController probe failed', exc_info=True)

	def _test_search_wildcard(self):
		"""Test if the search controller accepts wildcard queries without auth."""
		_log.debug('[AuraFuzzer] Testing search wildcard exposure')
		action = AuraActionHelper.build_action(
			'1;a',
			'aura://SearchController/ACTION$search',
			{'searchTerm': '%', 'resultLimit': 50},
		)
		try:
			response = self.aura.send_aura_bulk([action])
			if not response.actions_responses:
				return
			resp = response.actions_responses[0]
			if resp.is_success() and resp.return_value:
				results = resp.return_value if isinstance(resp.return_value, list) else resp.return_value.get('results', [])
				if results:
					self._add_finding(
						title='Search Controller Returns Results for Wildcard Guest Query',
						severity=Severity.MEDIUM,
						description=(
							f'SearchController returned {len(results)} results for a "%" wildcard query '
							f'without authentication. This indicates the search runs in system mode '
							f'or the guest profile has excessive read permissions.'
						),
						evidence=f'SearchController(%) returned {len(results)} results',
						remediation=(
							'Add "with sharing" to the Apex class backing the search controller.\n'
							'Use WITH USER_MODE in the SOQL query.\n'
							'Validate and sanitize search inputs to reject wildcard characters.'
						),
						owasp_ref='API8:2023 Security Misconfiguration',
					)
		except Exception:
			_log.debug('[AuraFuzzer] SearchController probe failed', exc_info=True)

	def _test_theme_controller_info_leak(self):
		"""Test if the theme controller leaks internal org configuration."""
		_log.debug('[AuraFuzzer] Testing theme controller info leak')
		action = AuraActionHelper.build_action(
			'1;a',
			'aura://LightningExperienceThemeController/ACTION$getTheme',
			{},
		)
		try:
			response = self.aura.send_aura_bulk([action])
			if not response.actions_responses:
				return
			resp = response.actions_responses[0]
			if resp.is_success() and resp.return_value:
				ret_str = json.dumps(resp.return_value)
				if 'orgId' in ret_str or 'instanceUrl' in ret_str or 'orgName' in ret_str:
					self._add_finding(
						title='Theme Controller Leaks Org Metadata to Guest User',
						severity=Severity.LOW,
						description=(
							'The LightningExperienceThemeController returned org-level metadata '
							'(orgId, instanceUrl, or orgName) without authentication. '
							'This information aids attacker reconnaissance.'
						),
						evidence='ThemeController response contains org metadata fields',
						remediation=(
							'Review the theme controller Apex class and strip org-identifying fields '
							'from the response before returning data to unauthenticated callers.'
						),
						owasp_ref='API8:2023 Security Misconfiguration',
					)
		except Exception:
			_log.debug('[AuraFuzzer] ThemeController probe failed', exc_info=True)

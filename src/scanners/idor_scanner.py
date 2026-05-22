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


# Standard Salesforce object key prefixes (first 3 chars of a 15/18-char record ID)
SF_KEY_PREFIXES = {
	'001': 'Account',
	'003': 'Contact',
	'005': 'User',
	'006': 'Opportunity',
	'00Q': 'Lead',
	'500': 'Case',
	'0Q0': 'Quote',
	'01I': 'RecordType',
	'00e': 'Profile',
	'0D5': 'ContentVersion',
	'069': 'ContentDocument',
}

# Regex that loosely matches a Salesforce 15- or 18-char record ID
_SF_ID_PATTERN = re.compile(r'\b([A-Za-z0-9]{3})([A-Za-z0-9]{12,15})\b')


class IDORScanner(BaseScanner):
	"""Tests for Insecure Direct Object Reference (IDOR) vulnerabilities via Aura controllers."""

	SCANNER_NAME = 'IDORScanner'

	def scan(self) -> list:
		_log.info('[IDORScanner] Starting IDOR vulnerability scan')
		sample_ids = self._collect_sample_record_ids()
		if sample_ids:
			self._test_direct_record_access(sample_ids)
			self._test_cross_object_id_swap(sample_ids)
		self._test_record_ui_controller_availability()
		return self.findings

	# ------------------------------------------------------------------
	# Step 1: gather some real record IDs from the site's home URLs
	# ------------------------------------------------------------------

	def _collect_sample_record_ids(self) -> dict:
		"""
		Extract sample record IDs from object home URLs returned by the
		existing get_object_home_urls() helper.

		Returns {object_name: record_id_string}.
		"""
		_log.debug('[IDORScanner] Collecting sample record IDs from home URLs')
		sample_ids = {}
		try:
			home_urls = self.aura.get_object_home_urls()
			for obj_name, url in (home_urls or {}).items():
				if not url:
					continue
				m = _SF_ID_PATTERN.search(url)
				if m:
					sample_ids[obj_name] = m.group(0)
		except Exception:
			_log.debug('[IDORScanner] Failed to collect sample record IDs', exc_info=True)
		_log.debug('[IDORScanner] Collected %d sample IDs: %s', len(sample_ids), list(sample_ids.keys()))
		return sample_ids

	# ------------------------------------------------------------------
	# Step 2: test direct record access via RecordUiController
	# ------------------------------------------------------------------

	def _test_direct_record_access(self, sample_ids: dict):
		"""
		For each sampled record, attempt a direct RecordUiController/ACTION$getRecord call
		as the current user (guest or authenticated).  A SUCCESS response means the record
		is readable without any additional sharing check.
		"""
		_log.debug('[IDORScanner] Testing direct record access')
		for obj_name, record_id in list(sample_ids.items())[:5]:
			action = AuraActionHelper.build_action(
				'1;a',
				'aura://RecordUiController/ACTION$getRecord',
				{'recordId': record_id},
			)
			try:
				response = self.aura.send_aura_bulk([action])
				if not response.actions_responses:
					continue
				resp = response.actions_responses[0]
				if resp.is_success() and resp.return_value:
					self._add_finding(
						title=f'Direct Record Access: {obj_name} Readable via RecordUiController',
						severity=Severity.HIGH,
						description=(
							f'The current user can read a {obj_name} record by ID directly via '
							f'RecordUiController without any additional authorization check. '
							f'An attacker can enumerate any {obj_name} records if they know or guess the ID.'
						),
						evidence=f'Record ID {record_id} returned SUCCESS from RecordUiController',
						remediation=(
							'Enforce sharing rules on the guest user profile for this object.\n'
							'Add explicit WITH USER_MODE to any Apex SOQL backing this controller.\n'
							'Set the org-wide default for this object to Private and create '
							'Criteria-Based Sharing Rules for only the records that must be public.'
						),
						owasp_ref='API1:2023 Broken Object Level Authorization',
						affected_objects=[obj_name],
					)
			except Exception:
				_log.debug('[IDORScanner] Direct record access probe failed', exc_info=True)

	# ------------------------------------------------------------------
	# Step 3: attempt cross-object ID prefix swap
	# ------------------------------------------------------------------

	def _test_cross_object_id_swap(self, sample_ids: dict):
		"""
		Replace the 3-char object prefix of a known accessible record ID
		with the prefix of a different (potentially sensitive) object.
		A SUCCESS response is a critical IDOR.
		"""
		_log.debug('[IDORScanner] Testing cross-object ID prefix swap')
		target_prefixes = {k: v for k, v in SF_KEY_PREFIXES.items()
						   if v not in sample_ids and v in ['User', 'Profile', 'Contact', 'Organization']}

		for src_obj, src_id in list(sample_ids.items())[:2]:
			for new_prefix, target_obj in target_prefixes.items():
				# Rebuild ID: replace first 3 chars with the target object prefix
				test_id = new_prefix + src_id[3:]
				action = AuraActionHelper.build_action(
					'1;a',
					'aura://RecordUiController/ACTION$getRecord',
					{'recordId': test_id},
				)
				try:
					response = self.aura.send_aura_bulk([action])
					if not response.actions_responses:
						continue
					resp = response.actions_responses[0]
					if resp.is_success() and resp.return_value:
						self._add_finding(
							title=f'Cross-Object IDOR: {src_obj} ID Exposes {target_obj} Data',
							severity=Severity.CRITICAL,
							description=(
								f'Swapping the object prefix of a {src_obj} record ID to the '
								f'{target_obj} prefix succeeded. An attacker can access {target_obj} '
								f'records without any {target_obj}-level authorization.'
							),
							evidence=f'Original ID prefix {src_id[:3]} ({src_obj}) swapped to {new_prefix} ({target_obj}): got SUCCESS',
							remediation=(
								'Implement strict object-type validation before executing RecordUiController '
								'queries. Never trust the prefix embedded in a user-supplied record ID.\n'
								'Enforce sharing rules and WITH USER_MODE in all Apex controllers.'
							),
							owasp_ref='API1:2023 Broken Object Level Authorization',
							affected_objects=[src_obj, target_obj],
						)
						break
				except Exception:
					_log.debug('[IDORScanner] Cross-object ID swap probe failed', exc_info=True)

	# ------------------------------------------------------------------
	# Step 4: confirm whether RecordUiController is accessible at all
	# ------------------------------------------------------------------

	def _test_record_ui_controller_availability(self):
		"""
		Send a call with a syntactically valid but non-existent record ID.
		An ERROR (not a network failure) means the controller is reachable —
		a prerequisite for all IDOR attacks against it.
		"""
		_log.debug('[IDORScanner] Testing RecordUiController availability')
		probe_ids = ['0010000000000001AAA', '0030000000000001AAA']
		reachable_prefixes = []
		for probe_id in probe_ids:
			action = AuraActionHelper.build_action(
				'1;a',
				'aura://RecordUiController/ACTION$getRecord',
				{'recordId': probe_id},
			)
			try:
				response = self.aura.send_aura_bulk([action])
				if response.actions_responses:
					# Either SUCCESS or ERROR means the endpoint is reachable
					reachable_prefixes.append(probe_id[:3])
			except Exception:
				_log.debug('[IDORScanner] RecordUiController availability probe failed', exc_info=True)

		if reachable_prefixes:
			self._add_finding(
				title='RecordUiController Endpoint Reachable by Current User',
				severity=Severity.MEDIUM,
				description=(
					'The RecordUiController API responds to requests from the current user. '
					'This is the primary attack surface for IDOR attempts against Salesforce records. '
					'Sharing rules and object-level security become the only barrier.'
				),
				evidence=f'Reachable for object prefixes: {reachable_prefixes}',
				remediation=(
					'Verify that all objects accessible through this controller have explicit '
					'sharing rules configured for the current user profile.\n'
					'Use Salesforce Security Health Check to audit guest profile permissions.'
				),
				owasp_ref='API5:2023 Broken Function Level Authorization',
			)

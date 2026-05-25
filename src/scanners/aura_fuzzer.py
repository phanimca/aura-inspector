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
from urllib.parse import urljoin, urlparse

from colored_logger import logger
from aura_helper import AuraActionHelper
from scanners.base_scanner import BaseScanner, Severity

_log = logging.getLogger(__name__)


# Standard Salesforce objects that should NEVER be visible to guest users
SENSITIVE_OBJECTS = [
	'User', 'Profile', 'Organization', 'LoginHistory', 'AuthSession',
	'SetupEntityAccess', 'PermissionSet', 'PermissionSetAssignment',
	'UserPermissionAccess', 'AuthProvider',
	# File / attachment objects
	'ContentDocument', 'ContentVersion', 'ContentDocumentLink', 'Attachment',
	# Communication / PII objects
	'EmailMessage', 'FeedItem', 'Task', 'Event',
	# Org config objects
	'NamedCredential', 'ConnectedApplication', 'OAuthCustomScope',
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
		self._test_http_security_headers()
		self._test_session_cookie_security()
		self._test_content_document_access()
		self._test_screen_flow_access()
		self._test_open_redirect()
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

	# ─────────────────────────────────────────────────────────────────
	# HTTP security header analysis
	# ─────────────────────────────────────────────────────────────────

	_REQUIRED_HEADERS = {
		'Strict-Transport-Security': (
			Severity.HIGH,
			'HSTS header missing — the site can be loaded over plain HTTP, enabling MITM attacks.',
			'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
		),
		'Content-Security-Policy': (
			Severity.MEDIUM,
			'No Content-Security-Policy header. Malicious scripts injected into any page can execute freely.',
			"Add a CSP that restricts script-src to 'self' and your CDN origins.",
		),
		'X-Frame-Options': (
			Severity.MEDIUM,
			'No X-Frame-Options header. The site can be embedded in an iframe enabling clickjacking.',
			'Add: X-Frame-Options: SAMEORIGIN  (or use CSP frame-ancestors).',
		),
		'X-Content-Type-Options': (
			Severity.LOW,
			'No X-Content-Type-Options header. Browsers may MIME-sniff responses and execute unexpected content.',
			'Add: X-Content-Type-Options: nosniff',
		),
		'Referrer-Policy': (
			Severity.LOW,
			'No Referrer-Policy header. The full URL (including tokens in query strings) leaks to third-party sites.',
			'Add: Referrer-Policy: strict-origin-when-cross-origin',
		),
		'Permissions-Policy': (
			Severity.LOW,
			'No Permissions-Policy header. Browser features (camera, mic, geolocation) are unrestricted.',
			'Add: Permissions-Policy: camera=(), microphone=(), geolocation=()',
		),
	}

	def _test_http_security_headers(self):
		"""Check the site home page for missing HTTP security response headers."""
		_log.debug('[AuraFuzzer] Checking HTTP security headers')
		try:
			resp = self.aura.session.get(
				self.aura.url,
				verify=self.aura.verify,
				timeout=10,
				allow_redirects=True,
			)
			headers = {k.lower(): v for k, v in resp.headers.items()}
			for header, (severity, description, remediation) in self._REQUIRED_HEADERS.items():
				if header.lower() not in headers:
					self._add_finding(
						title=f'Missing Security Header: {header}',
						severity=severity,
						description=description,
						evidence=f'GET {self.aura.url} — header "{header}" absent from response',
						remediation=remediation,
						owasp_ref='API8:2023 Security Misconfiguration',
					)
			# Extra: flag weak CSP if present
			csp = headers.get('content-security-policy', '')
			if csp and any(v in csp for v in ("'unsafe-inline'", "'unsafe-eval'", '* ')):
				self._add_finding(
					title='Weak Content-Security-Policy Directive',
					severity=Severity.MEDIUM,
					description="The CSP contains 'unsafe-inline', 'unsafe-eval', or a wildcard (*) source that negates XSS protection.",
					evidence=f'CSP: {csp[:300]}',
					remediation="Remove 'unsafe-inline' and 'unsafe-eval'. Use nonce- or hash-based CSP instead.",
					owasp_ref='API8:2023 Security Misconfiguration',
				)
		except Exception:
			_log.debug('[AuraFuzzer] Header check failed', exc_info=True)

	# ─────────────────────────────────────────────────────────────────
	# Session cookie security flags
	# ─────────────────────────────────────────────────────────────────

	def _test_session_cookie_security(self):
		"""Verify that cookies set by the site carry Secure, HttpOnly, and SameSite flags."""
		_log.debug('[AuraFuzzer] Checking session cookie security flags')
		try:
			resp = self.aura.session.get(
				self.aura.url,
				verify=self.aura.verify,
				timeout=10,
				allow_redirects=True,
			)
			for cookie in resp.cookies:
				flags = []
				if not cookie.secure:
					flags.append('Secure flag missing')
				raw = resp.headers.get('Set-Cookie', '')
				if f'{cookie.name}=' in raw:
					if 'httponly' not in raw.lower():
						flags.append('HttpOnly flag missing')
					if 'samesite' not in raw.lower():
						flags.append('SameSite flag missing')
				if flags:
					self._add_finding(
						title=f'Insecure Cookie: {cookie.name}',
						severity=Severity.MEDIUM,
						description=(
							f'Cookie "{cookie.name}" is missing security attributes: {", ".join(flags)}. '
							f'Missing Secure allows transmission over HTTP. Missing HttpOnly enables XSS '
							f'cookie theft. Missing SameSite enables CSRF.'
						),
						evidence=f'Cookie: {cookie.name}, Issues: {", ".join(flags)}',
						remediation=(
							'Set all session cookies with: Secure; HttpOnly; SameSite=Strict\n'
							'In Salesforce: Setup > Session Settings > enable "Lock sessions to the IP address from which they originated".'
						),
						owasp_ref='API2:2023 Broken Authentication',
					)
		except Exception:
			_log.debug('[AuraFuzzer] Cookie security check failed', exc_info=True)

	# ─────────────────────────────────────────────────────────────────
	# ContentDocument / file access
	# ─────────────────────────────────────────────────────────────────

	def _test_content_document_access(self):
		"""Check if ContentDocument (Files) records are accessible to the guest user."""
		_log.debug('[AuraFuzzer] Checking ContentDocument guest access')
		action = AuraActionHelper.build_action(
			'1;a',
			'aura://RecordUiController/ACTION$getObjectInfo',
			{'objectApiName': 'ContentDocument'},
		)
		try:
			response = self.aura.send_aura_bulk([action])
			if not response.actions_responses:
				return
			resp = response.actions_responses[0]
			if resp.is_success() and resp.return_value:
				fields = resp.return_value.get('fields', {})
				self._add_finding(
					title='ContentDocument (Files) Object Accessible to Guest User',
					severity=Severity.HIGH,
					description=(
						'The guest user profile can query ContentDocument object metadata. '
						'This is the gateway to reading uploaded files and attachments without authentication.'
					),
					evidence=f'RecordUiController/getObjectInfo(ContentDocument) returned {len(fields)} field(s)',
					remediation=(
						'Remove Read access for ContentDocument and ContentVersion from the Guest User Profile.\n'
						'Ensure ContentDocumentLink sharing rules restrict file visibility to authenticated users only.'
					),
					owasp_ref='API1:2023 Broken Object Level Authorization',
					affected_objects=['ContentDocument', 'ContentVersion'],
				)
		except Exception:
			_log.debug('[AuraFuzzer] ContentDocument check failed', exc_info=True)

	# ─────────────────────────────────────────────────────────────────
	# Lightning Screen Flow accessibility
	# ─────────────────────────────────────────────────────────────────

	def _test_screen_flow_access(self):
		"""Test if Lightning Screen Flows are accessible to unauthenticated guest users."""
		_log.debug('[AuraFuzzer] Checking Screen Flow guest access')
		action = AuraActionHelper.build_action(
			'1;a',
			'aura://FlowController/ACTION$getFlowMetadata',
			{'flowDevName': 'Survey_Flow'},
		)
		try:
			response = self.aura.send_aura_bulk([action])
			if not response.actions_responses:
				return
			resp = response.actions_responses[0]
			if resp.is_success() and resp.return_value:
				self._add_finding(
					title='Lightning Screen Flow Accessible to Guest User',
					severity=Severity.MEDIUM,
					description=(
						'FlowController returned metadata for a Screen Flow without authentication. '
						'Flows running in System context can create/update records on behalf of a guest user.'
					),
					evidence='FlowController/getFlowMetadata returned SUCCESS for guest user',
					remediation=(
						'Set the Flow Run Mode to "User or System Context — Default" and verify'
						' guest user can only trigger flows that explicitly allow guest access.\n'
						'Audit each flow for DML operations that create/update records in system mode.'
					),
					owasp_ref='API5:2023 Broken Function Level Authorization',
				)
		except Exception:
			_log.debug('[AuraFuzzer] Screen Flow check failed', exc_info=True)

	# ─────────────────────────────────────────────────────────────────
	# Open redirect via aura returnUrl
	# ─────────────────────────────────────────────────────────────────

	def _test_open_redirect(self):
		"""Test if the Aura login endpoint accepts an arbitrary external returnUrl."""
		_log.debug('[AuraFuzzer] Checking open redirect via returnUrl')
		canary = 'https://evil.example.com/phish'
		test_url = f'{self.aura.url}/login?retURL={canary}'
		try:
			resp = self.aura.session.get(
				test_url,
				verify=self.aura.verify,
				timeout=10,
				allow_redirects=False,
			)
			location = resp.headers.get('Location', '')
			if resp.status_code in (301, 302, 303, 307, 308) and 'evil.example.com' in location:
				self._add_finding(
					title='Open Redirect via Login retURL Parameter',
					severity=Severity.MEDIUM,
					description=(
						'The login endpoint redirects to an arbitrary external URL supplied via the '
						'"retURL" parameter. Attackers can craft phishing links that appear to start '
						'on the legitimate Salesforce domain before redirecting to a malicious site.'
					),
					evidence=f'GET {test_url} → {resp.status_code} Location: {location}',
					remediation=(
						'Validate returnUrl against an allowlist of trusted domains before redirecting.\n'
						'Reject any retURL that does not start with the org\'s own domain.'
					),
					owasp_ref='API8:2023 Security Misconfiguration',
				)
		except Exception:
			_log.debug('[AuraFuzzer] Open redirect check failed', exc_info=True)

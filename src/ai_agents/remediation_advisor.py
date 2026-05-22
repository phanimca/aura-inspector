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

"""
Salesforce-specific remediation guidance keyed by OWASP API Security 2023 reference.

Each entry contains:
  - title        : Human-readable vulnerability class name.
  - owasp        : OWASP API Security 2023 reference string.
  - setup_steps  : Ordered list of Salesforce Setup navigation steps.
  - apex_example : Minimal Apex code snippet that demonstrates the fix.
"""

_REMEDIATION_MAP = {
	'API1': {
		'title': 'Broken Object Level Authorization (BOLA / IDOR)',
		'owasp': 'API1:2023',
		'setup_steps': [
			'Setup > Digital Experiences > All Sites > [Site] > Workplaces > Guest User Profile',
			'Under Object Settings, remove Read (and all DML) permissions for each over-exposed object.',
			'Set the object org-wide default (OWD) to Private: Setup > Sharing Settings.',
			'Create a Criteria-Based Sharing Rule to expose only the records that must be public (e.g., Status = "Published").',
			'Run Setup > Security > Health Check to confirm no guest sharing gaps remain.',
		],
		'apex_example': (
			'// Before (system mode — dangerous for guest-accessible controllers)\n'
			'List<Account> accs = [SELECT Id, Name FROM Account];\n\n'
			'// After: enforce record-level sharing\n'
			'List<Account> accs = [SELECT Id, Name FROM Account WITH USER_MODE];\n'
			'// Or add "with sharing" to the class declaration:\n'
			'public with sharing class MyController {\n'
			'    public List<Account> getAccounts() {\n'
			'        return [SELECT Id, Name FROM Account];\n'
			'    }\n'
			'}'
		),
	},
	'API3': {
		'title': 'Broken Object Property Level Authorization (Excessive Data Exposure / FLS)',
		'owasp': 'API3:2023',
		'setup_steps': [
			'Setup > Object Manager > [Object] > Fields & Relationships > [Field] > Set Field-Level Security',
			'Remove field visibility for the guest user profile on any sensitive field.',
			'Run Setup > Security > View Setup Audit Trail to review recent FLS changes.',
		],
		'apex_example': (
			'// Strip fields the running user cannot read before returning results\n'
			'SObjectAccessDecision decision = Security.stripInaccessible(\n'
			'    AccessType.READABLE, records\n'
			');\n'
			'return decision.getRecords();\n'
		),
	},
	'API5': {
		'title': 'Broken Function Level Authorization',
		'owasp': 'API5:2023',
		'setup_steps': [
			'Audit which Aura/LWC controllers are exposed on the Experience Cloud site.',
			'Remove @AuraEnabled methods from classes that guest users should not reach.',
			'Use Custom Permissions to guard privileged actions.',
		],
		'apex_example': (
			'// Guard privileged Apex actions with a Custom Permission check\n'
			'if (!FeatureManagement.checkPermission("Admin_Action")) {\n'
			'    throw new AuraHandledException("You do not have permission to perform this action.");\n'
			'}'
		),
	},
	'API8': {
		'title': 'Security Misconfiguration',
		'owasp': 'API8:2023',
		'setup_steps': [
			'Run Setup > Security > Health Check weekly and resolve any Critical Risk items.',
			'Enable Shield Platform Encryption for PII fields (if licensed).',
			'Restrict IP ranges on the guest user profile: Setup > Network Access.',
			'Review Setup > Session Settings: set session timeout to ≤ 2 hours for all profiles.',
		],
		'apex_example': (
			'// Never expose raw exception details to the caller\n'
			'try {\n'
			'    // ... business logic\n'
			'} catch (Exception e) {\n'
			'    // Log the detail internally\n'
			'    System.debug(LoggingLevel.ERROR, e.getMessage());\n'
			'    // Return a safe, generic message\n'
			'    throw new AuraHandledException("An unexpected error occurred. Please contact support.");\n'
			'}'
		),
	},
}

_FALLBACK_KEY = 'API8'


class RemediationAdvisor:
	"""Maps ScanFinding objects to Salesforce-specific remediation guidance."""

	def get_remediation(self, finding) -> dict:
		"""Return the remediation dict for the OWASP ref in *finding*."""
		owasp_ref = finding.owasp_ref or ''
		for key in _REMEDIATION_MAP:
			if key in owasp_ref:
				return _REMEDIATION_MAP[key]
		return _REMEDIATION_MAP[_FALLBACK_KEY]

	def generate_report_sections(self, findings: list) -> list:
		"""
		Return one remediation entry per unique OWASP category represented
		across the provided findings list.
		"""
		seen = set()
		sections = []
		for finding in findings:
			rem = self.get_remediation(finding)
			key = rem['owasp']
			if key not in seen:
				seen.add(key)
				sections.append(rem)
		return sections

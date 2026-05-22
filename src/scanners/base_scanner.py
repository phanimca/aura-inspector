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

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class Severity(Enum):
	CRITICAL = 'critical'
	HIGH = 'high'
	MEDIUM = 'medium'
	LOW = 'low'
	INFO = 'info'


_SEVERITY_ORDER = {
	Severity.CRITICAL: 0,
	Severity.HIGH: 1,
	Severity.MEDIUM: 2,
	Severity.LOW: 3,
	Severity.INFO: 4,
}


@dataclass
class ScanFinding:
	scanner: str
	title: str
	severity: Severity
	description: str
	evidence: Optional[str] = None
	remediation: Optional[str] = None
	owasp_ref: Optional[str] = None
	affected_objects: list = field(default_factory=list)

	def to_dict(self):
		return {
			'scanner': self.scanner,
			'title': self.title,
			'severity': self.severity.value,
			'description': self.description,
			'evidence': self.evidence,
			'remediation': self.remediation,
			'owasp_ref': self.owasp_ref,
			'affected_objects': self.affected_objects,
		}

	def __lt__(self, other):
		return _SEVERITY_ORDER[self.severity] < _SEVERITY_ORDER[other.severity]


class BaseScanner:
	SCANNER_NAME = 'BaseScanner'

	def __init__(self, aura_helper):
		self.aura = aura_helper
		self.findings = []

	def scan(self) -> list:
		raise NotImplementedError

	def _add_finding(
		self, title, severity, description,
		evidence=None, remediation=None, owasp_ref=None, affected_objects=None
	):
		finding = ScanFinding(
			scanner=self.SCANNER_NAME,
			title=title,
			severity=severity,
			description=description,
			evidence=evidence,
			remediation=remediation,
			owasp_ref=owasp_ref,
			affected_objects=affected_objects or [],
		)
		self.findings.append(finding)
		return finding

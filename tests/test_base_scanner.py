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

"""Unit tests for scanners/base_scanner.py — Severity, ScanFinding, BaseScanner."""

import pytest
from scanners.base_scanner import Severity, ScanFinding, BaseScanner


class TestSeverity:
    def test_all_values_defined(self):
        assert {s.value for s in Severity} == {'critical', 'high', 'medium', 'low', 'info'}

    def test_enum_members_accessible(self):
        assert Severity.CRITICAL.value == 'critical'
        assert Severity.INFO.value == 'info'


class TestScanFinding:
    def _make(self, severity=Severity.HIGH):
        return ScanFinding(
            scanner='TestScanner',
            title='Test Finding',
            severity=severity,
            description='A test description.',
            evidence='Some evidence',
            remediation='Fix it',
            owasp_ref='API1:2023',
            affected_objects=['Account'],
        )

    def test_to_dict_keys(self):
        d = self._make().to_dict()
        assert set(d.keys()) == {
            'scanner', 'title', 'severity', 'description',
            'evidence', 'remediation', 'owasp_ref', 'affected_objects',
        }

    def test_to_dict_severity_is_string(self):
        d = self._make(Severity.CRITICAL).to_dict()
        assert d['severity'] == 'critical'

    def test_to_dict_affected_objects(self):
        d = self._make().to_dict()
        assert d['affected_objects'] == ['Account']

    def test_optional_fields_default_none(self):
        f = ScanFinding(scanner='S', title='T', severity=Severity.INFO, description='D')
        assert f.evidence is None
        assert f.remediation is None
        assert f.owasp_ref is None
        assert f.affected_objects == []

    def test_sorting_critical_before_high(self):
        critical = self._make(Severity.CRITICAL)
        high = self._make(Severity.HIGH)
        assert critical < high

    def test_sorting_info_last(self):
        info = self._make(Severity.INFO)
        medium = self._make(Severity.MEDIUM)
        assert medium < info

    def test_sorted_list_order(self):
        findings = [
            self._make(Severity.INFO),
            self._make(Severity.CRITICAL),
            self._make(Severity.MEDIUM),
            self._make(Severity.HIGH),
            self._make(Severity.LOW),
        ]
        ordered = sorted(findings)
        severities = [f.severity for f in ordered]
        assert severities == [
            Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM,
            Severity.LOW, Severity.INFO,
        ]


class TestBaseScanner:
    def test_scan_raises_not_implemented(self, empty_aura):
        scanner = BaseScanner(empty_aura)
        with pytest.raises(NotImplementedError):
            scanner.scan()

    def test_add_finding_appends_to_findings(self, empty_aura):
        scanner = BaseScanner(empty_aura)
        scanner._add_finding(
            title='T', severity=Severity.LOW, description='D',
            affected_objects=['Obj'],
        )
        assert len(scanner.findings) == 1
        assert scanner.findings[0].title == 'T'
        assert scanner.findings[0].scanner == 'BaseScanner'

    def test_add_finding_uses_scanner_name(self, empty_aura):
        class ConcreteScanner(BaseScanner):
            SCANNER_NAME = 'ConcreteScanner'
            def scan(self):
                self._add_finding('T', Severity.HIGH, 'D')
                return self.findings

        s = ConcreteScanner(empty_aura)
        s.scan()
        assert s.findings[0].scanner == 'ConcreteScanner'

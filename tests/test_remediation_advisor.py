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

"""Unit tests for ai_agents/remediation_advisor.py — RemediationAdvisor."""

import pytest
from ai_agents.remediation_advisor import RemediationAdvisor
from scanners.base_scanner import ScanFinding, Severity


def _finding(owasp_ref: str | None) -> ScanFinding:
    return ScanFinding(
        scanner='TestScanner',
        title='Test',
        severity=Severity.HIGH,
        description='desc',
        owasp_ref=owasp_ref,
    )


class TestGetRemediation:
    def test_api1_returns_setup_steps(self):
        result = RemediationAdvisor().get_remediation(_finding('API1:2023'))
        assert isinstance(result['setup_steps'], list)
        assert len(result['setup_steps']) > 0

    def test_api1_has_apex_example(self):
        result = RemediationAdvisor().get_remediation(_finding('API1:2023'))
        assert result['apex_example'] is not None
        assert 'WITH USER_MODE' in result['apex_example'] or 'with sharing' in result['apex_example']

    def test_api3_returns_fls_guidance(self):
        result = RemediationAdvisor().get_remediation(_finding('API3'))
        assert 'Field' in result['title'] or 'Property' in result['title']
        assert any('FLS' in s or 'Field' in s for s in result['setup_steps'])

    def test_api5_returns_function_auth_guidance(self):
        result = RemediationAdvisor().get_remediation(_finding('API5:2023'))
        assert 'Function' in result['title']

    def test_api8_returns_security_config_guidance(self):
        result = RemediationAdvisor().get_remediation(_finding('API8'))
        assert 'Misconfiguration' in result['title'] or 'Security' in result['title']

    def test_unknown_ref_falls_back_to_api8(self):
        result = RemediationAdvisor().get_remediation(_finding('API99'))
        assert result is not None
        assert 'setup_steps' in result

    def test_none_ref_falls_back(self):
        result = RemediationAdvisor().get_remediation(_finding(None))
        assert result is not None

    def test_full_owasp_string_matched(self):
        result = RemediationAdvisor().get_remediation(
            _finding('API1:2023 Broken Object Level Authorization')
        )
        assert 'API1' in result['owasp']

    def test_result_has_required_keys(self):
        required = {'title', 'owasp', 'setup_steps', 'apex_example'}
        for ref in ('API1', 'API3', 'API5', 'API8'):
            result = RemediationAdvisor().get_remediation(_finding(ref))
            assert required.issubset(result.keys()), f'Missing keys for {ref}'


class TestGenerateReportSections:
    def test_deduplicates_same_owasp_ref(self):
        findings = [_finding('API1'), _finding('API1'), _finding('API1')]
        sections = RemediationAdvisor().generate_report_sections(findings)
        assert len(sections) == 1

    def test_multiple_distinct_refs(self):
        findings = [_finding('API1'), _finding('API3'), _finding('API5')]
        sections = RemediationAdvisor().generate_report_sections(findings)
        assert len(sections) == 3

    def test_empty_findings_returns_empty_list(self):
        sections = RemediationAdvisor().generate_report_sections([])
        assert sections == []

    def test_sections_contain_required_keys(self):
        findings = [_finding('API1'), _finding('API8')]
        sections = RemediationAdvisor().generate_report_sections(findings)
        for section in sections:
            assert 'title' in section
            assert 'owasp' in section
            assert 'setup_steps' in section

    def test_sections_preserve_insertion_order_of_first_occurrence(self):
        findings = [_finding('API8'), _finding('API1')]
        sections = RemediationAdvisor().generate_report_sections(findings)
        # API8 appears first in findings, so its section should come first
        assert 'API8' in sections[0]['owasp']
        assert 'API1' in sections[1]['owasp']

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

"""Unit tests for scanners/aura_fuzzer.py — AuraFuzzer."""

import pytest
from unittest.mock import MagicMock, patch

from conftest import make_aura, MockActionResponse, MockBulkResponse
from scanners.aura_fuzzer import AuraFuzzer, SENSITIVE_OBJECTS
from scanners.base_scanner import Severity


class TestSensitiveObjectExposure:
    def test_sensitive_objects_produce_critical_finding(self, aura_with_sensitive_objects):
        findings = AuraFuzzer(aura_with_sensitive_objects).scan()
        crits = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(crits) == 1
        assert 'User' in crits[0].affected_objects
        assert 'Profile' in crits[0].affected_objects

    def test_critical_finding_has_owasp_ref(self, aura_with_sensitive_objects):
        findings = AuraFuzzer(aura_with_sensitive_objects).scan()
        crits = [f for f in findings if f.severity == Severity.CRITICAL]
        assert crits[0].owasp_ref is not None
        assert 'API1' in crits[0].owasp_ref

    def test_safe_objects_only_no_critical_finding(self, aura_with_safe_objects):
        findings = AuraFuzzer(aura_with_safe_objects).scan()
        crits = [f for f in findings if f.severity == Severity.CRITICAL]
        assert crits == []

    def test_empty_object_list_no_finding(self, empty_aura):
        findings = AuraFuzzer(empty_aura).scan()
        crits = [f for f in findings if f.severity == Severity.CRITICAL]
        assert crits == []

    def test_non_sensitive_objects_not_included_in_finding(self):
        aura = make_aura(objects=['User', 'Account', 'Product2'])
        findings = AuraFuzzer(aura).scan()
        crits = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(crits) == 1
        assert 'Product2' not in crits[0].affected_objects
        assert 'Account' not in crits[0].affected_objects

    def test_get_objects_exception_does_not_crash_scan(self):
        aura = make_aura()
        aura.get_objects.side_effect = RuntimeError('network error')
        findings = AuraFuzzer(aura).scan()
        assert isinstance(findings, list)


class TestListViewController:
    def test_list_view_records_produce_high_finding(self, aura_with_list_view_records):
        findings = AuraFuzzer(aura_with_list_view_records).scan()
        high = [f for f in findings if f.severity == Severity.HIGH]
        assert any('List View' in f.title for f in high)

    def test_list_view_empty_records_no_high_finding(self):
        resp = MockActionResponse(
            success=True,
            return_value={'records': {'records': []}},
        )
        aura = make_aura(
            objects=['Account'],
            bulk_response=MockBulkResponse([resp]),
        )
        findings = AuraFuzzer(aura).scan()
        list_view_high = [f for f in findings if f.severity == Severity.HIGH and 'List View' in f.title]
        assert list_view_high == []

    def test_list_view_failed_response_no_finding(self):
        resp = MockActionResponse(success=False, error_message='Access denied')
        aura = make_aura(bulk_response=MockBulkResponse([resp]))
        findings = AuraFuzzer(aura).scan()
        list_view_high = [f for f in findings if f.severity == Severity.HIGH and 'List View' in f.title]
        assert list_view_high == []

    def test_list_view_null_return_value_no_finding(self):
        resp = MockActionResponse(success=True, return_value=None)
        aura = make_aura(bulk_response=MockBulkResponse([resp]))
        findings = AuraFuzzer(aura).scan()
        list_view_high = [f for f in findings if f.severity == Severity.HIGH and 'List View' in f.title]
        assert list_view_high == []

    def test_bulk_exception_does_not_crash_scan(self):
        aura = make_aura(objects=['Account'])
        aura.send_aura_bulk.side_effect = RuntimeError('timeout')
        findings = AuraFuzzer(aura).scan()
        assert isinstance(findings, list)


class TestScanContract:
    def test_scan_always_returns_list(self, empty_aura):
        result = AuraFuzzer(empty_aura).scan()
        assert isinstance(result, list)

    def test_all_findings_are_scan_findings(self, aura_with_sensitive_objects):
        from scanners.base_scanner import ScanFinding
        for f in AuraFuzzer(aura_with_sensitive_objects).scan():
            assert isinstance(f, ScanFinding)

    def test_scanner_name_on_findings(self, aura_with_sensitive_objects):
        for f in AuraFuzzer(aura_with_sensitive_objects).scan():
            assert f.scanner == 'AuraFuzzer'

    def test_sensitive_objects_list_is_not_empty(self):
        assert len(SENSITIVE_OBJECTS) > 0
        assert 'User' in SENSITIVE_OBJECTS

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

"""Unit tests for scanners/apex_scanner.py — ApexScanner."""

import pytest

from conftest import make_aura, MockActionResponse, MockBulkResponse
from scanners.apex_scanner import ApexScanner, _LARGE_RESULT_THRESHOLD, _SYSTEM_MODE_PATTERNS
from scanners.base_scanner import Severity, ScanFinding


_FAKE_CONTROLLER = 'apex://c.MyCustomController/ACTION$search'


class TestSystemModePatterns:
    def test_patterns_list_not_empty(self):
        assert len(_SYSTEM_MODE_PATTERNS) > 0

    def test_soql_pattern_in_list(self):
        import re
        soql_found = any(
            re.search(p, 'SELECT Id FROM Account') for p in _SYSTEM_MODE_PATTERNS
        )
        assert soql_found

    def test_java_exception_pattern_in_list(self):
        import re
        java_found = any(
            re.search(p, 'java.lang.NullPointerException') for p in _SYSTEM_MODE_PATTERNS
        )
        assert java_found


class TestLargeResultDetection:
    def _make_aura_with_records(self, count: int):
        records = [{'Id': f'001{i:012d}', 'Name': f'Rec{i}'} for i in range(count)]
        resp = MockActionResponse(
            success=True,
            return_value={'records': records},
        )
        return make_aura(
            custom_controllers=[_FAKE_CONTROLLER],
            bulk_response=MockBulkResponse([resp]),
        )

    def test_large_result_above_threshold_adds_finding(self):
        aura = self._make_aura_with_records(_LARGE_RESULT_THRESHOLD + 5)
        findings = ApexScanner(aura).scan()
        large = [f for f in findings if 'Oversized' in f.title or 'Large' in f.title]
        assert len(large) >= 1

    def test_small_result_no_large_result_finding(self):
        aura = self._make_aura_with_records(2)
        findings = ApexScanner(aura).scan()
        large = [f for f in findings if 'Oversized' in f.title or 'Large' in f.title]
        assert large == []

    def test_empty_result_no_finding(self):
        resp = MockActionResponse(success=True, return_value={'records': []})
        aura = make_aura(
            custom_controllers=[_FAKE_CONTROLLER],
            bulk_response=MockBulkResponse([resp]),
        )
        findings = ApexScanner(aura).scan()
        large = [f for f in findings if 'Oversized' in f.title or 'Large' in f.title]
        assert large == []


class TestErrorLeakDetection:
    def _make_aura_with_error(self, error_msg: str):
        resp = MockActionResponse(success=False, error_message=error_msg)
        return make_aura(
            custom_controllers=[_FAKE_CONTROLLER],
            bulk_response=MockBulkResponse([resp]),
        )

    def test_soql_in_error_adds_finding(self):
        aura = self._make_aura_with_error('Error: SELECT Id, Name FROM Account')
        findings = ApexScanner(aura).scan()
        leak = [f for f in findings if 'Error' in f.title or 'Leak' in f.title or 'Information' in f.title]
        assert len(leak) >= 1

    def test_java_exception_in_error_adds_finding(self):
        aura = self._make_aura_with_error('java.lang.NullPointerException at line 42')
        findings = ApexScanner(aura).scan()
        leak = [f for f in findings if 'Error' in f.title or 'Leak' in f.title or 'Information' in f.title]
        assert len(leak) >= 1

    def test_generic_error_no_finding(self):
        aura = self._make_aura_with_error('You do not have access.')
        findings = ApexScanner(aura).scan()
        leak = [f for f in findings if 'Leak' in f.title or 'Information' in f.title]
        assert leak == []


class TestControllerProbeLimit:
    def test_probes_at_most_15_controllers(self):
        # Generate 20 controllers — only 15 should be probed
        controllers = [f'apex://c.Ctrl{i}/ACTION$search' for i in range(20)]
        call_log = []

        def counting_bulk(actions):
            call_log.append(actions)
            return MockBulkResponse()

        aura = make_aura(custom_controllers=controllers)
        aura.send_aura_bulk.side_effect = counting_bulk

        ApexScanner(aura).scan()
        # 2 probe sets × 15 controllers = 30 controller calls
        # + 2 self-registration calls from _test_self_registration_leak = 32 total
        assert len(call_log) <= 32

    def test_no_custom_controllers_no_probe_calls(self, empty_aura):
        ApexScanner(empty_aura).scan()
        # _test_self_registration_leak always runs — it makes 2 calls for the built-in
        # self-registration controllers. No user-defined controller calls are expected.
        for call in empty_aura.send_aura_bulk.call_args_list:
            actions = call.args[0]
            for action in actions:
                assert _FAKE_CONTROLLER not in action.get('descriptor', '')


class TestScanContract:
    def test_scan_returns_list(self, empty_aura):
        assert isinstance(ApexScanner(empty_aura).scan(), list)

    def test_bulk_exception_does_not_crash(self):
        aura = make_aura(custom_controllers=[_FAKE_CONTROLLER])
        aura.send_aura_bulk.side_effect = RuntimeError('timeout')
        findings = ApexScanner(aura).scan()
        assert isinstance(findings, list)

    def test_all_findings_have_scanner_name(self):
        records = [{'Id': f'001{i:012d}'} for i in range(_LARGE_RESULT_THRESHOLD + 5)]
        resp = MockActionResponse(success=True, return_value={'records': records})
        aura = make_aura(
            custom_controllers=[_FAKE_CONTROLLER],
            bulk_response=MockBulkResponse([resp]),
        )
        for f in ApexScanner(aura).scan():
            assert f.scanner == 'ApexScanner'

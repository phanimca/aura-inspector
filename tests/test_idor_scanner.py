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

"""Unit tests for scanners/idor_scanner.py — IDORScanner."""

import re

import pytest

from conftest import make_aura, MockActionResponse, MockBulkResponse
from scanners.idor_scanner import IDORScanner, SF_KEY_PREFIXES, _SF_ID_PATTERN
from scanners.base_scanner import Severity, ScanFinding


class TestSFIDPattern:
    """Verify the Salesforce record ID regex."""

    def test_matches_15_char_id(self):
        assert _SF_ID_PATTERN.search('001000000000001') is not None

    def test_matches_18_char_id(self):
        assert _SF_ID_PATTERN.search('001000000000001AAA') is not None

    def test_matches_id_in_url(self):
        url = 'https://example.com/s/account/001000000000001/view'
        m = _SF_ID_PATTERN.search(url)
        assert m is not None
        assert m.group(0).startswith('001')

    def test_does_not_match_short_strings(self):
        assert _SF_ID_PATTERN.search('abc') is None

    def test_sf_key_prefixes_populated(self):
        assert '001' in SF_KEY_PREFIXES
        assert SF_KEY_PREFIXES['001'] == 'Account'
        assert '005' in SF_KEY_PREFIXES   # User


class TestCollectSampleRecordIds:
    def test_ids_extracted_from_home_urls(self):
        aura = make_aura(home_urls={
            'Account': 'https://example.com/s/account/001000000000001/view',
            'Contact': 'https://example.com/s/contact/003000000000001/view',
        })
        scanner = IDORScanner(aura)
        ids = scanner._collect_sample_record_ids()
        assert 'Account' in ids
        assert ids['Account'].startswith('001')

    def test_urls_without_ids_are_skipped(self):
        aura = make_aura(home_urls={'Account': 'https://example.com/s/accounts'})
        scanner = IDORScanner(aura)
        ids = scanner._collect_sample_record_ids()
        assert ids == {}

    def test_empty_home_urls_returns_empty(self):
        aura = make_aura(home_urls={})
        scanner = IDORScanner(aura)
        ids = scanner._collect_sample_record_ids()
        assert ids == {}

    def test_none_home_urls_returns_empty(self):
        aura = make_aura()
        aura.get_object_home_urls.return_value = None
        scanner = IDORScanner(aura)
        ids = scanner._collect_sample_record_ids()
        assert ids == {}

    def test_exception_from_home_urls_returns_empty(self):
        aura = make_aura()
        aura.get_object_home_urls.side_effect = RuntimeError('network error')
        scanner = IDORScanner(aura)
        ids = scanner._collect_sample_record_ids()
        assert ids == {}


class TestRecordUIControllerCheck:
    def test_scan_runs_without_exception(self, empty_aura):
        findings = IDORScanner(empty_aura).scan()
        assert isinstance(findings, list)

    def test_bulk_exception_does_not_crash(self):
        aura = make_aura()
        aura.send_aura_bulk.side_effect = RuntimeError('timeout')
        findings = IDORScanner(aura).scan()
        assert isinstance(findings, list)


class TestDirectRecordAccess:
    def test_successful_record_access_adds_high_finding(self):
        # Aura returns a record when accessed directly — indicates IDOR
        resp = MockActionResponse(
            success=True,
            return_value={'record': {'Id': '001000000000001', 'Name': 'ACME'}},
        )
        aura = make_aura(
            home_urls={'Account': 'https://example.com/s/account/001000000000001/view'},
            bulk_response=MockBulkResponse([resp]),
        )
        findings = IDORScanner(aura).scan()
        assert any(f.severity in (Severity.HIGH, Severity.CRITICAL) for f in findings)

    def test_failed_record_access_no_idor_finding(self):
        resp = MockActionResponse(success=False, error_message='INSUFFICIENT_ACCESS')
        aura = make_aura(
            home_urls={'Account': 'https://example.com/s/account/001000000000001/view'},
            bulk_response=MockBulkResponse([resp]),
        )
        findings = IDORScanner(aura).scan()
        idor = [f for f in findings if 'IDOR' in f.title or 'Direct Record' in f.title]
        assert idor == []


class TestScanContract:
    def test_scan_returns_list(self, empty_aura):
        assert isinstance(IDORScanner(empty_aura).scan(), list)

    def test_all_findings_have_scanner_name(self):
        resp = MockActionResponse(
            success=True,
            return_value={'record': {'Id': '001000000000001'}},
        )
        aura = make_aura(
            home_urls={'Account': 'https://example.com/s/account/001000000000001/view'},
            bulk_response=MockBulkResponse([resp]),
        )
        for f in IDORScanner(aura).scan():
            assert f.scanner == 'IDORScanner'

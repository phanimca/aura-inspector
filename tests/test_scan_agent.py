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

"""Unit tests for ai_agents/scan_agent.py — SecurityScanAgent."""

import os
from unittest.mock import MagicMock, patch

import pytest

from conftest import make_aura
from ai_agents.scan_agent import SecurityScanAgent, _OPENAI_AVAILABLE
from scanners.base_scanner import Severity, ScanFinding


# ── Helper to build a deterministic ScanFinding ─────────────────────────────

def _finding(title='Test', severity=Severity.HIGH, owasp_ref='API1'):
    return ScanFinding(
        scanner='MockScanner',
        title=title,
        severity=severity,
        description='test desc',
        owasp_ref=owasp_ref,
    )


# ── Helpers to patch all three scanner classes ───────────────────────────────

def _patch_scanners(fuzzer_findings=None, idor_findings=None, apex_findings=None):
    """Return a context manager list that stubs out all three scanner .scan() methods."""
    from unittest.mock import patch

    fuzzer_mock = MagicMock()
    fuzzer_mock.return_value.scan.return_value = fuzzer_findings or []

    idor_mock = MagicMock()
    idor_mock.return_value.scan.return_value = idor_findings or []

    apex_mock = MagicMock()
    apex_mock.return_value.scan.return_value = apex_findings or []

    return (
        patch('ai_agents.scan_agent.AuraFuzzer', fuzzer_mock),
        patch('ai_agents.scan_agent.IDORScanner', idor_mock),
        patch('ai_agents.scan_agent.ApexScanner', apex_mock),
    )


class TestRunFullScan:
    def test_result_has_required_keys(self, empty_aura):
        p1, p2, p3 = _patch_scanners()
        with p1, p2, p3:
            result = SecurityScanAgent(empty_aura).run_full_scan()
        assert {'findings', 'ai_analysis', 'summary'} == result.keys()

    def test_findings_combined_from_all_three_scanners(self, empty_aura):
        p1, p2, p3 = _patch_scanners(
            fuzzer_findings=[_finding('Fuzzer F', Severity.CRITICAL)],
            idor_findings=[_finding('IDOR F', Severity.HIGH)],
            apex_findings=[_finding('Apex F', Severity.MEDIUM)],
        )
        with p1, p2, p3:
            result = SecurityScanAgent(empty_aura).run_full_scan()
        assert len(result['findings']) == 3

    def test_findings_sorted_by_severity(self, empty_aura):
        p1, p2, p3 = _patch_scanners(
            fuzzer_findings=[
                _finding('Info F', Severity.INFO),
                _finding('Crit F', Severity.CRITICAL),
            ],
        )
        with p1, p2, p3:
            result = SecurityScanAgent(empty_aura).run_full_scan()
        severities = [f['severity'] for f in result['findings']]
        assert severities == ['critical', 'info']

    def test_findings_are_dicts(self, empty_aura):
        p1, p2, p3 = _patch_scanners(fuzzer_findings=[_finding()])
        with p1, p2, p3:
            result = SecurityScanAgent(empty_aura).run_full_scan()
        assert all(isinstance(f, dict) for f in result['findings'])

    def test_progress_callback_called_four_times(self, empty_aura):
        cb = MagicMock()
        p1, p2, p3 = _patch_scanners()
        with p1, p2, p3:
            SecurityScanAgent(empty_aura).run_full_scan(progress_callback=cb)
        assert cb.call_count == 4   # Phase 1, Phase 2, Phase 3, analysis

    def test_no_progress_callback_still_works(self, empty_aura):
        p1, p2, p3 = _patch_scanners()
        with p1, p2, p3:
            result = SecurityScanAgent(empty_aura).run_full_scan()
        assert result is not None


class TestRuleBasedAnalysis:
    def test_uses_rule_based_when_no_api_key(self, empty_aura):
        p1, p2, p3 = _patch_scanners(
            fuzzer_findings=[_finding('Crit', Severity.CRITICAL)],
        )
        # Ensure no env API key bleeds in
        with patch.dict(os.environ, {'OPENAI_API_KEY': ''}, clear=False):
            with p1, p2, p3:
                agent = SecurityScanAgent(empty_aura, openai_api_key=None)
                agent.api_key = None          # force rule-based path
                result = agent.run_full_scan()
        assert result['ai_analysis'] is not None
        assert 'risk_summary' in result['ai_analysis']

    def test_risk_score_zero_for_no_findings(self, empty_aura):
        p1, p2, p3 = _patch_scanners()
        with p1, p2, p3:
            agent = SecurityScanAgent(empty_aura, openai_api_key=None)
            agent.api_key = None
            result = agent.run_full_scan()
        assert result['ai_analysis']['estimated_risk_score'] == 0

    def test_risk_score_increases_with_critical_findings(self, empty_aura):
        p1, p2, p3 = _patch_scanners(
            fuzzer_findings=[_finding('C', Severity.CRITICAL)] * 2,
        )
        with p1, p2, p3:
            agent = SecurityScanAgent(empty_aura, openai_api_key=None)
            agent.api_key = None
            result = agent.run_full_scan()
        # 2 criticals × 25 = 50
        assert result['ai_analysis']['estimated_risk_score'] >= 50

    def test_risk_score_capped_at_100(self, empty_aura):
        # 5 criticals × 25 = 125 → capped to 100
        p1, p2, p3 = _patch_scanners(
            fuzzer_findings=[_finding('C', Severity.CRITICAL)] * 5,
        )
        with p1, p2, p3:
            agent = SecurityScanAgent(empty_aura, openai_api_key=None)
            agent.api_key = None
            result = agent.run_full_scan()
        assert result['ai_analysis']['estimated_risk_score'] == 100

    def test_priority_actions_present(self, empty_aura):
        p1, p2, p3 = _patch_scanners(
            fuzzer_findings=[_finding('C', Severity.CRITICAL)],
        )
        with p1, p2, p3:
            agent = SecurityScanAgent(empty_aura, openai_api_key=None)
            agent.api_key = None
            result = agent.run_full_scan()
        actions = result['ai_analysis']['priority_actions']
        assert isinstance(actions, list)
        assert len(actions) > 0


class TestSummaryBuilding:
    def test_summary_counts_by_severity(self, empty_aura):
        p1, p2, p3 = _patch_scanners(
            fuzzer_findings=[
                _finding('C', Severity.CRITICAL),
                _finding('H', Severity.HIGH),
                _finding('H2', Severity.HIGH),
            ],
        )
        with p1, p2, p3:
            agent = SecurityScanAgent(empty_aura, openai_api_key=None)
            agent.api_key = None
            result = agent.run_full_scan()
        summary = result['summary']
        assert summary['total_findings'] == 3
        assert summary['by_severity']['critical'] == 1
        assert summary['by_severity']['high'] == 2

    def test_summary_has_required_keys(self, empty_aura):
        p1, p2, p3 = _patch_scanners()
        with p1, p2, p3:
            agent = SecurityScanAgent(empty_aura, openai_api_key=None)
            agent.api_key = None
            result = agent.run_full_scan()
        assert {'total_findings', 'by_severity', 'remediation_sections'} <= result['summary'].keys()

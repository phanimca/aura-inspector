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
Unit tests for src/mcp/server.py — MCP tool functions and resources.

Tests exercise the Python functions directly without starting the MCP runtime,
so no stdio/SSE transport is needed.  AuraHelper is never constructed — all
tests that would need a real connection mock it out at the _build_aura_helper
level or patch SecurityScanAgent.
"""

import importlib.util
import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

# ── Load our server module without triggering a naming conflict ──────────────
# fastmcp imports `mcp.types` from the official MCP Python SDK.  Our src/mcp/
# package has the same name and would shadow it if src/ were at the front of
# sys.path.  conftest.py appends src/ at the END so the official SDK is found
# first.  We load our server module by file path under a private alias so that
# `import mcp.server` always resolves to the official SDK (if any), not ours.
_SRC_ABS = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src'))
_SERVER_FILE = os.path.join(_SRC_ABS, 'mcp', 'server.py')

_spec = importlib.util.spec_from_file_location('_aura_inspector_mcp_server', _SERVER_FILE)
_server_mod = importlib.util.module_from_spec(_spec)
sys.modules['_aura_inspector_mcp_server'] = _server_mod
try:
    _spec.loader.exec_module(_server_mod)
    _MCP_AVAILABLE = True
except ImportError:
    _MCP_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not _MCP_AVAILABLE,
    reason='fastmcp or mcp SDK not installed — skip MCP server tests',
)

if _MCP_AVAILABLE:
    _build_aura_helper = _server_mod._build_aura_helper
    get_remediation = _server_mod.get_remediation
    explain_finding = _server_mod.explain_finding
    scan_result_schema = _server_mod.scan_result_schema
    owasp_references = _server_mod.owasp_references
else:
    # Provide stubs so the module can still be collected when skipped
    def _build_aura_helper(*a, **kw): pass  # noqa: E301
    def get_remediation(*a, **kw): pass  # noqa: E301
    def explain_finding(*a, **kw): pass  # noqa: E301
    def scan_result_schema(*a, **kw): return '{}'  # noqa: E301
    def owasp_references(*a, **kw): return '[]'  # noqa: E301


# ════════════════════════════════════════════════════════════════════════════
# _build_aura_helper — input validation
# ════════════════════════════════════════════════════════════════════════════

class TestBuildAuraHelper:
    def test_empty_url_raises_value_error(self):
        with pytest.raises(ValueError, match='target_url'):
            _build_aura_helper('')

    def test_non_http_url_raises_value_error(self):
        with pytest.raises(ValueError, match='target_url'):
            _build_aura_helper('ftp://example.com')

    def test_relative_url_raises_value_error(self):
        with pytest.raises(ValueError, match='target_url'):
            _build_aura_helper('/some/path')

    def test_valid_https_url_constructs_helper(self):
        with patch('_aura_inspector_mcp_server.AuraHelper') as mock_cls:
            mock_cls.return_value = MagicMock()
            helper = _build_aura_helper('https://example.com')
            mock_cls.assert_called_once()
            assert helper is not None

    def test_valid_http_url_accepted(self):
        with patch('_aura_inspector_mcp_server.AuraHelper') as mock_cls:
            mock_cls.return_value = MagicMock()
            _build_aura_helper('http://example.com')
            mock_cls.assert_called_once()

    def test_trailing_slash_stripped_from_url(self):
        with patch('_aura_inspector_mcp_server.AuraHelper') as mock_cls:
            mock_cls.return_value = MagicMock()
            _build_aura_helper('https://example.com/')
            call_kwargs = mock_cls.call_args
            # url kwarg should not end with /
            url_arg = call_kwargs.kwargs.get('url') or call_kwargs.args[0]
            assert not url_arg.endswith('/')

    def test_system_exit_from_aura_helper_propagates(self):
        with patch('_aura_inspector_mcp_server.AuraHelper', side_effect=SystemExit(1)):
            with pytest.raises(SystemExit):
                _build_aura_helper('https://example.com')


# ════════════════════════════════════════════════════════════════════════════
# get_remediation — OWASP ref normalisation and lookup
# ════════════════════════════════════════════════════════════════════════════

class TestGetRemediation:
    def test_short_ref_api1_returns_guidance(self):
        result = get_remediation('API1')
        assert 'setup_steps' in result
        assert isinstance(result['setup_steps'], list)
        assert len(result['setup_steps']) > 0

    def test_short_ref_api3(self):
        result = get_remediation('API3')
        assert 'owasp' in result
        assert 'API3' in result['owasp']

    def test_short_ref_api5(self):
        result = get_remediation('API5')
        assert 'apex_example' in result

    def test_short_ref_api8(self):
        result = get_remediation('API8')
        assert result['title'] is not None

    def test_full_ref_with_year_normalised(self):
        result = get_remediation('API1:2023')
        assert 'setup_steps' in result
        assert len(result['setup_steps']) > 0

    def test_full_ref_with_title_normalised(self):
        result = get_remediation('API1:2023 Broken Object Level Authorization')
        assert 'API1' in result['owasp']

    def test_lowercase_ref_normalised(self):
        result = get_remediation('api1')
        assert 'setup_steps' in result

    def test_unknown_ref_returns_fallback_dict(self):
        result = get_remediation('API99')
        assert isinstance(result, dict)
        assert 'setup_steps' in result

    def test_result_has_all_required_keys(self):
        for ref in ('API1', 'API3', 'API5', 'API8'):
            result = get_remediation(ref)
            assert {'title', 'owasp', 'setup_steps'} <= result.keys(), \
                f'Missing keys for {ref}: {result.keys()}'


# ════════════════════════════════════════════════════════════════════════════
# explain_finding — rule-based fallback (no OpenAI key)
# ════════════════════════════════════════════════════════════════════════════

class TestExplainFinding:
    def _call(self, **kwargs):
        base = {
            'title': 'Sensitive Objects Accessible to Guest',
            'description': 'User and Profile objects exposed to unauthenticated users.',
            'owasp_ref': 'API1:2023',
            'evidence': 'Objects: User, Profile',
            'openai_api_key': None,
        }
        base.update(kwargs)
        return explain_finding(**base)

    def test_rule_based_fallback_when_no_key(self):
        with patch.dict(os.environ, {'OPENAI_API_KEY': ''}, clear=False):
            result = self._call(openai_api_key=None)
        assert result['source'] == 'rule_based'

    def test_rule_based_result_has_required_keys(self):
        with patch.dict(os.environ, {'OPENAI_API_KEY': ''}, clear=False):
            result = self._call(openai_api_key=None)
        required = {'plain_language_summary', 'business_impact', 'suggested_next_steps', 'source'}
        assert required <= result.keys()

    def test_plain_language_summary_contains_title(self):
        with patch.dict(os.environ, {'OPENAI_API_KEY': ''}, clear=False):
            result = self._call(openai_api_key=None)
        assert 'Sensitive Objects' in result['plain_language_summary']

    def test_suggested_next_steps_is_list(self):
        with patch.dict(os.environ, {'OPENAI_API_KEY': ''}, clear=False):
            result = self._call(openai_api_key=None)
        assert isinstance(result['suggested_next_steps'], list)

    def test_no_owasp_ref_still_returns(self):
        with patch.dict(os.environ, {'OPENAI_API_KEY': ''}, clear=False):
            result = self._call(owasp_ref=None, openai_api_key=None)
        assert result['source'] == 'rule_based'


# ════════════════════════════════════════════════════════════════════════════
# run_auth_scan — cookie validation
# ════════════════════════════════════════════════════════════════════════════

class TestRunAuthScan:
    def test_empty_cookies_raises_value_error(self):
        run_auth_scan = _server_mod.run_auth_scan
        with pytest.raises(ValueError, match='cookies'):
            run_auth_scan(
                target_url='https://example.com',
                cookies='',
            )

    def test_whitespace_only_cookies_raises_value_error(self):
        run_auth_scan = _server_mod.run_auth_scan
        with pytest.raises(ValueError, match='cookies'):
            run_auth_scan(
                target_url='https://example.com',
                cookies='   ',
            )


# ════════════════════════════════════════════════════════════════════════════
# Resources — scan://schema and scan://owasp
# ════════════════════════════════════════════════════════════════════════════

class TestResources:
    def test_scan_result_schema_is_valid_json(self):
        raw = scan_result_schema()
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)
        assert parsed.get('type') == 'object'

    def test_scan_result_schema_has_findings_property(self):
        parsed = json.loads(scan_result_schema())
        assert 'findings' in parsed.get('properties', {})

    def test_owasp_references_is_valid_json(self):
        raw = owasp_references()
        parsed = json.loads(raw)
        assert isinstance(parsed, dict)

    def test_owasp_references_contains_api1(self):
        parsed = json.loads(owasp_references())
        assert 'API1' in parsed

    def test_owasp_references_all_have_titles(self):
        parsed = json.loads(owasp_references())
        for ref, title in parsed.items():
            assert isinstance(ref, str)
            assert isinstance(title, str)
            assert len(title) > 0

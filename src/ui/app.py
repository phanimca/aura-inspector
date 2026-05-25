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
Salesforce Security AI Scanner – Admin UI
==========================================
Gradio-based web interface for guest and authenticated Salesforce Experience Cloud
security scans.  Run with:

    python src/ui/app.py

or via Docker (see Dockerfile).  The UI is served on port 7860 by default.
"""

import json
import logging
import os
import sys
import tempfile

# Make src/ importable regardless of cwd
_SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC_DIR not in sys.path:
	sys.path.insert(0, _SRC_DIR)

import gradio as gr  # noqa: E402 – must come after sys.path fix

from colored_logger import init_logger, add_logging_level  # noqa: E402

add_logging_level('VERBOSE', 15)
init_logger(logging.INFO)

# ------------------------------------------------------------------
# Lazy import helpers – keeps startup fast even without optional deps
# ------------------------------------------------------------------

def _aura_helper_class():
	from aura_helper import AuraHelper
	return AuraHelper


def _scan_agent_class():
	from ai_agents.scan_agent import SecurityScanAgent
	return SecurityScanAgent


def _oauth_handler_class():
	from ui.oauth_handler import SalesforceOAuthHandler
	return SalesforceOAuthHandler


# ------------------------------------------------------------------
# Core scan functions
# ------------------------------------------------------------------

def run_guest_scan(url, app_path, aura_path, proxy, openai_key):
	"""Execute an unauthenticated guest-user scan and return formatted results."""
	if not url or not url.strip():
		return '**Please enter a Salesforce site URL.**', '', ''
	try:
		AuraHelper = _aura_helper_class()
		SecurityScanAgent = _scan_agent_class()
		aura = AuraHelper(
			url=url.strip().rstrip('/'),
			cookies=None,
			proxy=proxy.strip() if proxy and proxy.strip() else None,
			insecure=False,
			app=app_path.strip() if app_path and app_path.strip() else None,
			aura=aura_path.strip() if aura_path and aura_path.strip() else None,
			context=None,
			token='null',
		)
		agent = SecurityScanAgent(aura, openai_api_key=openai_key.strip() if openai_key else None)
		result = agent.run_full_scan()
		return (
			_findings_to_markdown(result['findings']),
			_analysis_to_markdown(result['ai_analysis']),
			json.dumps(result, indent=2),
		)
	except SystemExit:
		return '**Could not reach Aura endpoint.** Check the URL. Try supplying App Path and Aura Path explicitly.', '', ''
	except Exception as exc:
		return f'**Scan error:** {exc}', '', ''


def run_auth_scan(url, app_path, aura_path, cookies, proxy, openai_key, oauth_state):
	"""Execute an authenticated scan using session cookies or a stored OAuth token."""
	if not url or not url.strip():
		return '**Please enter a Salesforce site URL.**', '', ''

	effective_cookies = cookies.strip() if cookies and cookies.strip() else None

	# Fall back to the OAuth token stored in gr.State
	if not effective_cookies and oauth_state:
		try:
			OAuthHandler = _oauth_handler_class()
			handler = OAuthHandler(url.strip(), '')
			effective_cookies = handler.get_session_cookie(oauth_state['access_token'])
		except Exception:
			pass

	if not effective_cookies:
		return '**Please paste session cookies or connect via OAuth first.**', '', ''

	try:
		AuraHelper = _aura_helper_class()
		SecurityScanAgent = _scan_agent_class()
		aura = AuraHelper(
			url=url.strip().rstrip('/'),
			cookies=effective_cookies,
			proxy=proxy.strip() if proxy and proxy.strip() else None,
			insecure=False,
			app=app_path.strip() if app_path and app_path.strip() else None,
			aura=aura_path.strip() if aura_path and aura_path.strip() else None,
			context=None,
			token='null',
		)
		agent = SecurityScanAgent(aura, openai_api_key=openai_key.strip() if openai_key else None)
		result = agent.run_full_scan()
		return (
			_findings_to_markdown(result['findings']),
			_analysis_to_markdown(result['ai_analysis']),
			json.dumps(result, indent=2),
		)
	except SystemExit:
		return '**Could not reach Aura endpoint.** Check the URL and cookie/token validity.', '', ''
	except Exception as exc:
		return f'**Scan error:** {exc}', '', ''


def oauth_connect(instance_url, client_id, client_secret, current_state):
	"""Initiate Salesforce OAuth browser flow and store the token in gr.State."""
	if not instance_url or not instance_url.strip():
		return '**Please enter the Salesforce Instance URL.**', current_state
	if not client_id or not client_id.strip():
		return '**Please enter the Consumer Key (Client ID).**', current_state
	try:
		OAuthHandler = _oauth_handler_class()
		handler = OAuthHandler(
			instance_url=instance_url.strip(),
			client_id=client_id.strip(),
			client_secret=client_secret.strip() if client_secret and client_secret.strip() else None,
		)
		token_data = handler.authenticate_browser_flow()
		status = f'Connected. Scope: `{token_data.get("scope", "api web")}`. Ready for authenticated scans.'
		return status, token_data
	except TimeoutError as exc:
		return f'**Timeout:** {exc}', current_state
	except Exception as exc:
		return f'**OAuth error:** {exc}', current_state


def export_report(raw_json: str):
	"""Write the scan JSON to a temp file and return the path for Gradio download."""
	if not raw_json or not raw_json.strip():
		return None
	try:
		with tempfile.NamedTemporaryFile(
			mode='w', suffix='.json', delete=False, prefix='aura_inspector_report_'
		) as fh:
			fh.write(raw_json)
			return fh.name
	except Exception:
		return None


# ------------------------------------------------------------------
# Display helpers
# ------------------------------------------------------------------

_SEVERITY_BADGE = {
	'critical': '🔴 CRITICAL',
	'high': '🟠 HIGH',
	'medium': '🟡 MEDIUM',
	'low': '🔵 LOW',
	'info': '⚪ INFO',
}


def _findings_to_markdown(findings: list) -> str:
	if not findings:
		return '**No findings detected.** The scan completed without identifying issues.'
	lines = ['| Severity | Title | OWASP | Scanner |', '|:---|:---|:---|:---|']
	for f in findings:
		sev = _SEVERITY_BADGE.get(f.get('severity', ''), f.get('severity', ''))
		lines.append(
			f'| {sev} | {f.get("title", "")} | {f.get("owasp_ref", "—")} | {f.get("scanner", "")} |'
		)
	# Append detail cards for critical/high findings
	detail_lines = []
	for f in findings:
		if f.get('severity') in ('critical', 'high'):
			detail_lines.append(f'\n### {_SEVERITY_BADGE.get(f["severity"])} — {f["title"]}')
			detail_lines.append(f'**Description:** {f["description"]}')
			if f.get('evidence'):
				detail_lines.append(f'**Evidence:** `{f["evidence"]}`')
			if f.get('remediation'):
				detail_lines.append(f'**Remediation:**\n```\n{f["remediation"]}\n```')
	return '\n'.join(lines + detail_lines)


def _analysis_to_markdown(analysis: dict) -> str:
	if not analysis:
		return '_No analysis available._'
	score = analysis.get('estimated_risk_score', 'N/A')
	lines = [
		f'## Risk Score: **{score} / 100**\n',
		f'**Summary:** {analysis.get("risk_summary", "")}\n',
	]
	patterns = analysis.get('critical_patterns', [])
	if patterns:
		lines.append('**Key Patterns Identified:**')
		lines.extend(f'- {p}' for p in patterns)
		lines.append('')
	actions = analysis.get('priority_actions', [])
	if actions:
		lines.append('**Priority Actions:**')
		urgency_icon = {'immediate': '🚨', 'short-term': '⚠️', 'long-term': '📋'}
		for i, a in enumerate(actions, 1):
			icon = urgency_icon.get(a.get('urgency', ''), '')
			label = a.get('urgency', '').upper()
			lines.append(f'{i}. {icon} [{label}] {a.get("action", "")}')
	return '\n'.join(lines)


# ------------------------------------------------------------------
# Help text
# ------------------------------------------------------------------

_HELP_MD = """
## Salesforce Security AI Scanner – Admin UI

### Scan Modes
| Tab | What it does |
|---|---|
| **Guest Scan** | Runs unauthenticated – simulates a public visitor |
| **Authenticated Scan** | Runs with a logged-in session (cookies or OAuth) |
| **OAuth Connect** | Opens a browser to authenticate with Salesforce and stores the token |

### Scanner Modules
| Scanner | Tests |
|---|---|
| **AuraFuzzer** | Sensitive object exposure, list-view controller, search wildcards, theme info leaks |
| **IDORScanner** | Direct record access, cross-object ID prefix swap, RecordUiController availability |
| **ApexScanner** | Custom controller large result sets, internal error leaks, self-registration config leaks |

### AI Analysis
Set **OpenAI API Key** (or the `OPENAI_API_KEY` env var) to enable GPT-4o powered enrichment.
Without a key, rule-based risk scoring is used automatically.

### OAuth Prerequisites (one-time Salesforce Setup)
1. **Setup > App Manager > New Connected App**
2. Enable OAuth Settings
3. Set callback URL: `http://localhost:8484/callback`
4. Add scopes: `api`, `web`
5. Copy the **Consumer Key** (Client ID) to the OAuth Connect tab.

### Environment Variables
| Variable | Purpose |
|---|---|
| `OPENAI_API_KEY` | AI analysis key |
| `SF_CLIENT_ID` | Pre-fill Connected App Consumer Key |
| `SF_INSTANCE_URL` | Pre-fill Salesforce Instance URL |
| `PORT` | Override UI port (default 7860) |

### OWASP References
- **API1:2023** Broken Object Level Authorization  
- **API3:2023** Broken Object Property Level Authorization  
- **API5:2023** Broken Function Level Authorization  
- **API8:2023** Security Misconfiguration  
"""


# ------------------------------------------------------------------
# Gradio layout
# ------------------------------------------------------------------

def build_ui() -> gr.Blocks:
	oauth_token_state = gr.State(value=None)

	with gr.Blocks(
		title='Salesforce Security AI Scanner',
		theme=gr.themes.Soft(),
	) as demo:
		gr.Markdown(
			'# 🔍 Salesforce Security AI Scanner\n'
			'### AI-Powered Salesforce Experience Cloud Security Scanner'
		)

		with gr.Tabs():

			# ── Guest Scan ────────────────────────────────────────────
			with gr.Tab('Guest Scan'):
				gr.Markdown(
					'Run an **unauthenticated** scan simulating a public site visitor. '
					'No credentials required.'
				)
				with gr.Row():
					g_url = gr.Textbox(
						label='Salesforce Site URL *',
						placeholder='https://example.my.site.com',
						scale=4,
					)
				with gr.Row():
					g_app = gr.Textbox(
						label='App Path (optional)',
						placeholder='/s',
						scale=2,
					)
					g_aura = gr.Textbox(
						label='Aura Path (optional)',
						placeholder='/s/sfsites/aura',
						scale=2,
					)
					g_proxy = gr.Textbox(
						label='Proxy (optional)',
						placeholder='http://127.0.0.1:8080',
						scale=2,
					)
				g_key = gr.Textbox(
					label='OpenAI API Key (optional – enables AI analysis)',
					type='password',
					placeholder='sk-…',
				)
				g_btn = gr.Button('▶ Run Guest Scan', variant='primary')

				with gr.Tabs():
					with gr.Tab('Findings'):
						g_findings = gr.Markdown()
					with gr.Tab('AI Analysis'):
						g_analysis = gr.Markdown()
					with gr.Tab('Raw JSON'):
						g_raw = gr.Code(language='json', label='Scan Result JSON')

				with gr.Row():
					g_export = gr.Button('⬇ Export JSON Report')
					g_file = gr.File(label='Download')

				g_btn.click(
					fn=run_guest_scan,
					inputs=[g_url, g_app, g_aura, g_proxy, g_key],
					outputs=[g_findings, g_analysis, g_raw],
				)
				g_export.click(fn=export_report, inputs=[g_raw], outputs=[g_file])

			# ── Authenticated Scan ────────────────────────────────────
			with gr.Tab('Authenticated Scan'):
				gr.Markdown(
					'Run an **authenticated** scan using session cookies or an OAuth token '
					'(connect via the **OAuth Connect** tab first).'
				)
				with gr.Row():
					a_url = gr.Textbox(
						label='Salesforce Site URL *',
						placeholder='https://example.my.site.com',
						scale=4,
					)
				with gr.Row():
					a_app = gr.Textbox(label='App Path (optional)', placeholder='/s', scale=2)
					a_aura = gr.Textbox(
						label='Aura Path (optional)',
						placeholder='/s/sfsites/aura',
						scale=2,
					)
					a_proxy = gr.Textbox(
						label='Proxy (optional)',
						placeholder='http://127.0.0.1:8080',
						scale=2,
					)
				a_cookies = gr.Textbox(
					label='Session Cookies (paste from browser DevTools, or leave blank if using OAuth)',
					placeholder='sid=00D...; other_cookie=...',
					lines=2,
				)
				a_key = gr.Textbox(
					label='OpenAI API Key (optional)',
					type='password',
					placeholder='sk-…',
				)
				a_btn = gr.Button('▶ Run Authenticated Scan', variant='primary')

				with gr.Tabs():
					with gr.Tab('Findings'):
						a_findings = gr.Markdown()
					with gr.Tab('AI Analysis'):
						a_analysis = gr.Markdown()
					with gr.Tab('Raw JSON'):
						a_raw = gr.Code(language='json', label='Scan Result JSON')

				with gr.Row():
					a_export = gr.Button('⬇ Export JSON Report')
					a_file = gr.File(label='Download')

				a_btn.click(
					fn=run_auth_scan,
					inputs=[a_url, a_app, a_aura, a_cookies, a_proxy, a_key, oauth_token_state],
					outputs=[a_findings, a_analysis, a_raw],
				)
				a_export.click(fn=export_report, inputs=[a_raw], outputs=[a_file])

			# ── OAuth Connect ─────────────────────────────────────────
			with gr.Tab('OAuth Connect'):
				gr.Markdown(
					'## Salesforce OAuth 2.0\n'
					'Connects to your org and stores the access token for use in the '
					'**Authenticated Scan** tab.\n\n'
					'**Callback URL to configure in your Connected App:** '
					'`http://localhost:8484/callback`'
				)
				with gr.Row():
					o_url = gr.Textbox(
						label='Salesforce Instance URL *',
						placeholder='https://login.salesforce.com',
						value=os.environ.get('SF_INSTANCE_URL', ''),
						scale=3,
					)
					o_cid = gr.Textbox(
						label='Consumer Key (Client ID) *',
						value=os.environ.get('SF_CLIENT_ID', ''),
						scale=3,
					)
				o_secret = gr.Textbox(
					label='Consumer Secret (optional – required for Web Server flow)',
					type='password',
				)
				o_btn = gr.Button('🔑 Connect via OAuth  (opens browser)', variant='secondary')
				o_status = gr.Textbox(label='Connection Status', interactive=False)

				o_btn.click(
					fn=oauth_connect,
					inputs=[o_url, o_cid, o_secret, oauth_token_state],
					outputs=[o_status, oauth_token_state],
				)

			# ── Help ──────────────────────────────────────────────────
			with gr.Tab('Help'):
				gr.Markdown(_HELP_MD)

	return demo


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

def main():
	app = build_ui()
	app.launch(
		server_name='0.0.0.0',
		server_port=int(os.environ.get('PORT', 7860)),
		share=False,
		show_error=True,
	)


if __name__ == '__main__':
	main()

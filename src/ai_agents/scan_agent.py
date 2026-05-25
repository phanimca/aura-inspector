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

import concurrent.futures
import json
import logging
import os
import threading
from typing import Callable, Optional

from colored_logger import logger
from scanners.aura_fuzzer import AuraFuzzer
from scanners.idor_scanner import IDORScanner
from scanners.apex_scanner import ApexScanner
from scanners.base_scanner import Severity, ScanFinding
from ai_agents.remediation_advisor import RemediationAdvisor

_log = logging.getLogger(__name__)


class ScanCancelledError(Exception):
	"""Raised inside run_full_scan when the caller sets the stop_event."""

try:
    import openai
    from tenacity import (
        retry,
        stop_after_attempt,
        wait_exponential,
        retry_if_exception_type,
    )
    _OPENAI_AVAILABLE = True
except ImportError:
    _OPENAI_AVAILABLE = False


_AGENT_SYSTEM_PROMPT = """You are an expert Salesforce security analyst.
Analyze the provided JSON scan findings from a Salesforce Security AI Scanner scan of a Salesforce
Experience Cloud site and return a JSON object with exactly these keys:

  "risk_summary"         – 2–3 sentence plain-language executive summary of risk.
  "critical_patterns"    – list of strings describing systemic vulnerability patterns
                           (not individual findings), e.g. "All custom Apex controllers
                           run without sharing".
  "priority_actions"     – ordered list of objects, each with:
                             "action"   – specific Salesforce fix (include Setup paths).
                             "urgency"  – one of: immediate, short-term, long-term.
                             "type"     – one of: config, code, policy.
  "estimated_risk_score" – integer 0-100 reflecting exploitability × business impact.

Be specific: name exact Salesforce Setup navigation paths, exact Apex keywords, and
exact OWASP API Security 2023 references. Do not suggest generic best-practice steps
unless they directly resolve a finding in the provided data.
"""


class SecurityScanAgent:
	"""
	AI-orchestrated security scan agent for Salesforce Experience Cloud.

	Usage
	-----
	  agent = SecurityScanAgent(aura_helper, openai_api_key='sk-...')
	  result = agent.run_full_scan(progress_callback=print)
	  # result = {'findings': [...], 'ai_analysis': {...}, 'summary': {...}}

	If no OpenAI API key is supplied (and the OPENAI_API_KEY env var is not set),
	the agent falls back to rule-based analysis automatically.
	"""

	def __init__(self, aura_helper, openai_api_key: Optional[str] = None,
	             openai_base_url: Optional[str] = None, verbose: bool = False):
		self.aura = aura_helper
		self.api_key = openai_api_key or os.environ.get('OPENAI_API_KEY')
		# Base URL for the OpenAI-compatible endpoint.
		# Set OPENAI_BASE_URL=https://models.github.ai/inference to use GitHub Models.
		self.base_url = openai_base_url or os.environ.get('OPENAI_BASE_URL') or None
		self.verbose = verbose
		self.all_findings: list[ScanFinding] = []

	# ------------------------------------------------------------------
	# Public entry point
	# ------------------------------------------------------------------

	def run_full_scan(
		self,
		progress_callback: Optional[Callable[[str], None]] = None,
		stop_event: Optional[threading.Event] = None,
	) -> dict:
		"""
		Run all three scanners concurrently, then run AI/rule-based analysis.

		Parameters
		----------
		progress_callback : callable, optional
		    Called with a human-readable status string as phases complete.
		stop_event : threading.Event, optional
		    Set this from another thread to request cancellation.
		    Raises ScanCancelledError when detected between phases.

		Returns
		-------
		dict with keys: findings, ai_analysis, summary
		"""
		self.all_findings = []
		_stop = stop_event or threading.Event()

		if _stop.is_set():
			raise ScanCancelledError('Scan cancelled before it started')

		if progress_callback:
			progress_callback('Running all 3 scanners in parallel…')

		def _run_scanner(scanner_cls, name: str) -> tuple[str, list]:
			if _stop.is_set():
				return name, []
			findings = scanner_cls(self.aura).scan()
			_log.info('[ScanAgent] %s: %d findings', name, len(findings))
			return name, findings

		# Run AuraFuzzer, IDORScanner, ApexScanner concurrently.
		scanner_tasks = [
			(AuraFuzzer, 'AuraFuzzer'),
			(IDORScanner, 'IDORScanner'),
			(ApexScanner, 'ApexScanner'),
		]

		all_findings_map: dict[str, list] = {}
		with concurrent.futures.ThreadPoolExecutor(
			max_workers=3, thread_name_prefix='scanner'
		) as pool:
			futures = {
				pool.submit(_run_scanner, cls, name): name
				for cls, name in scanner_tasks
			}
			pending = set(futures)
			completed_count = 0

			# Poll with 0.5 s timeout so the stop_event is checked frequently.
			while pending:
				if _stop.is_set():
					for f in futures:
						f.cancel()
					raise ScanCancelledError('Scan cancelled during parallel scanner phase')
				done, pending = concurrent.futures.wait(
					pending, timeout=0.5,
					return_when=concurrent.futures.FIRST_COMPLETED,
				)
				completed_count += len(done)
				if progress_callback and done:
					names_done = ', '.join(futures[f] for f in done)
					progress_callback(
						f'Scanners: {completed_count}/3 complete (✓ {names_done})'
					)

		# Collect results in deterministic order.
		for f, name in futures.items():
			_, findings = f.result()
			all_findings_map[name] = findings
			self.all_findings.extend(findings)

		if _stop.is_set():
			raise ScanCancelledError('Scan cancelled after scanner phase')

		if progress_callback:
			msg = 'Generating AI analysis…' if (self.api_key and _OPENAI_AVAILABLE) else 'Generating rule-based analysis…'
			progress_callback(msg)

		ai_analysis = self._analyze_with_ai() if (self.api_key and _OPENAI_AVAILABLE) else self._rule_based_analysis()

		return {
			'findings': [f.to_dict() for f in sorted(self.all_findings)],
			'ai_analysis': ai_analysis,
			'summary': self._build_summary(),
		}

	# ------------------------------------------------------------------
	# AI analysis path (requires openai + tenacity packages + API key)
	# ------------------------------------------------------------------

	def _analyze_with_ai(self) -> dict:
		"""Call GPT-4o to produce structured risk analysis; falls back on any error."""
		try:
			@retry(
				stop=stop_after_attempt(4),
				wait=wait_exponential(multiplier=1, min=1, max=16),
				retry=retry_if_exception_type(openai.RateLimitError),
				reraise=True,
			)
			def _call(client: openai.OpenAI, messages: list) -> str:
				response = client.chat.completions.create(
					model=os.environ.get('OPENAI_MODEL', 'openai/gpt-4o-mini'),
					messages=messages,
					response_format={'type': 'json_object'},
					max_tokens=2000,
				)
				return response.choices[0].message.content

			client = openai.OpenAI(
				api_key=self.api_key,
				**({'base_url': self.base_url} if self.base_url else {}),
			)
			findings_json = json.dumps([f.to_dict() for f in self.all_findings], indent=2)
			messages = [
				{'role': 'system', 'content': _AGENT_SYSTEM_PROMPT},
				{'role': 'user', 'content': f'Findings:\n\n{findings_json}'},
			]
			content = _call(client, messages)
			return json.loads(content)
		except openai.APIError as exc:
			_log.warning('[ScanAgent] OpenAI API error (%s) – using rule-based fallback', exc)
			return self._rule_based_analysis()
		except Exception:
			_log.error('[ScanAgent] AI analysis failed unexpectedly – using rule-based fallback', exc_info=True)
			return self._rule_based_analysis()

	# ------------------------------------------------------------------
	# Rule-based fallback (no external dependencies)
	# ------------------------------------------------------------------

	def _rule_based_analysis(self) -> dict:
		critical = [f for f in self.all_findings if f.severity == Severity.CRITICAL]
		high = [f for f in self.all_findings if f.severity == Severity.HIGH]
		medium = [f for f in self.all_findings if f.severity == Severity.MEDIUM]

		risk_score = min(100, len(critical) * 25 + len(high) * 15 + len(medium) * 5)

		priority_actions = []
		if critical:
			priority_actions.append({
				'action': (
					'Immediately revoke guest user access to sensitive objects '
					'(Setup > Digital Experiences > All Sites > [Site] > Workplaces > Guest User Profile > Object Settings).'
				),
				'urgency': 'immediate',
				'type': 'config',
			})
		if any('IDOR' in f.title for f in self.all_findings):
			priority_actions.append({
				'action': (
					'Add WITH USER_MODE to every SOQL query in Apex classes that serve the Experience '
					'Cloud guest profile, and add "with sharing" to each class declaration.'
				),
				'urgency': 'immediate',
				'type': 'code',
			})
		if any('Custom Controller' in f.title for f in self.all_findings):
			priority_actions.append({
				'action': (
					'Conduct a full Apex code review for all custom controllers listed in the findings. '
					'Each class must carry the "with sharing" keyword or use '
					'Security.stripInaccessible(AccessType.READABLE, records) before returning data.'
				),
				'urgency': 'short-term',
				'type': 'code',
			})
		if any('Search' in f.title for f in self.all_findings):
			priority_actions.append({
				'action': (
					'Validate and sanitize Apex search inputs to reject wildcard characters. '
					'Enforce WITH USER_MODE in the backing SOQL query.'
				),
				'urgency': 'short-term',
				'type': 'code',
			})
		if not priority_actions:
			priority_actions.append({
				'action': (
					'Run the Salesforce Security Health Check weekly '
					'(Setup > Security > Health Check) and address any failing items.'
				),
				'urgency': 'long-term',
				'type': 'policy',
			})

		critical_patterns = list({f.title for f in critical + high})

		return {
			'risk_summary': (
				f'{len(critical)} critical, {len(high)} high, and {len(medium)} medium severity '
				f'findings detected across AuraFuzzer, IDORScanner, and ApexScanner. '
				f'Estimated risk score: {risk_score}/100.'
			),
			'critical_patterns': critical_patterns,
			'priority_actions': priority_actions,
			'estimated_risk_score': risk_score,
		}

	# ------------------------------------------------------------------
	# Summary helper
	# ------------------------------------------------------------------

	def _build_summary(self) -> dict:
		by_severity: dict = {}
		for f in self.all_findings:
			by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
		advisor = RemediationAdvisor()
		remediation_sections = advisor.generate_report_sections(self.all_findings)
		return {
			'total_findings': len(self.all_findings),
			'by_severity': by_severity,
			'scanners_run': ['AuraFuzzer', 'IDORScanner', 'ApexScanner'],
			'remediation_sections': remediation_sections,
		}

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
Background scan execution thread.

Each scan runs in a daemon thread so it does not block the web server.
A fresh SQLAlchemy session is created per thread (sessions are not thread-safe).
SystemExit raised by AuraHelper (when endpoint is unreachable) is caught and
recorded as a scan failure.
"""

import os
import sys
import threading
import traceback
from datetime import datetime

# Make src/ importable when this module is loaded from src/web/
_SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC_DIR not in sys.path:
	sys.path.insert(0, _SRC_DIR)


def _execute(scan_id: int, config: dict) -> None:
	"""
	Run the full security scan pipeline and persist all results to the database.
	This function is designed to run in a background thread.
	"""
	# Import here so the worker thread gets its own module references
	from web.database import AiAnalysis, Finding, ScanJob, SessionLocal  # noqa: PLC0415
	from aura_helper import AuraHelper  # noqa: PLC0415
	from ai_agents.scan_agent import SecurityScanAgent  # noqa: PLC0415

	db = SessionLocal()
	try:
		scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
		if not scan:
			return

		scan.status = 'running'
		db.commit()

		aura = AuraHelper(
			url=config['target_url'].rstrip('/'),
			cookies=config.get('cookies') or None,
			proxy=config.get('proxy') or None,
			insecure=False,
			app=config.get('app_path') or None,
			aura=config.get('aura_path') or None,
			context=None,
			token='null',
		)

		agent = SecurityScanAgent(
			aura,
			openai_api_key=config.get('openai_api_key') or None,
		)
		result = agent.run_full_scan()

		# Persist findings
		for fd in result.get('findings', []):
			db.add(Finding(
				scan_job_id=scan_id,
				scanner=fd.get('scanner'),
				title=fd.get('title'),
				severity=fd.get('severity'),
				description=fd.get('description'),
				evidence=fd.get('evidence'),
				remediation=fd.get('remediation'),
				owasp_ref=fd.get('owasp_ref'),
				affected_objects=fd.get('affected_objects', []),
			))

		# Persist AI analysis
		ai = result.get('ai_analysis') or {}
		db.add(AiAnalysis(
			scan_job_id=scan_id,
			risk_score=ai.get('estimated_risk_score', 0),
			risk_summary=ai.get('risk_summary', ''),
			critical_patterns=ai.get('critical_patterns', []),
			priority_actions=ai.get('priority_actions', []),
		))

		scan.risk_score = ai.get('estimated_risk_score', 0)
		scan.status = 'completed'
		scan.completed_at = datetime.utcnow()
		db.commit()

	except (SystemExit, Exception):
		db.rollback()
		try:
			scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
			if scan:
				err = traceback.format_exc()
				scan.status = 'failed'
				scan.error_message = err[-1000:]
				scan.completed_at = datetime.utcnow()
				db.commit()
		except Exception:
			pass
	finally:
		db.close()


def launch(scan_id: int, config: dict) -> threading.Thread:
	"""Start a daemon thread that executes the scan and returns it immediately."""
	t = threading.Thread(target=_execute, args=(scan_id, config), daemon=True)
	t.start()
	return t

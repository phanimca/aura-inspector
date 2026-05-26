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
Background scan execution with parallel scanners and cooperative cancellation.

Each scan runs in a daemon thread so it does not block the web server.
A threading.Event is kept per scan_id so any route handler can request
cancellation — the agent polls this event between parallel scanner futures.
"""

import os
import sys
import logging
import threading
import traceback
from datetime import datetime

_logger = logging.getLogger(__name__)

# Make src/ importable when this module is loaded from src/web/
_SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC_DIR not in sys.path:
	sys.path.insert(0, _SRC_DIR)

# Register the VERBOSE custom log level used throughout aura_helper.py.
# aura_cli.py does this at CLI startup; the web runner must do it here.
def _register_verbose_level() -> None:
	if hasattr(logging, 'VERBOSE'):
		return
	from colored_logger import add_logging_level  # noqa: PLC0415
	add_logging_level('VERBOSE', 15)

_register_verbose_level()

# ---------------------------------------------------------------------------
# Cancel-event registry  {scan_id: threading.Event}
# ---------------------------------------------------------------------------
_cancel_events: dict[int, threading.Event] = {}
_registry_lock = threading.Lock()


def cancel(scan_id: int) -> bool:
	"""Signal a running scan to stop.  Returns True if the scan was found."""
	with _registry_lock:
		event = _cancel_events.get(scan_id)
	if event:
		event.set()
		return True
	return False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _update_progress(scan_id: int, msg: str, db) -> None:
	"""Write a human-readable progress label to the scan row (best-effort)."""
	try:
		from web.database import ScanJob  # noqa: PLC0415
		scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
		if scan:
			scan.progress = msg[:200]
			db.commit()
	except Exception:
		pass


def _execute(scan_id: int, config: dict, stop_event: threading.Event) -> None:
	"""
	Run the full security scan pipeline and persist all results to the database.
	This function is designed to run in a background thread.
	"""
	# Import here so the worker thread gets its own module references
	from web.database import AiAnalysis, Finding, ScanJob, SessionLocal  # noqa: PLC0415
	from aura_helper import AuraHelper  # noqa: PLC0415
	from ai_agents.scan_agent import SecurityScanAgent, ScanCancelledError  # noqa: PLC0415

	db = SessionLocal()
	try:
		scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
		if not scan:
			return

		scan.status = 'running'
		scan.progress = 'Initialising scanners…'
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
			openai_base_url=config.get('openai_base_url') or None,
		)

		def on_progress(msg: str) -> None:
			_update_progress(scan_id, msg, db)

		result = agent.run_full_scan(
			progress_callback=on_progress,
			stop_event=stop_event,
		)

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
		scan.progress = 'Completed'
		scan.completed_at = datetime.utcnow()
		db.commit()

	except ScanCancelledError:
		db.rollback()
		try:
			scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
			if scan:
				scan.status = 'cancelled'
				scan.cancelled_at = datetime.utcnow()
				scan.progress = 'Cancelled'
				db.commit()
		except Exception:
			pass

	except SystemExit:
		# AuraHelper.get_aura_endpoint() calls exit() when it cannot locate the Aura
		# endpoint.  Convert that into a friendly, actionable error message rather than
		# exposing the raw SystemExit traceback.
		db.rollback()
		try:
			scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
			if scan:
				scan.status = 'failed'
				scan.error_message = (
					'Aura endpoint not found at the target URL. '
					'Verify the URL points to a Salesforce Experience Cloud site. '
					'If the site uses a custom path, supply explicit App Path and Aura Path values in the scan form.'
				)
				scan.progress = 'Failed'
				scan.completed_at = datetime.utcnow()
				db.commit()
		except Exception:
			pass

	except Exception:
		db.rollback()
		try:
			scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
			if scan:
				err = traceback.format_exc()
				scan.status = 'failed'
				scan.error_message = err[-1000:]
				scan.progress = 'Failed'
				scan.completed_at = datetime.utcnow()
				db.commit()
		except Exception:
			pass
	finally:
		db.close()
		with _registry_lock:
			_cancel_events.pop(scan_id, None)


def launch(scan_id: int, config: dict) -> threading.Thread:
	"""Start a daemon thread that executes the scan and returns it immediately."""
	stop_event = threading.Event()
	with _registry_lock:
		_cancel_events[scan_id] = stop_event
	t = threading.Thread(target=_execute, args=(scan_id, config, stop_event), daemon=True)
	t.start()
	return t





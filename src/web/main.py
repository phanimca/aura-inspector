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
Salesforce Security AI Scanner — Web Application (FastAPI)

Run locally:
    pip install -r requirements-web.txt
    python src/web/main.py

Or via Docker:
    docker compose up --build
"""

import json
import os
import sys
import uuid
from datetime import datetime
from pathlib import Path

# Load .env from repo root before any os.environ reads
_REPO_ROOT = Path(__file__).parent.parent.parent
_ENV_FILE = _REPO_ROOT / '.env'
if _ENV_FILE.exists():
	try:
		from dotenv import load_dotenv
		load_dotenv(_ENV_FILE, override=False)
	except ImportError:
		pass  # python-dotenv not installed; rely on shell environment

# Make src/ importable (needed for aura_helper, scanners, ai_agents)
_SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _SRC_DIR not in sys.path:
	sys.path.insert(0, _SRC_DIR)

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from web.auth import COOKIE_NAME, create_token, decode_token, hash_password, verify_password
from web.database import AiAnalysis, Finding, OAuthState, ScanJob, User, _USING_EPHEMERAL_SQLITE, get_db, init_db
from web import scan_runner

# ---------------------------------------------------------------------------
# App and template setup
# ---------------------------------------------------------------------------

import logging
logger = logging.getLogger(__name__)

_BASE_DIR = Path(__file__).parent

app = FastAPI(title='Salesforce Security AI Scanner', docs_url=None, redoc_url=None)

# ---------------------------------------------------------------------------
# Base URL — used for absolute links, OAuth callbacks, etc.
# On Vercel, VERCEL_URL is set automatically to the deployment host (no scheme).
# Locally, fall back to WEB_PORT (default 8080).
# ---------------------------------------------------------------------------
if os.environ.get('VERCEL') == '1':
	_vercel_host = os.environ.get('VERCEL_URL', 'phani-aura-inspector.vercel.app')
	APP_BASE_URL: str = f'https://{_vercel_host}'
else:
	APP_BASE_URL = f'http://localhost:{os.environ.get("WEB_PORT", "8080")}'

# Mount static files directory (CSS/images if any).
# Guard against read-only serverless filesystems (e.g. Vercel).
_STATIC_DIR = _BASE_DIR / 'static'
try:
	_STATIC_DIR.mkdir(exist_ok=True)
	app.mount('/static', StaticFiles(directory=str(_STATIC_DIR)), name='static')
except (OSError, RuntimeError):
	pass  # Static files unavailable on read-only filesystem — skip gracefully

templates = Jinja2Templates(directory=str(_BASE_DIR / 'templates'))

# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

def _get_user(request: Request, db: Session) -> User | None:
	"""Return the authenticated User from the session cookie, or None."""
	token = request.cookies.get(COOKIE_NAME)
	if not token:
		return None
	payload = decode_token(token)
	if not payload:
		return None
	return db.query(User).filter(User.id == int(payload['sub'])).first()


def _require_user(request: Request, db: Session) -> User | None:
	"""Return the user or redirect to /login.  Callers must check for redirect."""
	return _get_user(request, db)


def _ctx(user: User | None = None, **kwargs) -> dict:
	"""Build a base template context dict (request is injected by starlette 1.x automatically)."""
	return {'user': user, 'app_base_url': APP_BASE_URL, **kwargs}


# ---------------------------------------------------------------------------
# Default admin credentials (overridable via environment variables)
# ---------------------------------------------------------------------------

_DEFAULT_ADMIN_USERNAME = os.environ.get('DEFAULT_ADMIN_USERNAME', 'phani')
_DEFAULT_ADMIN_EMAIL    = os.environ.get('DEFAULT_ADMIN_EMAIL', 'phani.dummy@hotmail.com')
_DEFAULT_ADMIN_PASSWORD = os.environ.get('DEFAULT_ADMIN_PASSWORD', 'Admin@123')

# Optional Salesforce Connected App credentials — pre-fill the OAuth form.
# Users can always override per-scan; these are convenience defaults.
_SF_INSTANCE_URL  = os.environ.get('SF_INSTANCE_URL', 'https://login.salesforce.com')
_SF_CLIENT_ID     = os.environ.get('SF_CLIENT_ID', '')
_SF_CLIENT_SECRET = os.environ.get('SF_CLIENT_SECRET', '')


def _seed_default_admin(db) -> None:
	"""Create the default admin account if it does not already exist."""
	if db.query(User).filter(User.email == _DEFAULT_ADMIN_EMAIL).first():
		return
	user = User(
		username=_DEFAULT_ADMIN_USERNAME,
		email=_DEFAULT_ADMIN_EMAIL,
		hashed_password=hash_password(_DEFAULT_ADMIN_PASSWORD),
		is_admin=True,
	)
	db.add(user)
	db.commit()


# ---------------------------------------------------------------------------
# Startup: initialise database tables and seed default admin
# ---------------------------------------------------------------------------

@app.on_event('startup')
def on_startup():
	if _USING_EPHEMERAL_SQLITE:
		import warnings
		warnings.warn(
			'Running with ephemeral SQLite (/tmp). '
			'Set DATABASE_URL to a PostgreSQL URL for persistent storage.',
			RuntimeWarning, stacklevel=1,
		)
	init_db()
	db = next(get_db())
	try:
		_seed_default_admin(db)
	finally:
		db.close()


# ---------------------------------------------------------------------------
# Public routes (no auth required)
# ---------------------------------------------------------------------------

@app.get('/', response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
	user = _get_user(request, db)
	# Live stats shown on the home page
	total_scans = db.query(ScanJob).count()
	total_findings = db.query(Finding).count()
	critical_count = db.query(Finding).filter(Finding.severity == 'critical').count()
	return templates.TemplateResponse(request, 'home.html', _ctx(
		user,
		total_scans=total_scans,
		total_findings=total_findings,
		critical_count=critical_count,
	))


@app.get('/login', response_class=HTMLResponse)
def login_page(request: Request, db: Session = Depends(get_db), error: str = ''):
	if _get_user(request, db):
		return RedirectResponse('/dashboard', status_code=302)
	return templates.TemplateResponse(request, 'login.html', _ctx(error=error))


@app.post('/login')
def login_submit(
	request: Request,
	email: str = Form(...),
	password: str = Form(...),
	db: Session = Depends(get_db),
):
	user = db.query(User).filter(User.email == email.strip().lower()).first()
	if not user or not verify_password(password, user.hashed_password):
		return RedirectResponse('/login?error=Invalid+email+or+password', status_code=302)
	token = create_token(user.id)
	resp = RedirectResponse('/dashboard', status_code=302)
	resp.set_cookie(
		key=COOKIE_NAME, value=token,
		httponly=True, samesite='lax', max_age=60 * 60 * 24 * 30,
	)
	return resp


@app.get('/register', response_class=HTMLResponse)
def register_page(request: Request, db: Session = Depends(get_db), error: str = ''):
	if _get_user(request, db):
		return RedirectResponse('/dashboard', status_code=302)
	return templates.TemplateResponse(request, 'register.html', _ctx(error=error))


@app.post('/register')
def register_submit(
	request: Request,
	username: str = Form(...),
	email: str = Form(...),
	password: str = Form(...),
	db: Session = Depends(get_db),
):
	username = username.strip()
	email = email.strip().lower()
	# Input validation
	if len(username) < 3:
		return RedirectResponse('/register?error=Username+must+be+at+least+3+characters', status_code=302)
	if len(password) < 8:
		return RedirectResponse('/register?error=Password+must+be+at+least+8+characters', status_code=302)
	if db.query(User).filter(User.email == email).first():
		return RedirectResponse('/register?error=Email+already+registered', status_code=302)
	if db.query(User).filter(User.username == username).first():
		return RedirectResponse('/register?error=Username+already+taken', status_code=302)
	# First registered user becomes admin
	is_first = db.query(User).count() == 0
	user = User(
		username=username,
		email=email,
		hashed_password=hash_password(password),
		is_admin=is_first,
	)
	db.add(user)
	db.commit()
	return RedirectResponse('/login?success=Account+created.+Please+log+in.', status_code=302)


@app.get('/logout')
def logout():
	resp = RedirectResponse('/', status_code=302)
	resp.delete_cookie(COOKIE_NAME)
	return resp


# ---------------------------------------------------------------------------
# Protected routes
# ---------------------------------------------------------------------------

@app.get('/dashboard', response_class=HTMLResponse)
def dashboard(request: Request, db: Session = Depends(get_db)):
	user = _get_user(request, db)
	if not user:
		return RedirectResponse('/login', status_code=302)

	# Admins see all scans; regular users see only their own
	query = db.query(ScanJob) if user.is_admin else db.query(ScanJob).filter(ScanJob.user_id == user.id)
	recent_scans = query.order_by(ScanJob.created_at.desc()).limit(10).all()

	finding_q = db.query(Finding)
	if not user.is_admin:
		own_ids = [s.id for s in db.query(ScanJob).filter(ScanJob.user_id == user.id).all()]
		finding_q = finding_q.filter(Finding.scan_job_id.in_(own_ids))

	recent_findings = finding_q.order_by(Finding.id.desc()).limit(8).all()

	return templates.TemplateResponse(request, 'dashboard.html', _ctx(
		user,
		recent_scans=recent_scans,
		recent_findings=recent_findings,
	))


@app.get('/scans/new', response_class=HTMLResponse)
def scan_new(request: Request, db: Session = Depends(get_db)):
	user = _get_user(request, db)
	if not user:
		return RedirectResponse('/login', status_code=302)
	return templates.TemplateResponse(request, 'scan_new.html', _ctx(
		user,
		sf_instance_url=_SF_INSTANCE_URL,
		sf_client_id=_SF_CLIENT_ID,
	))


@app.post('/scans')
def scan_create(
	request: Request,
	target_url: str = Form(...),
	scan_type: str = Form('guest'),
	app_path: str = Form(''),
	aura_path: str = Form(''),
	proxy: str = Form(''),
	cookies: str = Form(''),
	openai_key: str = Form(''),
	db: Session = Depends(get_db),
):
	user = _get_user(request, db)
	if not user:
		return RedirectResponse('/login', status_code=302)

	if not target_url.strip():
		return RedirectResponse('/scans/new?error=Target+URL+is+required', status_code=302)

	job = ScanJob(
		user_id=user.id,
		target_url=target_url.strip(),
		scan_type=scan_type,
		app_path=app_path.strip() or None,
		aura_path=aura_path.strip() or None,
		proxy=proxy.strip() or None,
		status='pending',
	)
	db.add(job)
	db.commit()
	db.refresh(job)

	scan_runner.launch(job.id, {
		'target_url': target_url.strip(),
		'scan_type': scan_type,
		'app_path': app_path.strip() or None,
		'aura_path': aura_path.strip() or None,
		'proxy': proxy.strip() or None,
		'cookies': cookies.strip() or None,
		'openai_api_key': openai_key.strip() or None,
	})

	return RedirectResponse(f'/scans/{job.id}', status_code=302)


# ---------------------------------------------------------------------------
# Salesforce OAuth 2.0 web flow  (for authenticated scans via browser login)
# ---------------------------------------------------------------------------

@app.post('/auth/sf/start')
def sf_oauth_start(
	request: Request,
	target_url: str = Form(...),
	app_path: str = Form(''),
	aura_path: str = Form(''),
	proxy: str = Form(''),
	openai_key: str = Form(''),
	sf_instance_url: str = Form(...),
	sf_client_id: str = Form(...),
	sf_client_secret: str = Form(''),
	db: Session = Depends(get_db),
):
	"""Store pending scan params + Salesforce credentials, then redirect the
	user's browser to the Salesforce /authorize page to complete login."""
	user = _get_user(request, db)
	if not user:
		return RedirectResponse('/login', status_code=302)

	sf_instance_url = sf_instance_url.strip().rstrip('/')
	sf_client_id = sf_client_id.strip()

	if not target_url.strip():
		return RedirectResponse('/scans/new?error=Target+URL+is+required', status_code=302)
	if not sf_client_id:
		return RedirectResponse('/scans/new?error=Salesforce+Consumer+Key+is+required', status_code=302)

	web_redirect_uri = f'{APP_BASE_URL}/auth/sf/callback'
	state_id = str(uuid.uuid4())

	oauth_state = OAuthState(
		id=state_id,
		user_id=user.id,
		scan_params=json.dumps({
			'target_url': target_url.strip(),
			'app_path': app_path.strip() or None,
			'aura_path': aura_path.strip() or None,
			'proxy': proxy.strip() or None,
			'openai_api_key': openai_key.strip() or None,
		}),
		sf_instance_url=sf_instance_url,
		sf_client_id=sf_client_id,
		sf_client_secret=sf_client_secret.strip() or None,
		redirect_uri=web_redirect_uri,
	)
	db.add(oauth_state)
	db.commit()

	# Build the Salesforce authorization URL and redirect the user's browser.
	from ui.oauth_handler import SalesforceOAuthHandler
	handler = SalesforceOAuthHandler(
		instance_url=sf_instance_url,
		client_id=sf_client_id,
		client_secret=sf_client_secret.strip() or None,
	)
	auth_url = handler.get_authorization_url(redirect_uri=web_redirect_uri, state=state_id)
	return RedirectResponse(auth_url, status_code=302)


@app.get('/auth/sf/callback')
def sf_oauth_callback(
	request: Request,
	code: str = '',
	state: str = '',
	error: str = '',
	error_description: str = '',
	db: Session = Depends(get_db),
):
	"""Salesforce redirects here after the user logs in.  Exchange the
	authorization code for an access token, derive the session cookie,
	and launch the authenticated scan."""
	if error:
		msg = (error_description or error).replace(' ', '+')
		return RedirectResponse(f'/scans/new?error=Salesforce+OAuth+error:+{msg}', status_code=302)

	if not code or not state:
		return RedirectResponse('/scans/new?error=Invalid+OAuth+callback+(missing+code+or+state)', status_code=302)

	oauth_state = db.query(OAuthState).filter(OAuthState.id == state).first()
	if not oauth_state:
		return RedirectResponse('/scans/new?error=OAuth+state+expired+or+not+found.+Please+try+again.', status_code=302)

	user = db.query(User).filter(User.id == oauth_state.user_id).first()
	if not user:
		db.delete(oauth_state)
		db.commit()
		return RedirectResponse('/login', status_code=302)

	# Exchange the authorization code for an access token.
	try:
		from ui.oauth_handler import SalesforceOAuthHandler
		handler = SalesforceOAuthHandler(
			instance_url=oauth_state.sf_instance_url,
			client_id=oauth_state.sf_client_id,
			client_secret=oauth_state.sf_client_secret,
		)
		token_data = handler._exchange_code(code=code, redirect_uri=oauth_state.redirect_uri)
		session_cookie = handler.get_session_cookie(token_data['access_token'])
	except Exception as exc:
		logger.error('Salesforce OAuth token exchange failed: %s', exc)
		db.delete(oauth_state)
		db.commit()
		return RedirectResponse('/scans/new?error=Salesforce+token+exchange+failed.+Check+credentials.', status_code=302)

	# All good — create the scan job and launch it.
	scan_params = json.loads(oauth_state.scan_params)
	job = ScanJob(
		user_id=user.id,
		target_url=scan_params['target_url'],
		scan_type='auth',
		app_path=scan_params.get('app_path'),
		aura_path=scan_params.get('aura_path'),
		proxy=scan_params.get('proxy'),
		status='pending',
	)
	db.add(job)
	db.delete(oauth_state)
	db.commit()
	db.refresh(job)

	scan_runner.launch(job.id, {
		**scan_params,
		'scan_type': 'auth',
		'cookies': session_cookie,
	})

	return RedirectResponse(f'/scans/{job.id}', status_code=302)


@app.get('/scans/{scan_id}', response_class=HTMLResponse)
def scan_detail(scan_id: int, request: Request, db: Session = Depends(get_db)):
	user = _get_user(request, db)
	if not user:
		return RedirectResponse('/login', status_code=302)

	scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
	if not scan or (not user.is_admin and scan.user_id != user.id):
		return RedirectResponse('/dashboard', status_code=302)

	findings = scan.findings
	counts = {sev: sum(1 for f in findings if f.severity == sev)
			  for sev in ('critical', 'high', 'medium', 'low', 'info')}

	return templates.TemplateResponse(request, 'scan_detail.html', _ctx(
		user,
		scan=scan,
		findings=findings,
		counts=counts,
	))


@app.get('/scans/{scan_id}/status')
def scan_status(scan_id: int, request: Request, db: Session = Depends(get_db)):
	user = _get_user(request, db)
	if not user:
		return JSONResponse({'error': 'unauthorized'}, status_code=401)

	scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
	if not scan or (not user.is_admin and scan.user_id != user.id):
		return JSONResponse({'error': 'not found'}, status_code=404)

	return JSONResponse({
		'status': scan.status,
		'risk_score': scan.risk_score,
		'finding_count': len(scan.findings),
		'error': scan.error_message,
	})


@app.get('/reports/{scan_id}', response_class=HTMLResponse)
def report(scan_id: int, request: Request, db: Session = Depends(get_db)):
	user = _get_user(request, db)
	if not user:
		return RedirectResponse('/login', status_code=302)

	scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
	if not scan or (not user.is_admin and scan.user_id != user.id):
		return RedirectResponse('/dashboard', status_code=302)

	findings = scan.findings
	counts = {sev: sum(1 for f in findings if f.severity == sev)
			  for sev in ('critical', 'high', 'medium', 'low', 'info')}

	from ai_agents.remediation_advisor import RemediationAdvisor  # noqa: PLC0415
	advisor = RemediationAdvisor()
	remediation_sections = advisor.generate_report_sections(
		[type('F', (), {'owasp_ref': f.owasp_ref})() for f in findings]
	)

	return templates.TemplateResponse(request, 'report.html', _ctx(
		user,
		scan=scan,
		findings=findings,
		counts=counts,
		remediation_sections=remediation_sections,
		generated_at=datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'),
	))


# ---------------------------------------------------------------------------
# JSON API for Chart.js dashboard charts
# ---------------------------------------------------------------------------

@app.get('/api/stats')
def api_stats(request: Request, db: Session = Depends(get_db)):
	user = _get_user(request, db)
	if not user:
		return JSONResponse({'error': 'unauthorized'}, status_code=401)

	base_q = db.query(Finding)
	scan_q = db.query(ScanJob)
	if not user.is_admin:
		own_ids = [s.id for s in scan_q.filter(ScanJob.user_id == user.id).all()]
		base_q = base_q.filter(Finding.scan_job_id.in_(own_ids))
		scan_q = scan_q.filter(ScanJob.user_id == user.id)

	# Severity breakdown
	severity_counts = {}
	for sev in ('critical', 'high', 'medium', 'low', 'info'):
		severity_counts[sev] = base_q.filter(Finding.severity == sev).count()

	# OWASP breakdown
	owasp_counts: dict = {}
	for finding in base_q.all():
		ref = (finding.owasp_ref or 'Unknown').split()[0]
		owasp_counts[ref] = owasp_counts.get(ref, 0) + 1

	# Scans per day (last 14 days)
	from sqlalchemy import func  # noqa: PLC0415
	from datetime import timedelta  # noqa: PLC0415
	day_counts = []
	for delta in range(13, -1, -1):
		day = datetime.utcnow().date() - timedelta(days=delta)
		count = scan_q.filter(
			func.date(ScanJob.created_at) == day.isoformat()
		).count()
		day_counts.append({'date': day.isoformat(), 'count': count})

	return JSONResponse({
		'severity': severity_counts,
		'owasp': owasp_counts,
		'scans_per_day': day_counts,
		'total_scans': scan_q.count(),
		'total_findings': base_q.count(),
		'avg_risk_score': int(
			db.query(func.avg(ScanJob.risk_score))
			.filter(ScanJob.user_id == user.id, ScanJob.status == 'completed')
			.scalar() or 0
		),
	})


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
	import uvicorn
	uvicorn.run(
		'web.main:app',
		host='0.0.0.0',
		port=int(os.environ.get('WEB_PORT', 8080)),
		reload=False,
	)


if __name__ == '__main__':
	main()

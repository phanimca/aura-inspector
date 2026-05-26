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

from fastapi import Depends, FastAPI, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session

from web.auth import COOKIE_NAME, create_token, decode_token, hash_password, verify_password
from web.database import AiAnalysis, ConnectedApp, Finding, OAuthState, ScanJob, User, _USING_EPHEMERAL_SQLITE, get_db, init_db
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
#
# Resolution order (first non-empty value wins):
#   1. APP_BASE_URL env var          — set this once in Vercel to the permanent URL
#                                      e.g. https://phani-aura-inspector.vercel.app
#   2. VERCEL_PROJECT_PRODUCTION_URL — Vercel's stable production alias (no scheme)
#   3. VERCEL_URL                    — deployment-specific URL (changes per deploy,
#                                      DO NOT rely on this for OAuth redirect URIs)
#   4. WEB_PORT                      — local development fallback
#
# For Salesforce OAuth the redirect_uri MUST be stable and match the value
# registered in your Connected App.  Set APP_BASE_URL in Vercel environment
# variables (all environments) to avoid redirect_uri_mismatch errors.
# ---------------------------------------------------------------------------
def _resolve_app_base_url() -> str:
	explicit = os.environ.get('APP_BASE_URL', '').strip().rstrip('/')
	if explicit:
		return explicit
	if os.environ.get('VERCEL') == '1':
		# VERCEL_PROJECT_PRODUCTION_URL is the stable alias; available in Vercel Runtime ≥ 3
		prod_url = os.environ.get('VERCEL_PROJECT_PRODUCTION_URL', '').strip()
		if prod_url:
			return f'https://{prod_url}'
		# Last resort: deployment-specific URL (breaks OAuth if it changes between deploys)
		deploy_url = os.environ.get('VERCEL_URL', 'phani-aura-inspector.vercel.app').strip()
		return f'https://{deploy_url}'
	return f'http://localhost:{os.environ.get("WEB_PORT", "8080")}'

APP_BASE_URL: str = _resolve_app_base_url()
logger.info('APP_BASE_URL resolved to: %s', APP_BASE_URL)

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

# AI / OpenAI configuration — set OPENAI_API_KEY in Vercel environment variables
# to enable GPT-4o-powered analysis for all scans automatically.
# Individual scans can also supply their own key via the Advanced Options form.
# To use GitHub Models set:
#   OPENAI_BASE_URL = https://models.github.ai/inference
#   OPENAI_MODEL    = openai/gpt-4o-mini
#   OPENAI_API_KEY  = <your GitHub personal access token>
_AI_KEY_CONFIGURED: bool = bool(os.environ.get('OPENAI_API_KEY', '').strip())
_AI_BASE_URL: str = os.environ.get('OPENAI_BASE_URL', '').strip()
_AI_MODEL: str = os.environ.get('OPENAI_MODEL', 'openai/gpt-4o-mini')


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


def _seed_default_connected_app(db) -> None:
	"""If SF_CLIENT_ID is configured in env and no connected apps exist yet, create one."""
	if not _SF_CLIENT_ID:
		return
	if db.query(ConnectedApp).count() > 0:
		return
	app = ConnectedApp(
		name='Default (from environment)',
		client_id=_SF_CLIENT_ID,
		# No client_secret — PKCE-only flow; secret is never stored.
		login_url=_SF_INSTANCE_URL or 'https://login.salesforce.com',
		app_base_url=None,
	)
	db.add(app)
	db.commit()
	logger.info('Seeded default ConnectedApp from SF_CLIENT_ID env var')


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
		_seed_default_connected_app(db)
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
	connected_apps = db.query(ConnectedApp).order_by(ConnectedApp.name).all()
	return templates.TemplateResponse(request, 'scan_new.html', _ctx(
		user,
		sf_auth_enabled=bool(connected_apps),
		connected_apps=connected_apps,
		ai_enabled=_AI_KEY_CONFIGURED,
		ai_model=_AI_MODEL,
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
		'openai_base_url': _AI_BASE_URL or None,
	})

	return RedirectResponse(f'/scans/{job.id}', status_code=302)


# ---------------------------------------------------------------------------
# Connected Apps management  (admin-only CRUD)
# ---------------------------------------------------------------------------

@app.get('/connected-apps', response_class=HTMLResponse)
def connected_apps_list(request: Request, db: Session = Depends(get_db)):
	user = _get_user(request, db)
	if not user:
		return RedirectResponse('/login', status_code=302)
	if not user.is_admin:
		return RedirectResponse('/dashboard', status_code=302)
	apps = db.query(ConnectedApp).order_by(ConnectedApp.name).all()
	saved = request.query_params.get('saved')
	error = request.query_params.get('error')
	return templates.TemplateResponse(request, 'connected_apps.html', _ctx(
		user, connected_apps=apps, saved=saved, error=error,
	))


@app.post('/connected-apps')
def connected_apps_create(
	request: Request,
	name: str = Form(...),
	client_id: str = Form(...),
	login_url: str = Form('https://login.salesforce.com'),
	login_url_custom: str = Form(''),
	app_base_url: str = Form(''),
	db: Session = Depends(get_db),
):
	user = _get_user(request, db)
	if not user or not user.is_admin:
		return RedirectResponse('/login', status_code=302)
	resolved_login = login_url_custom.strip() if login_url == 'custom' else login_url.strip()
	resolved_login = resolved_login.rstrip('/') or 'https://login.salesforce.com'
	ca = ConnectedApp(
		name=name.strip(),
		client_id=client_id.strip(),
		# No client_secret — PKCE-only flow.
		login_url=resolved_login,
		app_base_url=app_base_url.strip().rstrip('/') or None,
	)
	db.add(ca)
	db.commit()
	return RedirectResponse('/connected-apps?saved=1', status_code=302)


@app.post('/connected-apps/{app_id}/edit')
def connected_apps_edit(
	request: Request,
	app_id: int,
	name: str = Form(...),
	client_id: str = Form(...),
	login_url: str = Form('https://login.salesforce.com'),
	login_url_custom: str = Form(''),
	app_base_url: str = Form(''),
	db: Session = Depends(get_db),
):
	user = _get_user(request, db)
	if not user or not user.is_admin:
		return RedirectResponse('/login', status_code=302)
	ca = db.query(ConnectedApp).filter(ConnectedApp.id == app_id).first()
	if not ca:
		return RedirectResponse('/connected-apps?error=Not+found', status_code=302)
	resolved_login = login_url_custom.strip() if login_url == 'custom' else login_url.strip()
	resolved_login = resolved_login.rstrip('/') or 'https://login.salesforce.com'
	ca.name = name.strip()
	ca.client_id = client_id.strip()
	# client_secret is never stored — PKCE-only flow.
	ca.login_url = resolved_login
	ca.app_base_url = app_base_url.strip().rstrip('/') or None
	db.commit()
	return RedirectResponse('/connected-apps?saved=1', status_code=302)


@app.post('/connected-apps/{app_id}/delete')
def connected_apps_delete(
	request: Request,
	app_id: int,
	db: Session = Depends(get_db),
):
	user = _get_user(request, db)
	if not user or not user.is_admin:
		return RedirectResponse('/login', status_code=302)
	ca = db.query(ConnectedApp).filter(ConnectedApp.id == app_id).first()
	if ca:
		db.delete(ca)
		db.commit()
	return RedirectResponse('/connected-apps', status_code=302)


@app.get('/api/connected-apps')
def connected_apps_api(request: Request, db: Session = Depends(get_db)):
	"""Return connected apps as JSON for the scan form dropdown."""
	user = _get_user(request, db)
	if not user:
		return JSONResponse({'apps': []})
	apps = db.query(ConnectedApp).order_by(ConnectedApp.name).all()
	return JSONResponse({'apps': [
		{'id': a.id, 'name': a.name, 'login_url': a.login_url}
		for a in apps
	]})


# ---------------------------------------------------------------------------
# Salesforce OAuth 2.0 web flow  (for authenticated scans via browser login)
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Popup OAuth helper
# ---------------------------------------------------------------------------

def _popup_html(script_body: str) -> HTMLResponse:
	"""Return a minimal HTML page that runs *script_body* and closes itself."""
	html = (
		'<!doctype html><html><head><meta charset="utf-8">'
		'<title>Salesforce Login</title>'
		'<style>body{background:#0d1117;color:#c9d1d9;font-family:system-ui,sans-serif;'
		'display:flex;align-items:center;justify-content:center;height:100vh;margin:0}'
		'.box{text-align:center;max-width:340px}'
		'.sp{width:40px;height:40px;border:3px solid #30363d;border-top-color:#58a6ff;'
		'border-radius:50%;animation:spin .8s linear infinite;margin:0 auto 1rem}'
		'@keyframes spin{to{transform:rotate(360deg)}}</style></head>'
		'<body><div class="box"><div class="sp" id="sp"></div>'
		'<p id="msg" style="color:#8b949e;font-size:.9rem;">Processing…</p></div>'
		f'<script>{script_body}</script></body></html>'
	)
	return HTMLResponse(content=html)


@app.get('/auth/sf/popup')
def sf_oauth_popup(
	request: Request,
	target_url: str = Query(''),
	app_path: str = Query(''),
	aura_path: str = Query(''),
	proxy: str = Query(''),
	openai_key: str = Query(''),
	connected_app_id: int = Query(0),
	# Legacy fallback — used only when no connected_app_id is provided
	sf_login_url: str = Query('https://login.salesforce.com'),
	db: Session = Depends(get_db),
):
	"""Start the Salesforce OAuth flow in a popup window.
	On completion the popup posts the session cookie back to the opener."""
	user = _get_user(request, db)
	if not user:
		return RedirectResponse('/login', status_code=302)

	if not target_url.strip():
		return _popup_html(
			'window.opener&&window.opener.postMessage('
			'{type:"sf_error",message:"Target URL is required"},'
			'window.location.origin);window.close();'
		)

	# Resolve the connected app credentials to use for this OAuth flow.
	# Priority: DB record (by connected_app_id) → env vars fallback.
	# Only client_id and login_url are needed — PKCE replaces client_secret.
	ca_client_id: str = ''
	ca_login_url: str = sf_login_url.strip().rstrip('/') or 'https://login.salesforce.com'
	ca_app_base_url: str = APP_BASE_URL

	if connected_app_id:
		ca = db.query(ConnectedApp).filter(ConnectedApp.id == connected_app_id).first()
		if ca:
			ca_client_id = ca.client_id
			ca_login_url = ca.login_url.rstrip('/')
			ca_app_base_url = (ca.app_base_url or APP_BASE_URL).rstrip('/')
		else:
			return _popup_html(
				'window.opener&&window.opener.postMessage('
				'{type:"sf_error",message:"Selected Connected App not found. Please reconfigure."},'
				'window.location.origin);window.close();'
			)
	elif _SF_CLIENT_ID:
		ca_client_id = _SF_CLIENT_ID
	else:
		return _popup_html(
			'window.opener&&window.opener.postMessage('
			'{type:"sf_error",message:"No Connected App configured. Add one in Settings \u2192 Connected Apps."},'
			'window.location.origin);window.close();'
		)

	web_redirect_uri = f'{ca_app_base_url}/auth/sf/callback'
	state_id = str(uuid.uuid4())

	from ui.oauth_handler import SalesforceOAuthHandler, generate_pkce_pair
	code_verifier, code_challenge = generate_pkce_pair()

	oauth_state = OAuthState(
		id=state_id,
		user_id=user.id,
		scan_params=json.dumps({
			'target_url': target_url.strip(),
			'app_path': app_path.strip() or None,
			'aura_path': aura_path.strip() or None,
			'proxy': proxy.strip() or None,
			'openai_api_key': openai_key.strip() or None,
			'openai_base_url': _AI_BASE_URL or None,
			'popup': True,
		}),
		sf_instance_url=ca_login_url,
		sf_client_id=ca_client_id,
		# sf_client_secret intentionally omitted — PKCE-only flow.
		redirect_uri=web_redirect_uri,
		code_verifier=code_verifier,
	)
	db.add(oauth_state)
	db.commit()

	handler = SalesforceOAuthHandler(
		instance_url=ca_login_url,
		client_id=ca_client_id,
	)
	auth_url = handler.get_authorization_url(
		redirect_uri=web_redirect_uri,
		state=state_id,
		code_challenge=code_challenge,
	)
	return RedirectResponse(auth_url, status_code=302)


@app.post('/auth/sf/start')
def sf_oauth_start(
	request: Request,
	target_url: str = Form(...),
	app_path: str = Form(''),
	aura_path: str = Form(''),
	proxy: str = Form(''),
	openai_key: str = Form(''),
	sf_login_url: str = Form('https://login.salesforce.com'),
	db: Session = Depends(get_db),
):
	"""Redirect the user to Salesforce's own login page.  No Connected App
	credentials are required from the user — the app's pre-configured
	SF_CLIENT_ID / SF_CLIENT_SECRET env vars drive the OAuth flow."""
	user = _get_user(request, db)
	if not user:
		return RedirectResponse('/login', status_code=302)

	if not target_url.strip():
		return RedirectResponse('/scans/new?error=Target+URL+is+required', status_code=302)

	if not _SF_CLIENT_ID:
		return RedirectResponse(
			'/scans/new?error=Authenticated+scans+are+not+configured+on+this+server.+'
			'Set+SF_CLIENT_ID+in+environment+variables.',
			status_code=302,
		)

	sf_instance_url = sf_login_url.strip().rstrip('/')
	web_redirect_uri = f'{APP_BASE_URL}/auth/sf/callback'
	state_id = str(uuid.uuid4())

	# Generate a PKCE pair before persisting OAuthState so everything is stored
	# in a single DB write.  The verifier is sent with the token exchange request
	# in the callback route; the challenge is sent in the authorization URL now.
	from ui.oauth_handler import SalesforceOAuthHandler, generate_pkce_pair
	code_verifier, code_challenge = generate_pkce_pair()

	oauth_state = OAuthState(
		id=state_id,
		user_id=user.id,
		scan_params=json.dumps({
			'target_url': target_url.strip(),
			'app_path': app_path.strip() or None,
			'aura_path': aura_path.strip() or None,
			'proxy': proxy.strip() or None,
			'openai_api_key': openai_key.strip() or None,
			'openai_base_url': _AI_BASE_URL or None,
		}),
		sf_instance_url=sf_instance_url,
		sf_client_id=_SF_CLIENT_ID,
		# sf_client_secret intentionally omitted — PKCE-only flow.
		redirect_uri=web_redirect_uri,
		code_verifier=code_verifier,
	)
	db.add(oauth_state)
	db.commit()

	# Build the Salesforce authorization URL and redirect the user's browser.
	handler = SalesforceOAuthHandler(
		instance_url=sf_instance_url,
		client_id=_SF_CLIENT_ID,
	)
	auth_url = handler.get_authorization_url(
		redirect_uri=web_redirect_uri,
		state=state_id,
		code_challenge=code_challenge,
	)
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
	and — depending on how the flow was started — either launch the scan
	directly (legacy POST flow) or postMessage the cookie back to the
	opener popup so the form can submit it (popup flow)."""

	# Detect popup mode early so error responses can close the popup.
	is_popup = False
	if state:
		_early = db.query(OAuthState).filter(OAuthState.id == state).first()
		if _early:
			try:
				is_popup = json.loads(_early.scan_params or '{}').get('popup', False)
			except Exception:
				pass

	def _err(msg: str):
		if is_popup:
			script = (
				f'(function(){{'
				f'var p={{type:"sf_error",message:{json.dumps(msg)}}};'
				f'document.getElementById("sp").style.display="none";'
				f'document.getElementById("msg").textContent={json.dumps(msg)};'
				f'if(window.opener){{window.opener.postMessage(p,window.location.origin);'
				f'setTimeout(function(){{window.close();}},1500);}}'
				f'}})();'
			)
			return _popup_html(script)
		return RedirectResponse(f"/scans/new?error={msg.replace(' ', '+')}", status_code=302)

	if error:
		desc = (error_description or error).strip()
		# Provide actionable guidance for the most common Salesforce OAuth errors.
		desc_lower = desc.lower()
		if 'external client app' in desc_lower and any(
			kw in desc_lower for kw in ('not installed', 'not found', 'not recognized')
		):
			# Spring '26: External Client Apps are org-scoped; the app must exist in the target org.
			msg = (
				"External client app is not installed in this org. "
				"As of Spring '26, Salesforce External Client Apps are scoped to the single org where "
				"they were created and cannot authenticate users in a different org. "
				"Fix \u2014 choose one: "
				"(1) EASIEST: use 'Paste Session Cookie' instead \u2014 log in to the target Salesforce org "
				"in your browser, open DevTools \u2192 Application \u2192 Cookies, copy the sid value, paste it. "
				"(2) Create a Connected App or External Client App inside the TARGET org "
				"(Setup \u2192 App Manager \u2192 New Connected App), then update SF_CLIENT_ID / SF_CLIENT_SECRET. "
				"(3) If using a pre-Spring '26 Connected App, set the Login URL to the org "
				"where that Connected App was originally registered."
			)
		elif 'cross' in desc_lower and 'org' in desc_lower:
			msg = (
				'Cross-org OAuth is not enabled on your External Client App. '
				'Fix: Setup \u2192 Apps \u2192 App Manager \u2192 [Your App] \u2192 Edit \u2192 OAuth Policies \u2192 '
				'enable "Allow Cross-Org OAuth Flows". '
				'Alternatively, create a Connected App in the target org, '
				'or set the Login URL to the org where your Connected App was registered.'
			)
		elif 'redirect_uri' in desc_lower:
			msg = (
				'redirect_uri mismatch. '
				'Add https://phani-aura-inspector.vercel.app/auth/sf/callback '
				'as a Callback URL in your Connected App (Setup \u2192 App Manager \u2192 Edit).'
			)
		else:
			msg = desc
		return _err(msg)

	if not code or not state:
		return _err('Invalid OAuth callback (missing code or state)')

	oauth_state = db.query(OAuthState).filter(OAuthState.id == state).first()
	if not oauth_state:
		return _err('OAuth state expired or not found. Please try again.')

	user = db.query(User).filter(User.id == oauth_state.user_id).first()
	if not user:
		db.delete(oauth_state)
		db.commit()
		if is_popup:
			return _popup_html(
				'window.opener&&window.opener.postMessage({type:"sf_error",'
				'message:"Session expired — please log in again."},'
				'window.location.origin);window.close();'
			)
		return RedirectResponse('/login', status_code=302)

	# Exchange the authorization code for an access token.
	try:
		from ui.oauth_handler import SalesforceOAuthHandler
		handler = SalesforceOAuthHandler(
			instance_url=oauth_state.sf_instance_url,
			client_id=oauth_state.sf_client_id,
			# No client_secret — PKCE code_verifier is the security credential.
		)
		token_data = handler._exchange_code(
			code=code,
			redirect_uri=oauth_state.redirect_uri,
			code_verifier=oauth_state.code_verifier,
		)
		session_cookie = handler.get_session_cookie(token_data['access_token'])
	except Exception as exc:
		logger.error('Salesforce OAuth token exchange failed: %s', exc)
		db.delete(oauth_state)
		db.commit()
		return _err('Salesforce token exchange failed. Check Connected App credentials.')

	scan_params = json.loads(oauth_state.scan_params)
	db.delete(oauth_state)
	db.commit()

	if scan_params.get('popup'):
		# Popup flow — postMessage the session cookie back to the opener.
		# The parent form fills the cookies field and submits to /scans.
		cookie_json = json.dumps(session_cookie)
		script = (
			f'(function(){{'
			f'var p={{type:"sf_session",cookies:{cookie_json}}};'
			f'document.getElementById("sp").style.display="none";'
			f'document.getElementById("msg").textContent="Login successful! Starting scan\u2026";'
			f'if(window.opener){{window.opener.postMessage(p,window.location.origin);'
			f'setTimeout(function(){{window.close();}},800);}}'
			f'else{{document.getElementById("msg").textContent='
			f'"Login successful. You may close this window.";}}'
			f'}})();'
		)
		return _popup_html(script)

	# Legacy full-page flow — start the scan directly and redirect.
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
		'progress': getattr(scan, 'progress', '') or '',
	})


@app.post('/scans/{scan_id}/cancel')
def scan_cancel(scan_id: int, request: Request, db: Session = Depends(get_db)):
	user = _get_user(request, db)
	if not user:
		return JSONResponse({'error': 'unauthorized'}, status_code=401)

	scan = db.query(ScanJob).filter(ScanJob.id == scan_id).first()
	if not scan or (not user.is_admin and scan.user_id != user.id):
		return JSONResponse({'error': 'not found'}, status_code=404)

	if scan.status not in ('pending', 'running'):
		return JSONResponse({'error': f'scan is already {scan.status}'}, status_code=400)

	# Signal the background thread to stop.
	scan_runner.cancel(scan_id)

	# Update DB immediately for instant UI feedback; the thread also
	# updates when it detects the stop_event.
	scan.status = 'cancelled'
	scan.progress = 'Cancelling…'
	try:
		from datetime import datetime as _dt
		scan.cancelled_at = _dt.utcnow()
	except Exception:
		pass
	db.commit()
	return JSONResponse({'status': 'cancelled'})


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
	# Per-finding remediation lookup (setup steps + apex code), keyed by finding id.
	remediation_by_finding = {
		f.id: advisor.get_remediation(type('F', (), {'owasp_ref': f.owasp_ref})())
		for f in findings
	}

	# ── Risk score ──────────────────────────────────────────────────────────
	# Use AI-provided score when available; otherwise compute from finding severities.
	_ai_score = (scan.ai_analysis.risk_score if scan.ai_analysis else 0) or 0
	_sev_weight = {'critical': 25, 'high': 15, 'medium': 7, 'low': 3, 'info': 0}
	_computed_score = min(sum(_sev_weight.get(f.severity, 0) for f in findings), 100)
	if counts['critical']:
		_computed_score = max(_computed_score, 75)
	elif counts['high']:
		_computed_score = max(_computed_score, 50)
	elif counts['medium']:
		_computed_score = max(_computed_score, 30)
	risk_score: int = _ai_score if _ai_score > 0 else _computed_score
	risk_label: str = (
		'CRITICAL' if risk_score >= 80 else
		'HIGH'     if risk_score >= 60 else
		'MEDIUM'   if risk_score >= 40 else
		'LOW'
	)

	# ── Affected Salesforce objects aggregation ──────────────────────────────
	# Aggregate all affected_objects lists across findings; promote to highest severity.
	_sev_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
	_obj_map: dict[str, dict] = {}
	for _f in findings:
		for _obj in (_f.affected_objects or []):
			if _obj not in _obj_map:
				_obj_map[_obj] = {'severity': _f.severity, 'finding_titles': [_f.title]}
			else:
				_e = _obj_map[_obj]
				if _sev_order.get(_f.severity, 4) < _sev_order.get(_e['severity'], 4):
					_e['severity'] = _f.severity
				if _f.title not in _e['finding_titles']:
					_e['finding_titles'].append(_f.title)
	affected_objects_list = sorted(
		[{'name': k, **v} for k, v in _obj_map.items()],
		key=lambda x: _sev_order.get(x['severity'], 5),
	)

	# Unique scanner modules that contributed findings
	scanner_names: list[str] = sorted({f.scanner for f in findings if f.scanner})

	return templates.TemplateResponse(request, 'report.html', _ctx(
		user,
		scan=scan,
		findings=findings,
		counts=counts,
		remediation_sections=remediation_sections,
		remediation_by_finding=remediation_by_finding,
		generated_at=datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC'),
		risk_score=risk_score,
		risk_label=risk_label,
		affected_objects_list=affected_objects_list,
		scanner_names=scanner_names,
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

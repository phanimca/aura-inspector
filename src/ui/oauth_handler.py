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
Salesforce OAuth 2.0 Authorization Code + PKCE (S256) flow handler.

Uses the same approach as the Salesforce CLI `sf org login web` command:
no Consumer Secret is required or stored.

Prerequisites (one-time Salesforce Setup steps)
------------------------------------------------
1. Setup > App Manager > New Connected App (or External Client App).
2. Enable OAuth Settings.
3. Set the callback URL to: http://localhost:8484/callback
4. Add scopes: api, web.
5. In OAuth Policies, uncheck "Require Secret for Web Server Flow"
   (or enable "Require PKCE").
6. Note the Consumer Key (client_id) — the Consumer Secret is NOT needed.

Usage
-----
    handler = SalesforceOAuthHandler(
        instance_url='https://login.salesforce.com',
        client_id='3MVG9...',
    )
    token_data = handler.authenticate_browser_flow()
    # token_data = {'access_token': '...', 'instance_url': '...', 'scope': '...'}
    cookies = handler.get_session_cookie(token_data['access_token'])
    # cookies = 'sid=...'  – ready for AuraHelper
"""

import base64
import hashlib
import secrets
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import requests


def generate_pkce_pair() -> tuple[str, str]:
	"""Return (code_verifier, code_challenge) for the S256 PKCE method.

	The verifier is a cryptographically random URL-safe string (86 chars,
	well within the RFC 7636 requirement of 43–128 characters).  The
	challenge is BASE64URL(SHA-256(verifier)) without padding, as required
	by Salesforce when 'Require PKCE' is enabled on the Connected App.
	"""
	code_verifier = secrets.token_urlsafe(64)
	digest = hashlib.sha256(code_verifier.encode()).digest()
	code_challenge = base64.urlsafe_b64encode(digest).rstrip(b'=').decode()
	return code_verifier, code_challenge

CALLBACK_PORT = 8484
REDIRECT_URI = f'http://localhost:{CALLBACK_PORT}/callback'

_SUCCESS_HTML = (
	b'<!DOCTYPE html><html><head><title>SF Security AI Scanner - Connected</title></head>'
	b'<body style="font-family:sans-serif;text-align:center;padding-top:60px">'
	b'<h2>Authentication successful!</h2>'
	b'<p>You may close this browser tab and return to Salesforce Security AI Scanner.</p>'
	b'</body></html>'
)

_FAILURE_HTML = (
	b'<!DOCTYPE html><html><head><title>SF Security AI Scanner - Failed</title></head>'
	b'<body style="font-family:sans-serif;text-align:center;padding-top:60px">'
	b'<h2>Authentication failed.</h2>'
	b'<p>Check the Salesforce Security AI Scanner console for details.</p>'
	b'</body></html>'
)


class _CallbackHandler(BaseHTTPRequestHandler):
	"""Single-use HTTP handler that captures the OAuth authorization code."""

	# Shared state between the handler and the waiting thread
	auth_code: str = None
	auth_error: str = None

	def do_GET(self):  # noqa: N802 (Salesforce/Python HTTP convention)
		parsed = urlparse(self.path)
		params = parse_qs(parsed.query)

		if 'code' in params:
			_CallbackHandler.auth_code = params['code'][0]
			self._respond(200, _SUCCESS_HTML)
		elif 'error' in params:
			desc = params.get('error_description', ['Unknown OAuth error'])[0]
			_CallbackHandler.auth_error = desc
			self._respond(400, _FAILURE_HTML)
		else:
			self._respond(404, b'Not found')

	def _respond(self, status: int, body: bytes):
		self.send_response(status)
		self.send_header('Content-Type', 'text/html; charset=utf-8')
		self.send_header('Content-Length', str(len(body)))
		self.end_headers()
		self.wfile.write(body)

	def log_message(self, format, *args):  # suppress server access logs
		pass


class SalesforceOAuthHandler:
	"""
	Manages the Salesforce OAuth 2.0 Authorization Code Flow.

	The handler spins up a temporary local HTTP server on CALLBACK_PORT,
	opens the user's browser to the Salesforce authorization page, and
	captures the code when Salesforce redirects back.
	"""

	def __init__(self, instance_url: str, client_id: str, client_secret: str = None):
		if not instance_url:
			raise ValueError('instance_url is required')
		if not client_id:
			raise ValueError('client_id (Consumer Key) is required')
		self.instance_url = instance_url.rstrip('/')
		self.client_id = client_id
		self.client_secret = client_secret

	# ------------------------------------------------------------------
	# Public API
	# ------------------------------------------------------------------

	def get_authorization_url(
		self,
		redirect_uri: str = None,
		state: str = None,
		code_challenge: str = None,
		code_challenge_method: str = 'S256',
	) -> str:
		"""Build the Salesforce /authorize URL that the user must visit.

		Pass *code_challenge* (from :func:`generate_pkce_pair`) when the Connected
		App has "Require PKCE" enabled — Salesforce will reject the request with
		``missing required code challenge`` otherwise.
		"""
		params = {
			'response_type': 'code',
			'client_id': self.client_id,
			'redirect_uri': redirect_uri or REDIRECT_URI,
			'scope': 'api web',
			'prompt': 'login',
		}
		if state:
			params['state'] = state
		if code_challenge:
			params['code_challenge'] = code_challenge
			params['code_challenge_method'] = code_challenge_method
		return f'{self.instance_url}/services/oauth2/authorize?{urlencode(params)}'

	def authenticate_browser_flow(self, timeout_seconds: int = 120) -> dict:
		"""
		Open the browser to Salesforce, wait for the OAuth callback, exchange
		the code for a token using PKCE (S256), and return the token dict.

		Raises
		------
		TimeoutError  – if the callback is not received within *timeout_seconds*.
		ValueError    – if Salesforce returns an OAuth error or token exchange fails.
		"""
		# Reset shared state before each use
		_CallbackHandler.auth_code = None
		_CallbackHandler.auth_error = None

		server = HTTPServer(('localhost', CALLBACK_PORT), _CallbackHandler)
		server_thread = threading.Thread(target=server.serve_forever, daemon=True)
		server_thread.start()

		# Generate a fresh PKCE pair for this auth request.
		code_verifier, code_challenge = generate_pkce_pair()

		auth_url = self.get_authorization_url(
			redirect_uri=REDIRECT_URI,
			code_challenge=code_challenge,
		)
		webbrowser.open(auth_url)

		deadline = time.time() + timeout_seconds
		while _CallbackHandler.auth_code is None and _CallbackHandler.auth_error is None:
			if time.time() > deadline:
				server.shutdown()
				raise TimeoutError(
					f'OAuth callback not received within {timeout_seconds} seconds. '
					f'Did you complete login in the browser?'
				)
			time.sleep(0.5)

		server.shutdown()

		if _CallbackHandler.auth_error:
			raise ValueError(f'OAuth authorization error: {_CallbackHandler.auth_error}')

		return self._exchange_code(
			code=_CallbackHandler.auth_code,
			redirect_uri=REDIRECT_URI,
			code_verifier=code_verifier,
		)

	def get_session_cookie(self, access_token: str, verify_with_userinfo: bool = True) -> str:
		"""
		Convert an OAuth access_token to the cookie string expected by AuraHelper.

		Salesforce Aura uses the SID cookie which corresponds to the session token.
		When the Connected App is set up with the 'web' scope the access_token is
		directly usable as the SID.

		Returns a string like 'sid=<access_token>' ready to pass as *cookies* to AuraHelper.
		"""
		return f'sid={access_token}'

	# ------------------------------------------------------------------
	# Internal helpers
	# ------------------------------------------------------------------

	def _exchange_code(self, code: str, redirect_uri: str = None, code_verifier: str = None) -> dict:
		"""POST to /services/oauth2/token and return the response payload.

		Uses the PKCE Web Server Flow (no client_secret).  The Connected App in
		Salesforce must have "Require Secret for Web Server Flow" unchecked, or
		"Require PKCE" enabled.  This is the same approach used by the Salesforce
		CLI `sf org login web` command.

		Pass *code_verifier* (the value stored during :meth:`get_authorization_url`)
		so Salesforce can verify the PKCE challenge.
		"""
		payload = {
			'grant_type': 'authorization_code',
			'code': code,
			'redirect_uri': redirect_uri or REDIRECT_URI,
			'client_id': self.client_id,
		}
		# client_secret is intentionally omitted — PKCE code_verifier is the
		# security credential.  Never include client_secret in the exchange.
		if code_verifier:
			payload['code_verifier'] = code_verifier

		response = requests.post(
			f'{self.instance_url}/services/oauth2/token',
			data=payload,
			timeout=30,
		)
		if response.status_code != 200:
			raise ValueError(
				f'Token exchange failed (HTTP {response.status_code}): {response.text[:300]}'
			)
		token_data = response.json()
		return {
			'access_token': token_data['access_token'],
			'instance_url': token_data.get('instance_url', self.instance_url),
			'token_type': token_data.get('token_type', 'Bearer'),
			'scope': token_data.get('scope', ''),
			'refresh_token': token_data.get('refresh_token'),
		}

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
Salesforce OAuth 2.0 Authorization Code Flow handler for Experience Cloud.

Prerequisites (one-time Salesforce Setup steps)
------------------------------------------------
1. Setup > App Manager > New Connected App
2. Enable OAuth Settings.
3. Set the callback URL to: http://localhost:8484/callback
4. Add scopes: api, web, refresh_token (or the minimum your test requires).
5. Note the Consumer Key (client_id) and Consumer Secret (client_secret).

Usage
-----
    handler = SalesforceOAuthHandler(
        instance_url='https://login.salesforce.com',
        client_id='3MVG9...',
        client_secret='optional_for_web_server_flow',
    )
    token_data = handler.authenticate_browser_flow()
    # token_data = {'access_token': '...', 'instance_url': '...', 'scope': '...'}
    cookies = handler.get_session_cookie(token_data['access_token'])
    # cookies = 'sid=...'  – ready for AuraHelper
"""

import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

import requests

CALLBACK_PORT = 8484
REDIRECT_URI = f'http://localhost:{CALLBACK_PORT}/callback'

_SUCCESS_HTML = (
	b'<!DOCTYPE html><html><head><title>Aura Inspector - Connected</title></head>'
	b'<body style="font-family:sans-serif;text-align:center;padding-top:60px">'
	b'<h2>Authentication successful!</h2>'
	b'<p>You may close this browser tab and return to Aura Inspector.</p>'
	b'</body></html>'
)

_FAILURE_HTML = (
	b'<!DOCTYPE html><html><head><title>Aura Inspector - Failed</title></head>'
	b'<body style="font-family:sans-serif;text-align:center;padding-top:60px">'
	b'<h2>Authentication failed.</h2>'
	b'<p>Check the Aura Inspector console for details.</p>'
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

	def get_authorization_url(self) -> str:
		"""Build the Salesforce /authorize URL that the user must visit."""
		params = {
			'response_type': 'code',
			'client_id': self.client_id,
			'redirect_uri': REDIRECT_URI,
			'scope': 'api web',
			'prompt': 'login',
		}
		return f'{self.instance_url}/services/oauth2/authorize?{urlencode(params)}'

	def authenticate_browser_flow(self, timeout_seconds: int = 120) -> dict:
		"""
		Open the browser to Salesforce, wait for the OAuth callback, exchange
		the code for a token, and return the token dict.

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

		auth_url = self.get_authorization_url()
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

		return self._exchange_code(code=_CallbackHandler.auth_code)

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

	def _exchange_code(self, code: str) -> dict:
		"""POST to /services/oauth2/token and return the response payload."""
		payload = {
			'grant_type': 'authorization_code',
			'code': code,
			'redirect_uri': REDIRECT_URI,
			'client_id': self.client_id,
		}
		if self.client_secret:
			payload['client_secret'] = self.client_secret

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

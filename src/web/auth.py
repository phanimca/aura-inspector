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
Password hashing and JWT session token utilities for the Aura Inspector web app.
Tokens are stored in an HttpOnly cookie named COOKIE_NAME to prevent XSS access.
"""

import os
from datetime import datetime, timedelta

from jose import JWTError, jwt
from passlib.context import CryptContext

# Override SECRET_KEY in production via the environment variable
SECRET_KEY: str = os.environ.get(
	'SECRET_KEY', 'aura-inspector-dev-key-REPLACE-IN-PRODUCTION'
)
ALGORITHM = 'HS256'
TOKEN_EXPIRE_DAYS = 30
COOKIE_NAME = 'aura_session'

pwd_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


def hash_password(password: str) -> str:
	return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
	return pwd_context.verify(plain, hashed)


def create_token(user_id: int) -> str:
	expire = datetime.utcnow() + timedelta(days=TOKEN_EXPIRE_DAYS)
	payload = {'sub': str(user_id), 'exp': expire}
	return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict | None:
	"""Return the JWT payload dict, or None if the token is invalid or expired."""
	try:
		return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
	except JWTError:
		return None

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
SQLAlchemy models and session factory for the Salesforce Security AI Scanner web application.
Database: SQLite at <project-root>/data/aura_inspector.db (local)
         or the URL specified by the DATABASE_URL environment variable (cloud).

For persistent storage on Vercel (or any serverless platform), set DATABASE_URL
to a PostgreSQL connection string, e.g.:
  postgresql://user:pass@host/dbname?sslmode=require  (Neon / Vercel Postgres)
Without it the app falls back to SQLite in /tmp which is EPHEMERAL — all data
is lost when the serverless container is replaced.
"""

import logging
import os
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

from sqlalchemy import (
	Boolean, Column, DateTime, ForeignKey,
	Integer, JSON, String, Text, create_engine,
)
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker

# ---------------------------------------------------------------------------
# Environment detection
# ---------------------------------------------------------------------------
# Vercel automatically sets VERCEL=1 on every serverless invocation.
# Use it instead of fragile filesystem probing.
_IS_VERCEL: bool = os.environ.get('VERCEL') == '1'

# Resolve the database URL.
# Priority:
#   1. DATABASE_URL env var  — must contain a valid scheme (e.g. postgresql://,
#                               sqlite:///...).  Empty / non-URL values are ignored.
#   2. /tmp (Vercel)          — ephemeral but always writable on serverless.
#   3. Local data/ directory  — used when running locally or in Docker.
_raw_db_url = os.environ.get('DATABASE_URL', '').strip()
# Some providers (Heroku, Vercel Postgres) emit postgres:// — SQLAlchemy 2.x
# requires the postgresql:// scheme.  Fix it transparently.
_raw_db_url = _raw_db_url.replace('postgres://', 'postgresql://', 1) if _raw_db_url.startswith('postgres://') else _raw_db_url
DATABASE_URL: str = _raw_db_url if '://' in _raw_db_url else ''

_USING_EPHEMERAL_SQLITE = False  # flipped below when falling back to /tmp

if not DATABASE_URL:
	if _IS_VERCEL:
		DATABASE_URL = 'sqlite:////tmp/aura_inspector.db'
		_USING_EPHEMERAL_SQLITE = True
		logger.warning(
			'No DATABASE_URL set — using ephemeral SQLite at /tmp/aura_inspector.db. '
			'All data will be lost on container restart. '
			'Set DATABASE_URL to a PostgreSQL URL (e.g. Neon/Vercel Postgres) for persistence.'
		)
	else:
		_DATA_DIR = Path(__file__).resolve().parent.parent.parent / 'data'
		_DATA_DIR.mkdir(exist_ok=True)
		DATABASE_URL = f'sqlite:///{_DATA_DIR}/aura_inspector.db'

logger.info('Database: %s', DATABASE_URL.split('@')[-1] if '@' in DATABASE_URL else DATABASE_URL)

# SQLite needs check_same_thread=False; PostgreSQL needs pool_pre_ping to
# recover stale connections after serverless container hibernation.
_is_sqlite = DATABASE_URL.startswith('sqlite')
_connect_args = {'check_same_thread': False} if _is_sqlite else {}
engine = create_engine(
	DATABASE_URL,
	connect_args=_connect_args,
	pool_pre_ping=not _is_sqlite,  # re-check connections on checkout (PostgreSQL)
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
	pass


class User(Base):
	__tablename__ = 'users'
	id = Column(Integer, primary_key=True, index=True)
	username = Column(String(50), unique=True, index=True, nullable=False)
	email = Column(String(255), unique=True, index=True, nullable=False)
	hashed_password = Column(String(255), nullable=False)
	is_admin = Column(Boolean, default=False)
	created_at = Column(DateTime, default=datetime.utcnow)
	scans = relationship('ScanJob', back_populates='user', cascade='all, delete-orphan')


class ScanJob(Base):
	__tablename__ = 'scan_jobs'
	id = Column(Integer, primary_key=True, index=True)
	user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
	target_url = Column(String(512), nullable=False)
	scan_type = Column(String(20), default='guest')  # guest | auth
	app_path = Column(String(256))
	aura_path = Column(String(256))
	proxy = Column(String(256))
	status = Column(String(20), default='pending')  # pending | running | completed | failed | cancelled
	progress = Column(String(200), default='')       # human-readable phase label updated in real-time
	error_message = Column(Text)
	risk_score = Column(Integer, default=0)
	created_at = Column(DateTime, default=datetime.utcnow)
	completed_at = Column(DateTime)
	cancelled_at = Column(DateTime)
	user = relationship('User', back_populates='scans')
	findings = relationship('Finding', back_populates='scan_job', cascade='all, delete-orphan')
	ai_analysis = relationship(
		'AiAnalysis', back_populates='scan_job', uselist=False, cascade='all, delete-orphan'
	)


class Finding(Base):
	__tablename__ = 'findings'
	id = Column(Integer, primary_key=True, index=True)
	scan_job_id = Column(Integer, ForeignKey('scan_jobs.id'), nullable=False)
	scanner = Column(String(50))
	title = Column(String(512))
	severity = Column(String(20))  # critical | high | medium | low | info
	description = Column(Text)
	evidence = Column(Text)
	remediation = Column(Text)
	owasp_ref = Column(String(100))
	affected_objects = Column(JSON)
	scan_job = relationship('ScanJob', back_populates='findings')


class AiAnalysis(Base):
	__tablename__ = 'ai_analyses'
	id = Column(Integer, primary_key=True, index=True)
	scan_job_id = Column(Integer, ForeignKey('scan_jobs.id'), unique=True, nullable=False)
	risk_score = Column(Integer, default=0)
	risk_summary = Column(Text)
	critical_patterns = Column(JSON)
	priority_actions = Column(JSON)
	scan_job = relationship('ScanJob', back_populates='ai_analysis')


class OAuthState(Base):
	"""Temporary record that links an in-flight Salesforce OAuth flow to a pending scan.

	Lifecycle:
	  1. Created by POST /auth/sf/start (stores scan params + SF credentials).
	  2. Passed as `state` to Salesforce's /authorize URL.
	  3. Consumed (deleted) by GET /auth/sf/callback after the code is exchanged.
	  4. Rows older than 10 minutes can be considered stale and garbage-collected.
	"""
	__tablename__ = 'oauth_states'
	id = Column(String(64), primary_key=True)          # UUID4 — also the OAuth `state` param
	user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
	created_at = Column(DateTime, default=datetime.utcnow)
	scan_params = Column(Text, nullable=False)           # JSON: target_url, app_path, ...
	sf_instance_url = Column(String(500), nullable=False)
	sf_client_id = Column(String(500), nullable=False)
	sf_client_secret = Column(String(500))               # Optional — only for web-server flow
	redirect_uri = Column(String(500), nullable=False)   # Must match token exchange exactly
	code_verifier = Column(String(128))                  # PKCE verifier — required when Connected App enforces PKCE


# FastAPI dependency: yields a DB session and closes it when the request ends
def get_db():
	db = SessionLocal()
	try:
		yield db
	finally:
		db.close()


def init_db():
	"""Create all tables if they do not yet exist, then run incremental migrations."""
	Base.metadata.create_all(bind=engine)
	_run_migrations()


def _run_migrations() -> None:
	"""Apply additive schema changes to existing tables (safe to run on every startup)."""
	from sqlalchemy import inspect as sa_inspect, text
	inspector = sa_inspect(engine)
	# SQLite uses DATETIME; PostgreSQL uses TIMESTAMP.
	ts_type = 'DATETIME' if DATABASE_URL.startswith('sqlite') else 'TIMESTAMP'
	# scan_jobs additions introduced with the parallel-scan / cancel feature
	if 'scan_jobs' in inspector.get_table_names():
		existing = {c['name'] for c in inspector.get_columns('scan_jobs')}
		additions: list[tuple[str, str]] = []
		if 'progress' not in existing:
			additions.append(('progress', "ALTER TABLE scan_jobs ADD COLUMN progress VARCHAR(200) DEFAULT ''"))
		if 'cancelled_at' not in existing:
			additions.append(('cancelled_at', f'ALTER TABLE scan_jobs ADD COLUMN cancelled_at {ts_type}'))
		# Each ALTER runs in its own transaction so a failure on one column
		# does not abort and roll back the other (PostgreSQL aborts the whole
		# transaction on any error, so sharing one BEGIN block is unsafe).
		for col_name, stmt in additions:
			try:
				with engine.begin() as conn:
					conn.execute(text(stmt))
				logger.info('Migration applied: added scan_jobs.%s', col_name)
			except Exception as exc:  # column already exists in a concurrent startup
				logger.debug('Migration skipped for scan_jobs.%s: %s', col_name, exc)
	# oauth_states additions introduced with PKCE support
	if 'oauth_states' in inspector.get_table_names():
		existing_oa = {c['name'] for c in inspector.get_columns('oauth_states')}
		if 'code_verifier' not in existing_oa:
			try:
				with engine.begin() as conn:
					conn.execute(text('ALTER TABLE oauth_states ADD COLUMN code_verifier VARCHAR(128)'))
				logger.info('Migration applied: added oauth_states.code_verifier')
			except Exception as exc:
				logger.debug('Migration skipped for oauth_states.code_verifier: %s', exc)

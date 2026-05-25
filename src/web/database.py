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
SQLAlchemy models and session factory for the Aura Inspector web application.
Database: SQLite at <project-root>/data/aura_inspector.db (local)
         or the URL specified by the DATABASE_URL environment variable (cloud).
"""

import os
from datetime import datetime
from pathlib import Path

from sqlalchemy import (
	Boolean, Column, DateTime, ForeignKey,
	Integer, JSON, String, Text, create_engine,
)
from sqlalchemy.orm import DeclarativeBase, relationship, sessionmaker

# Resolve the database URL.
# Priority:
#   1. DATABASE_URL env var  — set this in Vercel/cloud to point at a managed DB
#                               (e.g. postgresql://... or sqlite:////tmp/...)
#   2. Local data/ directory — used when running locally or in Docker
#   3. /tmp fallback          — used on read-only serverless filesystems (Vercel)
DATABASE_URL = os.environ.get('DATABASE_URL')
if not DATABASE_URL:
	_DATA_DIR = Path(__file__).resolve().parent.parent.parent / 'data'
	try:
		_DATA_DIR.mkdir(exist_ok=True)
		DATABASE_URL = f'sqlite:///{_DATA_DIR}/aura_inspector.db'
	except OSError:
		# Serverless environment with read-only project root (e.g. Vercel) —
		# fall back to the writable /tmp directory.
		DATABASE_URL = 'sqlite:////tmp/aura_inspector.db'

engine = create_engine(DATABASE_URL, connect_args={'check_same_thread': False})
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
	status = Column(String(20), default='pending')  # pending | running | completed | failed
	error_message = Column(Text)
	risk_score = Column(Integer, default=0)
	created_at = Column(DateTime, default=datetime.utcnow)
	completed_at = Column(DateTime)
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


# FastAPI dependency: yields a DB session and closes it when the request ends
def get_db():
	db = SessionLocal()
	try:
		yield db
	finally:
		db.close()


def init_db():
	"""Create all tables if they do not yet exist."""
	Base.metadata.create_all(bind=engine)

#!/usr/bin/env python
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
validate_env.py
===============
Pre-flight environment check for aura-inspector.

Verifies:
  1. Python version is 3.11 or higher.
  2. Required base dependency (requests) is importable.
  3. Optional dependency groups (ai, mcp, web) are importable when present.
  4. All key repository files exist.
  5. SECRET_KEY is not the development default when WEB_ENV=production.
  6. OPENAI_API_KEY presence / basic format check.

Exits 0 when all required checks pass (optional checks only warn).
Exits 1 on any required-check failure.

Usage
-----
    python scripts/validate_env.py
    python scripts/validate_env.py --strict   # treat optional warnings as errors
"""

import importlib
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent

_GREEN  = '\033[92m'
_YELLOW = '\033[93m'
_RED    = '\033[91m'
_CYAN   = '\033[96m'
_RESET  = '\033[0m'
_BOLD   = '\033[1m'

_STRICT = '--strict' in sys.argv


def _ok(label: str, detail: str = ''):
    print(f'  {_GREEN}PASS{_RESET}  {label}' + (f'  ({detail})' if detail else ''))


def _warn(label: str, detail: str = ''):
    print(f'  {_YELLOW}WARN{_RESET}  {label}' + (f'  ({detail})' if detail else ''))


def _fail(label: str, detail: str = ''):
    print(f'  {_RED}FAIL{_RESET}  {label}' + (f'  → {detail}' if detail else ''))


# ════════════════════════════════════════════════════════════════════════════
# Individual checks
# ════════════════════════════════════════════════════════════════════════════

def check_python_version() -> bool:
    major, minor = sys.version_info[:2]
    label = f'Python version ≥ 3.11  (found {major}.{minor})'
    if (major, minor) >= (3, 11):
        _ok(label)
        return True
    _fail(label, 'Upgrade to Python 3.11+')
    return False


def check_base_deps() -> bool:
    required = ['requests']
    all_ok = True
    for pkg in required:
        try:
            importlib.import_module(pkg)
            _ok(f'Base dependency: {pkg}')
        except ImportError:
            _fail(f'Base dependency: {pkg}', 'Run: pip install -r requirements.txt')
            all_ok = False
    return all_ok


def check_optional_group(group: str, packages: list[str]) -> bool:
    available = []
    missing = []
    for pkg in packages:
        try:
            importlib.import_module(pkg)
            available.append(pkg)
        except ImportError:
            missing.append(pkg)

    if missing and available:
        _warn(
            f'Optional [{group}]: {len(missing)}/{len(packages)} packages missing',
            f'Missing: {", ".join(missing)}',
        )
        return False
    elif missing:
        _warn(
            f'Optional [{group}] not installed',
            f'Run: pip install -r requirements-{group}.txt',
        )
        return False
    else:
        _ok(f'Optional [{group}] fully installed', ', '.join(available))
        return True


def check_required_files() -> bool:
    required = [
        'requirements.txt',
        'pyproject.toml',
        'src/aura_cli.py',
        'src/aura_helper.py',
        'src/colored_logger.py',
        'src/scanners/base_scanner.py',
        'src/ai_agents/scan_agent.py',
        'src/ai_agents/remediation_advisor.py',
        'src/mcp/server.py',
    ]
    all_ok = True
    for rel in required:
        path = _REPO_ROOT / rel
        if path.exists():
            _ok(f'File exists: {rel}')
        else:
            _fail(f'File missing: {rel}')
            all_ok = False
    return all_ok


def check_optional_files() -> None:
    optional = [
        ('requirements-ai.txt',   'AI analysis support'),
        ('requirements-mcp.txt',  'MCP server support'),
        ('requirements-web.txt',  'Web dashboard support'),
        ('Dockerfile',            'Gradio UI Docker image'),
        ('Dockerfile.web',        'Web dashboard Docker image'),
        ('Dockerfile.mcp',        'MCP server Docker image'),
        ('docker-compose.yml',    'Multi-service compose'),
        ('.vscode/mcp.json',      'VS Code MCP integration'),
    ]
    for rel, purpose in optional:
        path = _REPO_ROOT / rel
        if path.exists():
            _ok(f'Optional file exists: {rel}', purpose)
        else:
            _warn(f'Optional file missing: {rel}', purpose)


def check_secret_key() -> bool:
    web_env = os.environ.get('WEB_ENV', 'development').lower()
    secret = os.environ.get('SECRET_KEY', '')
    dev_default = 'aura-inspector-dev-key-REPLACE-IN-PRODUCTION'
    label = 'SECRET_KEY security check'

    if web_env == 'production':
        if not secret or secret == dev_default:
            _fail(label, 'Set a strong SECRET_KEY env var before running in production')
            return False
        _ok(label, 'SECRET_KEY is set and non-default in production mode')
    else:
        if not secret or secret == dev_default:
            _warn(label, 'Using development default (acceptable for local dev; change for production)')
        else:
            _ok(label, 'Custom SECRET_KEY set')
    return True


def check_openai_api_key() -> None:
    key = os.environ.get('OPENAI_API_KEY', '')
    label = 'OPENAI_API_KEY'
    if not key:
        _warn(label, 'Not set — AI analysis will use rule-based fallback')
    elif not key.startswith('sk-'):
        _warn(label, 'Set but does not start with "sk-" — verify it is a valid OpenAI key')
    else:
        # Show only the first 7 chars to avoid logging the full secret
        _ok(label, f'Set ({key[:7]}...)')


def check_virtualenv() -> None:
    in_venv = (
        hasattr(sys, 'real_prefix')
        or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    )
    if in_venv:
        _ok('Virtual environment active', sys.prefix)
    else:
        _warn('No virtual environment detected', 'Activate .venv before running')


# ════════════════════════════════════════════════════════════════════════════
# Main
# ════════════════════════════════════════════════════════════════════════════

def main() -> int:
    print(f'\n{_BOLD}{_CYAN}aura-inspector — environment validation{_RESET}')
    if _STRICT:
        print(f'  {_YELLOW}[strict mode: warnings count as failures]{_RESET}')
    print()

    required_failures = 0
    optional_warnings = 0

    # ── Required checks ──────────────────────────────────────────────────────
    print(f'{_BOLD}Required checks{_RESET}')
    if not check_python_version():
        required_failures += 1
    if not check_base_deps():
        required_failures += 1
    if not check_required_files():
        required_failures += 1
    if not check_secret_key():
        required_failures += 1
    print()

    # ── Optional dependency groups ───────────────────────────────────────────
    print(f'{_BOLD}Optional dependency groups{_RESET}')
    groups = {
        'ai':  ['openai', 'tenacity'],
        'mcp': ['fastmcp', 'structlog'],
        'web': ['fastapi', 'uvicorn', 'sqlalchemy', 'jinja2', 'passlib', 'jose'],
    }
    for group, pkgs in groups.items():
        if not check_optional_group(group, pkgs):
            optional_warnings += 1
    print()

    # ── Optional files ───────────────────────────────────────────────────────
    print(f'{_BOLD}Optional files{_RESET}')
    check_optional_files()
    print()

    # ── Environment variables ─────────────────────────────────────────────────
    print(f'{_BOLD}Environment variables{_RESET}')
    check_virtualenv()
    check_openai_api_key()
    print()

    # ── Summary ──────────────────────────────────────────────────────────────
    print(f'{_BOLD}Summary{_RESET}')
    if required_failures:
        print(f'  {_RED}{_BOLD}{required_failures} required check(s) FAILED — fix before running.{_RESET}')
    else:
        print(f'  {_GREEN}{_BOLD}All required checks passed.{_RESET}')

    if optional_warnings:
        msg = f'  {_YELLOW}{optional_warnings} optional warning(s) — install extra deps for full functionality.{_RESET}'
        print(msg)

    if _STRICT and optional_warnings:
        return 1
    return 0 if required_failures == 0 else 1


if __name__ == '__main__':
    sys.exit(main())

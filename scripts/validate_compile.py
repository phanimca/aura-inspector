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
validate_compile.py
===================
Syntax-check every Python file under src/ and tests/ using py_compile.
Exits with code 0 when all files are clean; exits with code 1 on any error.

Usage
-----
    python scripts/validate_compile.py              # check src/ and tests/
    python scripts/validate_compile.py src/mcp/     # check a specific subtree
"""

import os
import py_compile
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_DIRS = [_REPO_ROOT / 'src', _REPO_ROOT / 'tests']

_GREEN = '\033[92m'
_RED   = '\033[91m'
_CYAN  = '\033[96m'
_RESET = '\033[0m'
_BOLD  = '\033[1m'


def _check_file(path: Path) -> bool:
    """Return True if the file compiles cleanly."""
    try:
        py_compile.compile(str(path), doraise=True)
        print(f'  {_GREEN}OK{_RESET}  {path.relative_to(_REPO_ROOT)}')
        return True
    except py_compile.PyCompileError as exc:
        print(f'  {_RED}FAIL{_RESET} {path.relative_to(_REPO_ROOT)}')
        print(f'       {_RED}{exc}{_RESET}')
        return False


def main(targets: list[str] | None = None) -> int:
    if targets:
        dirs = [Path(t).resolve() for t in targets]
    else:
        dirs = _DEFAULT_DIRS

    py_files: list[Path] = []
    for d in dirs:
        if d.is_file() and d.suffix == '.py':
            py_files.append(d)
        elif d.is_dir():
            py_files.extend(sorted(d.rglob('*.py')))
        else:
            print(f'{_RED}WARNING: {d} does not exist — skipping{_RESET}', file=sys.stderr)

    if not py_files:
        print(f'{_RED}No .py files found to check.{_RESET}')
        return 1

    print(f'\n{_BOLD}{_CYAN}aura-inspector — compile validation{_RESET}')
    print(f'Checking {len(py_files)} file(s)...\n')

    passed = 0
    failed = 0
    for f in py_files:
        if _check_file(f):
            passed += 1
        else:
            failed += 1

    print()
    print(f'{_BOLD}Results:{_RESET} {_GREEN}{passed} passed{_RESET}', end='')
    if failed:
        print(f', {_RED}{failed} failed{_RESET}')
        return 1
    else:
        print()
        print(f'{_GREEN}{_BOLD}All files compile cleanly.{_RESET}')
        return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:] or None))

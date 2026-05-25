"""
Vercel ASGI entry-point for the Aura Inspector web application.

Vercel routes all requests to this file via vercel.json.
The FastAPI `app` object is imported and exposed for the ASGI runtime.
"""

import os
import sys

# Make src/ importable (api/ sits one level below the repo root)
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SRC_DIR = os.path.join(_REPO_ROOT, "src")
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from web.main import app  # noqa: E402 — sys.path must be set first

# Vercel's Python runtime looks for `app` (ASGI callable) at module level.
__all__ = ["app"]

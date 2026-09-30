"""
Shared pytest configuration for the TrustGuard backend test suite.

Ensures:
  - `backend/` is importable regardless of the directory pytest is invoked from
  - required settings (JWT_SECRET) are present so `get_settings()` does not fail
    when the working directory is not `backend/` (so `backend/.env` is not found)
"""

from __future__ import annotations

import os
import sys

# Make `backend/` importable (config, services, engines, ...) no matter the cwd.
_BACKEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _BACKEND_DIR not in sys.path:
    sys.path.insert(0, _BACKEND_DIR)

# Provide a test JWT secret (>= 32 chars) if the environment / .env does not set one.
os.environ.setdefault("JWT_SECRET", "test-secret-key-for-unit-tests-only-000000")
os.environ.setdefault("ENVIRONMENT", "development")

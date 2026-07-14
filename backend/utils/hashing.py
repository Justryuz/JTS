"""TrustGuard v2.0 — Hashing utilities."""

from __future__ import annotations

import hashlib


def sha256_hash(value: str) -> str:
    """Return SHA-256 hex digest of value."""
    return hashlib.sha256(value.encode()).hexdigest()

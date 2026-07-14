"""TrustGuard v2.0 — Domain Verification Utilities."""

from __future__ import annotations

import httpx


def build_verification_instructions(domain: str, token: str) -> str:
    return (
        f"Simpan token ini di https://{domain}/.well-known/trustguard.txt\n"
        f"Kandungan fail mesti sama dengan token berikut:\n{token}"
    )


def verify_domain_file(target_url: str, token: str) -> bool:
    """Return True if the domain hosts the expected verification token."""
    try:
        response = httpx.get(target_url, timeout=15, follow_redirects=True)
        return response.status_code == 200 and response.text.strip() == token.strip()
    except Exception:
        return False

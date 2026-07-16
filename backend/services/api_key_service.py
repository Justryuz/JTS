"""
TrustGuard v2.0 — API Key Service
Business logic for API key generation, verification, and revocation.
Standards: Clean Architecture, Part 3 §31
"""

from __future__ import annotations

import secrets
from datetime import datetime, timezone

from config.constants import ErrorCode
from repositories.api_key_repo import ApiKeyRepository
from utils.domain_verify import build_verification_instructions, verify_domain_file
from utils.hashing import sha256_hash


class ApiKeyError(Exception):
    def __init__(self, code: str, title: str, description: str, recommendation: str = "") -> None:
        self.code = code
        self.title = title
        self.description = description
        self.recommendation = recommendation
        super().__init__(title)


class ApiKeyService:
    def __init__(self, repo: ApiKeyRepository) -> None:
        self._repo = repo

    def generate(self, user_id: str, domain: str) -> dict:
        plain_key = f"aisec_live_{secrets.token_hex(24)}"
        key_hash = sha256_hash(plain_key)
        verification_token = secrets.token_urlsafe(16)

        api_key = self._repo.create(
            user_id=user_id,
            key_hash=key_hash,
            domain=domain,
            verification_token=verification_token,
        )
        return {
            "api_key": plain_key,
            "key_id": api_key.id,
            "allowed_domain": domain,
            "verification_token": verification_token,
            "verification_instructions": build_verification_instructions(domain, verification_token),
            "warning": "Copy this key now. It will NOT be shown again.",
        }

    def verify_domain(self, key_id: str, user_id: str, target_url: str | None, repo_url: str | None, branch: str) -> dict:
        api_key = self._repo.get_active_by_id(key_id, user_id)
        if not api_key:
            raise ApiKeyError(ErrorCode.API_KEY_NOT_FOUND, "API Key Not Found", "API key not found.")
        if api_key.is_verified:
            raise ApiKeyError(ErrorCode.DOMAIN_ALREADY_VERIFIED, "Domain Already Verified", "This domain has already been verified.")

        domain = api_key.allowed_domain
        url = (target_url or f"https://{domain}").rstrip("/")
        verification_url = url + "/.well-known/trustguard.txt"

        if not verify_domain_file(verification_url, api_key.verification_token or ""):
            raise ApiKeyError(
                ErrorCode.DOMAIN_VERIFICATION_FAILED,
                "Domain Verification Failed",
                "trustguard.txt file not found or token mismatch.",
                "Ensure the file is accessible and contains the correct token.",
            )

        self._repo.mark_verified(api_key, datetime.now(timezone.utc))

        # Trigger auto-scan
        from ingest.url_ingest import scan_live_url
        result = {"verified_domain": domain, "target_url": url}
        result["live_scan"] = scan_live_url(url)

        if repo_url:
            from ingest.github_ingest import scan_github_repo
            result["repo_scan"] = scan_github_repo(repo_url, branch)

        return result

    def revoke(self, key_id: str, user_id: str) -> None:
        api_key = self._repo.get_by_id(key_id, user_id)
        if not api_key:
            raise ApiKeyError(ErrorCode.API_KEY_NOT_FOUND, "API Key Not Found", "API key not found.")
        self._repo.revoke(api_key)

    def validate_for_request(self, raw_key: str, origin_domain: str):
        """Validate API key + domain binding. Returns ApiKey record."""
        key_hash = sha256_hash(raw_key)
        api_key = self._repo.get_by_hash(key_hash)
        if not api_key:
            raise ApiKeyError(ErrorCode.INVALID_API_KEY, "Invalid API Key", "API key tidak sah atau tidak aktif.")
        if api_key.allowed_domain != origin_domain.lower().strip():
            raise ApiKeyError(ErrorCode.DOMAIN_NOT_AUTHORIZED, "Domain Not Authorized", "Domain tidak dibenarkan untuk API key ini.")
        return api_key

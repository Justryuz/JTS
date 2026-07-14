"""
TrustGuard v2.0 — API Key Repository
All database access for ApiKey model.
Standards: Part 3 §36, Repository Pattern
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from models.api_key import ApiKey
from utils.hashing import sha256_hash


class ApiKeyRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    def get_by_hash(self, key_hash: str) -> ApiKey | None:
        return (
            self._db.query(ApiKey)
            .filter(ApiKey.api_key_hash == key_hash, ApiKey.is_active.is_(True))
            .first()
        )

    def get_by_id(self, key_id: str, user_id: str) -> ApiKey | None:
        return (
            self._db.query(ApiKey)
            .filter(ApiKey.id == key_id, ApiKey.user_id == user_id)
            .first()
        )

    def get_active_by_id(self, key_id: str, user_id: str) -> ApiKey | None:
        return (
            self._db.query(ApiKey)
            .filter(ApiKey.id == key_id, ApiKey.user_id == user_id, ApiKey.is_active.is_(True))
            .first()
        )

    def list_by_user(self, user_id: str) -> list[ApiKey]:
        return self._db.query(ApiKey).filter(ApiKey.user_id == user_id).all()

    def create(self, user_id: str, key_hash: str, domain: str, verification_token: str) -> ApiKey:
        api_key = ApiKey(
            user_id=user_id,
            api_key_hash=key_hash,
            allowed_domain=domain,
            verification_token=verification_token,
            verification_method="http_file",
        )
        self._db.add(api_key)
        self._db.commit()
        self._db.refresh(api_key)
        return api_key

    def revoke(self, api_key: ApiKey) -> None:
        api_key.is_active = False
        self._db.commit()

    def mark_verified(self, api_key: ApiKey, verified_at) -> None:
        api_key.is_verified = True
        api_key.verified_at = verified_at
        self._db.commit()

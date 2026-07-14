"""
TrustGuard v2.0 — API Key Model
Domain-bound API keys with verification support.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class ApiKey(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    __tablename__ = "api_keys"

    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    api_key_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    allowed_domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    verification_token: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_method: Mapped[str] = mapped_column(String(50), default="http_file", nullable=False)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

"""
TrustGuard v2.0 — Log Models
PromptLog: every shield request
AuditLog: immutable audit trail (cannot be deleted)
ScanJob: background scan job tracking
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Float, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class PromptLog(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Records every prompt scan request through the shield gateway."""
    __tablename__ = "prompt_logs"

    api_key_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    source_domain: Mapped[str] = mapped_column(String(253), nullable=False, index=True)
    input_text: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    attack_type: Mapped[str] = mapped_column(String(50), default="NONE", nullable=False)
    engine_used: Mapped[str] = mapped_column(String(20), default="hybrid", nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    latency_ms: Mapped[int] = mapped_column(default=0, nullable=False)
    request_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    source_page: Mapped[str | None] = mapped_column(String(500), nullable=True)


class AuditLog(Base, UUIDPrimaryKeyMixin):
    """Immutable audit trail. Never deleted. Append-only."""
    __tablename__ = "audit_logs"

    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, index=True)
    request_id: Mapped[str] = mapped_column(String(36), nullable=False)
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)
    api_key_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    detail: Mapped[str | None] = mapped_column(Text, nullable=True)


class ScanJob(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """Tracks background scan jobs (repo/zip/url)."""
    __tablename__ = "scan_jobs"

    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False)
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="PENDING", nullable=False, index=True)
    result_json: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# Backward compatibility alias — v1 used SecurityLog
SecurityLog = PromptLog

"""
TrustGuard v2.0 — Common Response Schemas
StandardResponse and ErrorResponse used by ALL endpoints.
Standards: Part 3 §26, §18
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field, model_validator


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ErrorDetail(BaseModel):
    code: str = Field(description="TrustGuard error code, e.g. TG-1001")
    title: str
    description: str
    recommendation: str
    reference: str = ""


class StandardResponse(BaseModel):
    """Wrapper for all successful API responses."""
    success: bool = True
    message: str
    data: Any = None
    meta: dict[str, Any] | None = None
    request_id: str = ""
    timestamp: str = Field(default_factory=_now_iso)


class ErrorResponse(BaseModel):
    """Wrapper for all error API responses."""
    success: bool = False
    error: ErrorDetail
    request_id: str = ""
    timestamp: str = Field(default_factory=_now_iso)


class PaginationMeta(BaseModel):
    total: int
    page: int
    per_page: int
    total_pages: int

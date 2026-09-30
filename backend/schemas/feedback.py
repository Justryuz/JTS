"""
TrustGuard v2.0 — Feedback Schemas (Loop Engineering)
Input validation for analyst labels.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class FeedbackRequest(BaseModel):
    label: Literal["TP", "FP", "FN", "TN"]
    note: str | None = Field(default=None, max_length=1000)

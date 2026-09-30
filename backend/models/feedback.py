"""
TrustGuard v2.0 — Loop Engineering Models

PromptFeedback : analyst labels on a PromptLog (TP/FP/FN/TN) — the feedback signal.
RuleSuggestion : candidate detection rule mined from labelled attacks, pending
                 human approval before it can affect the live engine.

Design: human-in-the-loop, fully auditable, no auto-apply.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from models.base import Base, TimestampMixin, UUIDPrimaryKeyMixin


class PromptFeedback(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """An analyst's label on a single PromptLog entry.

    label:
      TP = true positive  (correctly blocked attack)
      FP = false positive (safe prompt wrongly blocked)
      FN = false negative (attack that was allowed / missed)
      TN = true negative  (correctly allowed safe prompt)
    """
    __tablename__ = "prompt_feedback"

    prompt_log_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    label: Mapped[str] = mapped_column(String(4), nullable=False, index=True)
    labeled_by: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    note: Mapped[str | None] = mapped_column(Text, nullable=True)


class RuleSuggestion(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A candidate rule mined from labelled attacks, awaiting human review.

    status: PENDING | APPROVED | REJECTED
    source: mined | manual
    """
    __tablename__ = "rule_suggestions"

    pattern: Mapped[str] = mapped_column(Text, nullable=False)
    rule_name: Mapped[str] = mapped_column(String(120), nullable=False)
    attack_type: Mapped[str] = mapped_column(String(50), default="PROMPT_INJECTION", nullable=False)
    sample_prompt: Mapped[str] = mapped_column(Text, nullable=False)
    source: Mapped[str] = mapped_column(String(20), default="mined", nullable=False)
    occurrence_count: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="PENDING", nullable=False, index=True)
    reviewed_by: Mapped[str | None] = mapped_column(String(36), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

"""
TrustGuard v2.0 — Feedback Repository (Loop Engineering)
Persists PromptFeedback labels and RuleSuggestion candidates.
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from models.feedback import PromptFeedback, RuleSuggestion


class FeedbackRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    # ── PromptFeedback ────────────────────────────────────────────────────

    def upsert_feedback(self, prompt_log_id: str, label: str, labeled_by: str, note: str | None = None) -> PromptFeedback:
        """One label per (log, analyst). Update if it already exists."""
        existing = (
            self._db.query(PromptFeedback)
            .filter(PromptFeedback.prompt_log_id == prompt_log_id, PromptFeedback.labeled_by == labeled_by)
            .first()
        )
        if existing:
            existing.label = label
            existing.note = note
            self._db.commit()
            return existing
        fb = PromptFeedback(prompt_log_id=prompt_log_id, label=label, labeled_by=labeled_by, note=note)
        self._db.add(fb)
        self._db.commit()
        return fb

    def attack_labeled_prompt_ids(self) -> list[str]:
        """PromptLog ids labelled as an attack (TP or FN)."""
        rows = (
            self._db.query(PromptFeedback.prompt_log_id)
            .filter(PromptFeedback.label.in_(("TP", "FN")))
            .all()
        )
        return [r[0] for r in rows]

    def feedback_by_log_ids(self, log_ids: list[str]) -> dict[str, str]:
        """Map prompt_log_id -> latest label, for the given logs."""
        if not log_ids:
            return {}
        rows = (
            self._db.query(PromptFeedback)
            .filter(PromptFeedback.prompt_log_id.in_(log_ids))
            .order_by(PromptFeedback.created_at.asc())
            .all()
        )
        return {r.prompt_log_id: r.label for r in rows}

    # ── RuleSuggestion ────────────────────────────────────────────────────

    def existing_suggestion_patterns(self) -> set[str]:
        rows = self._db.query(RuleSuggestion.pattern).all()
        return {r[0] for r in rows}

    def add_suggestion(self, pattern: str, rule_name: str, attack_type: str, sample_prompt: str, occurrence_count: int, source: str = "mined") -> RuleSuggestion:
        s = RuleSuggestion(
            pattern=pattern, rule_name=rule_name, attack_type=attack_type,
            sample_prompt=sample_prompt, occurrence_count=occurrence_count, source=source, status="PENDING",
        )
        self._db.add(s)
        self._db.commit()
        return s

    def list_suggestions(self, status: str | None = None) -> list[RuleSuggestion]:
        q = self._db.query(RuleSuggestion)
        if status:
            q = q.filter(RuleSuggestion.status == status)
        return q.order_by(RuleSuggestion.occurrence_count.desc(), RuleSuggestion.created_at.desc()).all()

    def get_suggestion(self, suggestion_id: str) -> RuleSuggestion | None:
        return self._db.query(RuleSuggestion).filter(RuleSuggestion.id == suggestion_id).first()

    def set_suggestion_status(self, suggestion: RuleSuggestion, status: str, reviewed_by: str) -> RuleSuggestion:
        suggestion.status = status
        suggestion.reviewed_by = reviewed_by
        suggestion.reviewed_at = datetime.now(timezone.utc)
        self._db.commit()
        return suggestion

    def approved_patterns(self) -> list[tuple[str, str]]:
        """Return (pattern, rule_name) for all APPROVED suggestions."""
        rows = (
            self._db.query(RuleSuggestion)
            .filter(RuleSuggestion.status == "APPROVED")
            .all()
        )
        return [(r.pattern, r.rule_name) for r in rows]

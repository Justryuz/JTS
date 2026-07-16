"""
TrustGuard v2.0 — Log Repository
Handles PromptLog, AuditLog, and ScanJob persistence.
AuditLog is append-only — no delete method exposed.
Standards: Part 3 §32, §36
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy.orm import Session

from models.log import AuditLog, PromptLog, ScanJob


class LogRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    # ── PromptLog ─────────────────────────────────────────────────────────

    def create_prompt_log(
        self,
        api_key_id: str,
        source_domain: str,
        input_text: str,
        status: str,
        attack_type: str,
        engine_used: str,
        confidence: float,
        latency_ms: int,
        request_id: str,
        source_page: str | None = None,
    ) -> PromptLog:
        log = PromptLog(
            api_key_id=api_key_id,
            source_domain=source_domain,
            input_text=input_text[:500],
            status=status,
            attack_type=attack_type,
            engine_used=engine_used,
            confidence=confidence,
            latency_ms=latency_ms,
            request_id=request_id,
            source_page=source_page,
        )
        self._db.add(log)
        self._db.commit()
        return log

    def list_by_key_ids(self, key_ids: list[str], limit: int = 100) -> list[PromptLog]:
        return (
            self._db.query(PromptLog)
            .filter(PromptLog.api_key_id.in_(key_ids))
            .order_by(PromptLog.created_at.desc())
            .limit(limit)
            .all()
        )

    def count_by_key_ids(self, key_ids: list[str]) -> tuple[int, int]:
        """Return (total, blocked) counts."""
        total = self._db.query(PromptLog).filter(PromptLog.api_key_id.in_(key_ids)).count()
        blocked = (
            self._db.query(PromptLog)
            .filter(PromptLog.api_key_id.in_(key_ids), PromptLog.status == "BLOCKED")
            .count()
        )
        return total, blocked

    # ── AuditLog (append-only) ────────────────────────────────────────────

    def append_audit(
        self,
        request_id: str,
        action: str,
        status: str,
        user_id: str | None = None,
        api_key_id: str | None = None,
        ip_address: str | None = None,
        resource: str | None = None,
        detail: str | None = None,
    ) -> None:
        log = AuditLog(
            timestamp=datetime.now(timezone.utc),
            request_id=request_id,
            user_id=user_id,
            api_key_id=api_key_id,
            ip_address=ip_address,
            action=action,
            resource=resource,
            status=status,
            detail=detail,
        )
        self._db.add(log)
        self._db.commit()

    # ── ScanJob ───────────────────────────────────────────────────────────

    def create_scan_job(self, user_id: str, scan_type: str, target: str) -> ScanJob:
        job = ScanJob(user_id=user_id, scan_type=scan_type, target=target, status="PENDING")
        self._db.add(job)
        self._db.commit()
        self._db.refresh(job)
        return job

    def get_scan_job(self, job_id: str, user_id: str) -> ScanJob | None:
        return (
            self._db.query(ScanJob)
            .filter(ScanJob.id == job_id, ScanJob.user_id == user_id)
            .first()
        )

    def update_scan_job(
        self,
        job: ScanJob,
        status: str,
        result_json: str | None = None,
        error_message: str | None = None,
    ) -> None:
        job.status = status
        if result_json is not None:
            job.result_json = result_json
        if error_message is not None:
            job.error_message = error_message
        if status in ("COMPLETED", "FAILED"):
            job.completed_at = datetime.now(timezone.utc)
        self._db.commit()

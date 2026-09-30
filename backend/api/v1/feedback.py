"""
TrustGuard v2.0 — Loop Engineering API (Feedback → Mining → Review → Deploy)

Human-in-the-loop adaptive detection:
  POST /portal/logs/{id}/feedback          label a log (TP/FP/FN/TN)
  POST /portal/feedback/mine               mine rule candidates from labelled attacks
  GET  /portal/feedback/suggestions        list rule suggestions
  POST /portal/feedback/suggestions/{id}/approve   approve → apply to live rule engine
  POST /portal/feedback/suggestions/{id}/reject    reject

RBAC: only `admin` and `security_analyst` may label / mine / review.
Every action is written to the append-only AuditLog. No auto-apply.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from config.constants import ErrorCode
from database.session import get_db
from models.log import PromptLog
from repositories.api_key_repo import ApiKeyRepository
from repositories.feedback_repo import FeedbackRepository
from repositories.log_repo import LogRepository
from schemas.feedback import FeedbackRequest
from utils.jwt_utils import get_current_role, get_current_user_id, verify_jwt

router = APIRouter(prefix="/portal", tags=["Loop Engineering"])

_REVIEWER_ROLES = {"admin", "security_analyst"}


def _require_reviewer(role: str) -> None:
    if role not in _REVIEWER_ROLES:
        raise HTTPException(
            status_code=403,
            detail={
                "code": ErrorCode.INSUFFICIENT_PERMISSION, "title": "Insufficient Permission",
                "description": "Only admin or security_analyst may perform loop-engineering actions.",
                "recommendation": "Request an analyst/admin role.", "reference": "",
            },
        )


def _audit(db: Session, request: Request, user_id: str, action: str, resource: str, detail: str) -> None:
    try:
        LogRepository(db).append_audit(
            request_id=getattr(request.state, "request_id", ""),
            action=action, status="SUCCESS", user_id=user_id,
            ip_address=getattr(getattr(request, "client", None), "host", None),
            resource=resource, detail=detail,
        )
    except Exception:
        pass


@router.post("/logs/{log_id}/feedback", summary="Label a security log (analyst feedback)")
def submit_feedback(
    log_id: str,
    body: FeedbackRequest,
    request: Request,
    payload: dict = Depends(verify_jwt),
    db: Session = Depends(get_db),
):
    user_id = payload["sub"]
    _require_reviewer(payload.get("role", "readonly"))

    # Ensure the log belongs to one of the caller's API keys.
    key_ids = [k.id for k in ApiKeyRepository(db).list_by_user(user_id)]
    log = db.query(PromptLog).filter(PromptLog.id == log_id).first()
    if not log or log.api_key_id not in key_ids:
        raise HTTPException(status_code=404, detail={
            "code": "TG-4008", "title": "Log Not Found",
            "description": "Security log not found or not owned by you.",
            "recommendation": "", "reference": ""})

    fb = FeedbackRepository(db).upsert_feedback(log_id, body.label, user_id, body.note)
    _audit(db, request, user_id, "feedback.label", f"prompt_log:{log_id}", f"label={body.label}")
    return {"id": fb.id, "prompt_log_id": log_id, "label": fb.label}


@router.post("/feedback/mine", summary="Mine rule candidates from labelled attacks")
def mine_rules(
    request: Request,
    payload: dict = Depends(verify_jwt),
    db: Session = Depends(get_db),
):
    user_id = payload["sub"]
    _require_reviewer(payload.get("role", "readonly"))

    from engines import rule_engine
    from engines.loop_miner import mine_candidates

    repo = FeedbackRepository(db)
    attack_ids = repo.attack_labeled_prompt_ids()
    if not attack_ids:
        return {"created": 0, "candidates": [], "note": "No prompts labelled as attacks (TP/FN) yet."}

    logs = db.query(PromptLog).filter(PromptLog.id.in_(attack_ids)).all()
    prompts = [l.input_text for l in logs if l.input_text]

    existing = [p for p, _ in rule_engine.PROMPT_INJECTION_RULES] + [p for p, _ in rule_engine.JAILBREAK_RULES]
    known = repo.existing_suggestion_patterns()

    candidates = mine_candidates(prompts, existing_patterns=existing, known_suggested=known)
    created = []
    for c in candidates:
        s = repo.add_suggestion(
            pattern=c["pattern"], rule_name=c["rule_name"], attack_type="PROMPT_INJECTION",
            sample_prompt=c["sample_prompt"], occurrence_count=c["occurrence_count"], source="mined",
        )
        created.append({"id": s.id, "pattern": s.pattern, "rule_name": s.rule_name, "occurrence_count": s.occurrence_count})

    _audit(db, request, user_id, "feedback.mine", "rule_suggestions", f"created={len(created)}")
    return {"created": len(created), "candidates": created}


@router.get("/feedback/suggestions", summary="List rule suggestions")
def list_suggestions(
    request: Request,
    status: str | None = None,
    payload: dict = Depends(verify_jwt),
    db: Session = Depends(get_db),
):
    _require_reviewer(payload.get("role", "readonly"))
    rows = FeedbackRepository(db).list_suggestions(status=status)
    return [
        {
            "id": r.id, "pattern": r.pattern, "rule_name": r.rule_name,
            "attack_type": r.attack_type, "sample_prompt": r.sample_prompt,
            "source": r.source, "occurrence_count": r.occurrence_count,
            "status": r.status, "reviewed_by": r.reviewed_by,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "reviewed_at": r.reviewed_at.isoformat() if r.reviewed_at else None,
        }
        for r in rows
    ]


@router.post("/feedback/suggestions/{suggestion_id}/approve", summary="Approve a rule suggestion (deploy to live engine)")
def approve_suggestion(
    suggestion_id: str,
    request: Request,
    payload: dict = Depends(verify_jwt),
    db: Session = Depends(get_db),
):
    user_id = payload["sub"]
    _require_reviewer(payload.get("role", "readonly"))

    from engines import rule_engine
    from engines.loop_miner import is_safe_pattern

    repo = FeedbackRepository(db)
    s = repo.get_suggestion(suggestion_id)
    if not s:
        raise HTTPException(status_code=404, detail={"code": "TG-4008", "title": "Not Found",
                                                      "description": "Suggestion not found.", "recommendation": "", "reference": ""})
    if s.status != "PENDING":
        raise HTTPException(status_code=409, detail={"code": "TG-4010", "title": "Already Reviewed",
                                                      "description": f"Suggestion already {s.status}.", "recommendation": "", "reference": ""})
    # Defensive re-validation before touching the live engine.
    if not is_safe_pattern(s.pattern):
        raise HTTPException(status_code=422, detail={"code": "TG-4011", "title": "Unsafe Pattern",
                                                      "description": "Rule pattern failed safety validation.", "recommendation": "", "reference": ""})

    repo.set_suggestion_status(s, "APPROVED", user_id)

    # Deploy: append to the LIVE rule engine (idempotent — skip if pattern already present).
    existing = {p for p, _ in rule_engine.PROMPT_INJECTION_RULES}
    if s.pattern not in existing:
        rule_engine.PROMPT_INJECTION_RULES.append((s.pattern, s.rule_name))

    _audit(db, request, user_id, "feedback.approve", f"rule_suggestion:{suggestion_id}", f"rule={s.rule_name}")
    return {"id": s.id, "status": "APPROVED", "rule_name": s.rule_name,
            "note": "Rule is now active in the live engine for this process. Persisted as APPROVED."}


@router.post("/feedback/suggestions/{suggestion_id}/reject", summary="Reject a rule suggestion")
def reject_suggestion(
    suggestion_id: str,
    request: Request,
    payload: dict = Depends(verify_jwt),
    db: Session = Depends(get_db),
):
    user_id = payload["sub"]
    _require_reviewer(payload.get("role", "readonly"))

    repo = FeedbackRepository(db)
    s = repo.get_suggestion(suggestion_id)
    if not s:
        raise HTTPException(status_code=404, detail={"code": "TG-4008", "title": "Not Found",
                                                      "description": "Suggestion not found.", "recommendation": "", "reference": ""})
    if s.status != "PENDING":
        raise HTTPException(status_code=409, detail={"code": "TG-4010", "title": "Already Reviewed",
                                                      "description": f"Suggestion already {s.status}.", "recommendation": "", "reference": ""})

    repo.set_suggestion_status(s, "REJECTED", user_id)
    _audit(db, request, user_id, "feedback.reject", f"rule_suggestion:{suggestion_id}", f"rule={s.rule_name}")
    return {"id": s.id, "status": "REJECTED"}

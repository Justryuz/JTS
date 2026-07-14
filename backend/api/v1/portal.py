"""
TrustGuard v2.0 — Portal API Routes v1
API key management, logs, stats, compliance.
Backward compatible with v1.0.
Standards: Part 3 §26, §31
"""

from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from config.constants import ErrorCode
from database.session import get_db
from repositories.api_key_repo import ApiKeyRepository
from repositories.log_repo import LogRepository
from repositories.user_repo import UserRepository
from schemas.common import StandardResponse
from schemas.scan import GenerateKeyRequest, VerifyDomainRequest
from services.api_key_service import ApiKeyError, ApiKeyService
from utils.jwt_utils import get_current_user_id

router = APIRouter(prefix="/portal", tags=["Portal"])


def _key_service(db: Session = Depends(get_db)) -> ApiKeyService:
    return ApiKeyService(ApiKeyRepository(db))


@router.post("/api-key/generate", status_code=201, summary="Jana API Key baru")
def generate_api_key(
    body: GenerateKeyRequest,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    service: ApiKeyService = Depends(_key_service),
):
    # Return flat format — backward compatible with v1 frontend
    return service.generate(user_id, body.allowed_domain)


@router.get("/api-keys", summary="Senarai kunci API")
def list_api_keys(
    request: Request,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    keys = ApiKeyRepository(db).list_by_user(user_id)
    # Return array directly — backward compatible with v1 frontend
    return [
        {
            "id": k.id,
            "allowed_domain": k.allowed_domain,
            "is_active": k.is_active,
            "is_verified": k.is_verified,
            "verification_method": k.verification_method,
            "created_at": k.created_at.isoformat() if k.created_at else None,
            "verified_at": k.verified_at.isoformat() if k.verified_at else None,
        }
        for k in keys
    ]


@router.get("/api-key/{key_id}", summary="Status API key")
def get_api_key_status(
    key_id: str,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    from utils.domain_verify import build_verification_instructions
    key = ApiKeyRepository(db).get_by_id(key_id, user_id)
    if not key:
        raise HTTPException(status_code=404, detail={"code": ErrorCode.API_KEY_NOT_FOUND,
                                                      "title": "Not Found", "description": "API key tidak dijumpai.",
                                                      "recommendation": "", "reference": ""})
    return StandardResponse(
        message="API key status retrieved",
        data={
            "id": key.id,
            "allowed_domain": key.allowed_domain,
            "is_active": key.is_active,
            "is_verified": key.is_verified,
            "verification_method": key.verification_method,
            "verified_at": key.verified_at.isoformat() if key.verified_at else None,
            "verification_instructions": build_verification_instructions(
                key.allowed_domain, key.verification_token or ""
            ),
        },
        request_id=getattr(request.state, "request_id", ""),
    )


@router.post("/api-key/{key_id}/verify", summary="Verify domain & auto-scan")
def verify_domain(
    key_id: str,
    body: VerifyDomainRequest,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    service: ApiKeyService = Depends(_key_service),
):
    try:
        result = service.verify_domain(
            key_id=key_id,
            user_id=user_id,
            target_url=body.target_url,
            repo_url=body.repo_url,
            branch=body.branch,
        )
        return StandardResponse(
            message="Domain verified and scan completed",
            data=result,
            request_id=getattr(request.state, "request_id", ""),
        )
    except ApiKeyError as e:
        raise HTTPException(status_code=400, detail={"code": e.code, "title": e.title,
                                                      "description": e.description,
                                                      "recommendation": e.recommendation, "reference": ""})


@router.delete("/api-key/{key_id}", summary="Revoke API key")
def revoke_api_key(
    key_id: str,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    service: ApiKeyService = Depends(_key_service),
):
    try:
        service.revoke(key_id, user_id)
        return StandardResponse(
            message="API key revoked",
            request_id=getattr(request.state, "request_id", ""),
        )
    except ApiKeyError as e:
        raise HTTPException(status_code=404, detail={"code": e.code, "title": e.title,
                                                      "description": e.description,
                                                      "recommendation": e.recommendation, "reference": ""})


@router.get("/logs", summary="Log keselamatan")
def get_logs(
    request: Request,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
    limit: int = 100,
):
    key_ids = [k.id for k in ApiKeyRepository(db).list_by_user(user_id)]
    logs = LogRepository(db).list_by_key_ids(key_ids, limit=min(limit, 500))
    # Return array directly — backward compatible with v1 frontend
    return [
        {
            "id": l.id,
            "source_domain": l.source_domain,
            "input_text": l.input_text,
            "status": l.status,
            "attack_type": l.attack_type,
            "engine_used": l.engine_used,
            "confidence": l.confidence,
            "created_at": l.created_at.isoformat() if l.created_at else None,
        }
        for l in logs
    ]


@router.get("/stats", summary="Statistik penggunaan")
def get_stats(
    request: Request,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    key_ids = [k.id for k in ApiKeyRepository(db).list_by_user(user_id)]
    total, blocked = LogRepository(db).count_by_key_ids(key_ids)
    return {"total_requests": total, "total_blocked": blocked, "engine_status": "ACTIVE"}


@router.get("/compliance/{domain}", summary="Skor pematuhan domain")
def get_compliance(
    domain: str,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    key_ids = [k.id for k in ApiKeyRepository(db).list_by_user(user_id)]
    from models.log import PromptLog
    logs = (
        db.query(PromptLog)
        .filter(PromptLog.api_key_id.in_(key_ids), PromptLog.source_domain == domain)
        .all()
    )
    total = len(logs)
    blocked = sum(1 for l in logs if l.status == "BLOCKED")
    threat_rate = (blocked / total * 100) if total > 0 else 0
    base_score = max(0, 100 - (threat_rate * 2))
    grade = "A" if base_score >= 90 else "B" if base_score >= 75 else "C" if base_score >= 60 else "D" if base_score >= 40 else "F"

    return StandardResponse(
        message="Compliance score retrieved",
        data={
            "domain": domain,
            "total_scans": total,
            "blocked": blocked,
            "threat_rate": round(threat_rate, 2),
            "prompt_safety_score": round(base_score, 2),
            "grade": grade,
        },
        request_id=getattr(request.state, "request_id", ""),
    )

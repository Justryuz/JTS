"""
TrustGuard v2.0 — Shield Gateway API Routes v1
Backward compatible with v1.0 /api/v1/shield endpoint.
Standards: Part 3 §26, §33
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from sqlalchemy.orm import Session

from config.constants import ErrorCode
from database.session import get_db
from repositories.api_key_repo import ApiKeyRepository
from repositories.log_repo import LogRepository
from schemas.common import StandardResponse
from schemas.gateway import ShieldRequest
from services.api_key_service import ApiKeyError, ApiKeyService
from services.shield_service import ShieldService

router = APIRouter(tags=["Shield"])
_shield_service = ShieldService()


def _api_key_service(db: Session = Depends(get_db)) -> ApiKeyService:
    return ApiKeyService(ApiKeyRepository(db))


@router.post(
    "/api/v1/shield",
    summary="Shield prompt AI",
    description=(
        "Scan prompt before sending to LLM model. "
        "Detects Prompt Injection, Jailbreak, Encoding Attacks, and OWASP LLM Top 10 threats."
    ),
)
def shield(
    body: ShieldRequest,
    request: Request,
    x_api_key: str = Header(..., alias="X-API-Key"),
    x_origin_domain: str = Header(..., alias="X-Origin-Domain"),
    db: Session = Depends(get_db),
    key_service: ApiKeyService = Depends(_api_key_service),
):
    request_id = getattr(request.state, "request_id", "")
    start = time.time()

    # Validate API key + domain
    try:
        api_key_record = key_service.validate_for_request(x_api_key, x_origin_domain)
    except ApiKeyError as e:
        http_status = 401 if e.code == ErrorCode.INVALID_API_KEY else 403
        raise HTTPException(status_code=http_status, detail={
            "code": e.code, "title": e.title,
            "description": e.description, "recommendation": e.recommendation, "reference": "",
        })

    # Run detection
    result = _shield_service.scan(body.prompt, body.engine_mode.value)

    # Resolve source_page: body field takes priority, fallback to Referer header
    source_page = body.source_page or request.headers.get("referer") or None
    if source_page:
        source_page = source_page[:500]

    # Persist log
    log_repo = LogRepository(db)
    log_repo.create_prompt_log(
        api_key_id=api_key_record.id,
        source_domain=x_origin_domain,
        input_text=body.prompt,
        status=result["status"],
        attack_type=result["attack_type"],
        engine_used=result["engine_used"],
        confidence=result["confidence"],
        latency_ms=result["latency_ms"],
        request_id=request_id,
        source_page=source_page,
    )

    # v1 backward-compatible response format
    if result["status"] == "BLOCKED":
        return {"status": "BLOCKED", "reason": result["attack_type"]}
    return {"status": "ALLOWED"}

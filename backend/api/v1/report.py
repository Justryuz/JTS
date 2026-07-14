"""
TrustGuard v2.0 — PDF Report API Routes v1
Backward compatible with v1.0 /portal/report/pdf endpoint.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy.orm import Session

from database.session import get_db
from repositories.api_key_repo import ApiKeyRepository
from repositories.log_repo import LogRepository
from schemas.scan import CodeScanRequest
from utils.jwt_utils import get_current_user_id

router = APIRouter(prefix="/portal", tags=["Compliance"])


@router.post("/report/pdf", summary="Jana laporan audit PDF")
def generate_pdf_report(
    body: CodeScanRequest,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    from scanners.cve_scanner import scan_code
    from compliance.scorer import calculate
    from reports.pdf_generator import generate

    scan_result = scan_code(body.code, body.filename)
    compliance = calculate(scan_result)

    key_ids = [k.id for k in ApiKeyRepository(db).list_by_user(user_id)]
    total, blocked = LogRepository(db).count_by_key_ids(key_ids)

    try:
        pdf_bytes = generate(
            domain=body.filename,
            scan_result=scan_result,
            compliance_score=compliance,
            prompt_stats={"total_requests": total, "total_blocked": blocked},
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={"Content-Disposition": f"attachment; filename=audit-report-{body.filename}.pdf"},
        )
    except RuntimeError as e:
        raise HTTPException(status_code=501, detail=str(e))

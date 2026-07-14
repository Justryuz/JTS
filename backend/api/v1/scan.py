"""
TrustGuard v2.0 — Scan API Routes v1
Code, repo, URL, ZIP scan endpoints.
Backward compatible with v1.0.
Standards: Part 3 §26, §28
"""

from __future__ import annotations

import json

from fastapi import APIRouter, BackgroundTasks, Depends, File, Header, HTTPException, Request, UploadFile
from sqlalchemy.orm import Session

from config.constants import ErrorCode
from database.session import get_db
from repositories.api_key_repo import ApiKeyRepository
from repositories.log_repo import LogRepository
from schemas.common import StandardResponse
from schemas.scan import CodeScanRequest, RepoScanRequest, UrlScanRequest
from services.api_key_service import ApiKeyError, ApiKeyService
from utils.jwt_utils import get_current_user_id

router = APIRouter(tags=["Scan"])


def _key_service(db: Session = Depends(get_db)) -> ApiKeyService:
    return ApiKeyService(ApiKeyRepository(db))


def _validate_key(
    x_api_key: str,
    x_origin_domain: str,
    service: ApiKeyService,
):
    try:
        return service.validate_for_request(x_api_key, x_origin_domain)
    except ApiKeyError as e:
        http_status = 401 if e.code == ErrorCode.INVALID_API_KEY else 403
        raise HTTPException(status_code=http_status, detail={
            "code": e.code, "title": e.title,
            "description": e.description, "recommendation": e.recommendation, "reference": "",
        })


@router.post("/api/v1/scan/code", summary="Imbas kod sumber")
def scan_code(
    body: CodeScanRequest,
    request: Request,
    x_api_key: str = Header(..., alias="X-API-Key"),
    x_origin_domain: str = Header(..., alias="X-Origin-Domain"),
    db: Session = Depends(get_db),
    key_service: ApiKeyService = Depends(_key_service),
):
    _validate_key(x_api_key, x_origin_domain, key_service)

    from scanners.cve_scanner import scan_code as _scan
    from compliance.scorer import calculate

    scan_result = _scan(body.code, body.filename)
    compliance = calculate(scan_result)

    return {
        "domain": x_origin_domain,
        "filename": body.filename,
        "total_issues": scan_result.total_issues,
        "severity_breakdown": {
            "critical": scan_result.critical,
            "high": scan_result.high,
            "medium": scan_result.medium,
            "low": scan_result.low,
        },
        "vulnerabilities": [
            {
                "cwe_id": v.cwe_id, "cve_ref": v.cve_ref, "title": v.title,
                "severity": v.severity, "description": v.description,
                "line_hint": v.line_hint, "owasp_ref": v.owasp_ref,
            }
            for v in scan_result.vulnerabilities
        ],
        "compliance_flags": scan_result.compliance_flags,
        "compliance_score": {
            "overall": compliance.overall,
            "grade": compliance.grade,
            "breakdown": compliance.breakdown,
        },
    }


@router.post("/api/v1/scan/repo", summary="Imbas repo GitHub")
def scan_repo(
    body: RepoScanRequest,
    request: Request,
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(..., alias="X-API-Key"),
    x_origin_domain: str = Header(..., alias="X-Origin-Domain"),
    db: Session = Depends(get_db),
    key_service: ApiKeyService = Depends(_key_service),
):
    api_key = _validate_key(x_api_key, x_origin_domain, key_service)
    request_id = getattr(request.state, "request_id", "")

    # Create background job
    log_repo = LogRepository(db)
    job = log_repo.create_scan_job(
        user_id=api_key.user_id,
        scan_type="github_repo",
        target=body.repo_url,
    )

    background_tasks.add_task(_run_repo_scan, job.id, body.repo_url, body.branch, db)

    return StandardResponse(
        message="Scan job queued. Use job_id to check status.",
        data={"job_id": job.id, "status": "PENDING"},
        meta={"poll_url": f"/api/v1/scan/status/{job.id}"},
        request_id=request_id,
    )


@router.post("/api/v1/scan/url", summary="Imbas URL langsung")
def scan_url(
    body: UrlScanRequest,
    request: Request,
    x_api_key: str = Header(..., alias="X-API-Key"),
    x_origin_domain: str = Header(..., alias="X-Origin-Domain"),
    db: Session = Depends(get_db),
    key_service: ApiKeyService = Depends(_key_service),
):
    _validate_key(x_api_key, x_origin_domain, key_service)
    from ingest.url_ingest import scan_live_url
    result = scan_live_url(body.url)
    return result


@router.post("/api/v1/scan/upload", summary="Imbas ZIP upload")
async def scan_upload(
    request: Request,
    background_tasks: BackgroundTasks,
    x_api_key: str = Header(..., alias="X-API-Key"),
    x_origin_domain: str = Header(..., alias="X-Origin-Domain"),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    key_service: ApiKeyService = Depends(_key_service),
):
    api_key = _validate_key(x_api_key, x_origin_domain, key_service)

    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(status_code=422, detail={"code": ErrorCode.ZIP_INVALID,
                                                      "title": "Invalid File", "description": "Hanya fail .zip dibenarkan.",
                                                      "recommendation": "Muat naik fail ZIP yang sah.", "reference": ""})

    file_bytes = await file.read()
    log_repo = LogRepository(db)
    job = log_repo.create_scan_job(
        user_id=api_key.user_id,
        scan_type="zip_upload",
        target=file.filename or "upload.zip",
    )

    background_tasks.add_task(_run_zip_scan, job.id, file_bytes, db)

    return StandardResponse(
        message="ZIP scan job queued.",
        data={"job_id": job.id, "status": "PENDING"},
        meta={"poll_url": f"/api/v1/scan/status/{job.id}"},
        request_id=getattr(request.state, "request_id", ""),
    )


@router.get("/api/v1/scan/status/{job_id}", summary="Semak status scan job")
def get_scan_status(
    job_id: str,
    request: Request,
    user_id: str = Depends(get_current_user_id),
    db: Session = Depends(get_db),
):
    job = LogRepository(db).get_scan_job(job_id, user_id)
    if not job:
        raise HTTPException(status_code=404, detail={"code": "TG-4008", "title": "Job Not Found",
                                                      "description": "Scan job tidak dijumpai.", "recommendation": "", "reference": ""})
    data = {"job_id": job.id, "status": job.status, "scan_type": job.scan_type, "target": job.target}
    if job.status == "COMPLETED" and job.result_json:
        data["result"] = json.loads(job.result_json)
    if job.status == "FAILED":
        data["error"] = job.error_message
    return StandardResponse(
        message=f"Scan job {job.status.lower()}",
        data=data,
        request_id=getattr(request.state, "request_id", ""),
    )


# ── Background task helpers ───────────────────────────────────────────────────

def _run_repo_scan(job_id: str, repo_url: str, branch: str, db: Session) -> None:
    from database.session import SessionLocal
    from ingest.github_ingest import scan_github_repo
    _db = SessionLocal()
    try:
        log_repo = LogRepository(_db)
        job = _db.query(__import__("models.log", fromlist=["ScanJob"]).ScanJob).filter_by(id=job_id).first()
        if not job:
            return
        log_repo.update_scan_job(job, "RUNNING")
        result = scan_github_repo(repo_url, branch)
        if "error" in result:
            log_repo.update_scan_job(job, "FAILED", error_message=result["error"])
        else:
            log_repo.update_scan_job(job, "COMPLETED", result_json=json.dumps(result))
    except Exception as e:
        if job:
            log_repo.update_scan_job(job, "FAILED", error_message=str(e))
    finally:
        _db.close()


def _run_zip_scan(job_id: str, file_bytes: bytes, db: Session) -> None:
    from database.session import SessionLocal
    from ingest.zip_ingest import scan_zip_upload
    _db = SessionLocal()
    try:
        log_repo = LogRepository(_db)
        job = _db.query(__import__("models.log", fromlist=["ScanJob"]).ScanJob).filter_by(id=job_id).first()
        if not job:
            return
        log_repo.update_scan_job(job, "RUNNING")
        result = scan_zip_upload(file_bytes)
        if "error" in result:
            log_repo.update_scan_job(job, "FAILED", error_message=result["error"])
        else:
            log_repo.update_scan_job(job, "COMPLETED", result_json=json.dumps(result))
    except Exception as e:
        if job:
            log_repo.update_scan_job(job, "FAILED", error_message=str(e))
    finally:
        _db.close()

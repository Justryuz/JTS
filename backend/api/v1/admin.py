"""
TrustGuard v2.0 — Admin API Routes v1
Engine update endpoint. Requires JWT.
Standards: Part 3 §26
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from utils.jwt_utils import get_current_user_id

router = APIRouter(prefix="/admin", tags=["Admin"])


class UpdateRequest(BaseModel):
    update_rules: bool = True
    update_models: bool = True


@router.post("/update", summary="Update detection engine")
def update_engine(
    body: UpdateRequest,
    request: Request,
    user_id: str = Depends(get_current_user_id),
):
    from engine.updater import run_update
    result = run_update(
        update_rules_flag=body.update_rules,
        update_models_flag=body.update_models,
    )
    return {
        "success": result.success,
        "rules_updated": result.rules_updated,
        "models_refreshed": result.models_refreshed,
        "errors": result.errors,
        "timestamp": result.timestamp,
        "note": "Models will re-download on next scan request.",
    }

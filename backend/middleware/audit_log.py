"""
TrustGuard v2.0 — Structured Audit Log Middleware
Logs every request/response as JSON to stdout and file.
Standards: Part 3 §17, §32
"""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from config.settings import get_settings

logger = logging.getLogger("trustguard.audit")


class AuditLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        start = time.time()
        request_id = getattr(request.state, "request_id", "unknown")

        response = await call_next(request)

        latency_ms = int((time.time() - start) * 1000)

        # Skip health check from audit log to reduce noise
        if request.url.path == "/health":
            return response

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "status_code": response.status_code,
            "latency_ms": latency_ms,
            "ip_address": request.client.host if request.client else None,
            "user_agent": request.headers.get("user-agent", "")[:100],
        }

        logger.info(json.dumps(log_entry))
        return response

"""
TrustGuard v2.0 — Rate Limiting Middleware
Per-IP rate limiting using in-memory sliding window.
Standards: OWASP API Security API4:2023, Part 2 §23
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from config.settings import get_settings

# {ip: deque of timestamps}
_ip_windows: dict[str, deque] = defaultdict(deque)

# Rate limits per path prefix
_LIMITS: dict[str, int] = {}


def _get_limit(path: str, settings) -> int:
    if path.startswith("/portal/auth"):
        return settings.auth_rate_limit_per_minute
    if path.startswith("/api/v1/scan") or path.startswith("/api/v2/scan"):
        return settings.scan_rate_limit_per_minute
    if path.startswith("/api/v"):
        return settings.shield_rate_limit_per_minute
    return 200  # portal / admin endpoints


class RateLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        ip = request.client.host if request.client else "unknown"
        path = request.url.path
        limit = _get_limit(path, settings)

        now = time.time()
        window = _ip_windows[ip]

        # Remove timestamps older than 60 seconds
        while window and window[0] < now - 60:
            window.popleft()

        if len(window) >= limit:
            return JSONResponse(
                status_code=429,
                content={
                    "success": False,
                    "error": {
                        "code": "TG-6001",
                        "title": "Rate Limit Exceeded",
                        "description": f"Terlalu banyak permintaan dari IP {ip}.",
                        "recommendation": "Tunggu sebentar sebelum cuba semula.",
                        "reference": "OWASP API4:2023",
                    },
                },
                headers={"Retry-After": "60"},
            )

        window.append(now)
        return await call_next(request)

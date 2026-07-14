"""
TrustGuard v2.0 — TTL Cache
Lightweight in-memory cache using cachetools. No Redis required for v2.0.
Redis can be swapped in as an upgrade without changing the interface.
Standards: Part 2 §21
"""

from __future__ import annotations

from typing import Any

from cachetools import TTLCache

from config.settings import get_settings

_settings = get_settings()

# Cache instances — module-level singletons
_rules_cache: TTLCache = TTLCache(maxsize=10, ttl=_settings.cache_rules_ttl)
_compliance_cache: TTLCache = TTLCache(maxsize=1000, ttl=_settings.cache_compliance_ttl)
_shield_cache: TTLCache = TTLCache(maxsize=5000, ttl=_settings.cache_shield_ttl)


def get_shield_cache(key: str) -> Any | None:
    return _shield_cache.get(key)


def set_shield_cache(key: str, value: Any) -> None:
    _shield_cache[key] = value


def get_compliance_cache(key: str) -> Any | None:
    return _compliance_cache.get(key)


def set_compliance_cache(key: str, value: Any) -> None:
    _compliance_cache[key] = value


def invalidate_shield_cache() -> None:
    _shield_cache.clear()


def invalidate_compliance_cache() -> None:
    _compliance_cache.clear()

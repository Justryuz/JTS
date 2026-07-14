"""
TrustGuard v2.0 — Shield Service
Orchestrates prompt scanning through the hybrid detection engine.
Includes cache layer and structured result building.
Standards: Part 3 §33, Clean Architecture
"""

from __future__ import annotations

import hashlib
import time

from config.constants import (
    AttackType, ErrorCode, MITRE_ATLAS_REFERENCES, OWASP_REFERENCES, ScanStatus,
)
from config.settings import get_settings
from utils.cache import get_shield_cache, set_shield_cache


class ShieldService:
    def __init__(self) -> None:
        self._settings = get_settings()

    def scan(self, prompt: str, engine_mode: str = "hybrid") -> dict:
        """
        Scan a prompt through the detection engine.
        Returns a structured result dict — no FastAPI dependency.
        """
        start = time.time()

        # Cache lookup — identical prompts return cached result
        cache_key = hashlib.sha256(f"{prompt}:{engine_mode}".encode()).hexdigest()
        cached = get_shield_cache(cache_key)
        if cached:
            cached["cached"] = True
            return cached

        # Import engines here to keep service layer decoupled from engine internals
        from engines.hybrid_engine import scan as hybrid_scan
        from engines.rule_engine import scan as rule_scan
        from engines import ml_engine

        mode = engine_mode.strip().lower()

        if mode == "rule":
            rule = rule_scan(prompt)
            status = rule.status
            attack_type = rule.attack_type
            confidence = rule.confidence
            engine_used = "rule"
            matched = rule.matched_rule
        elif mode == "ml":
            result = hybrid_scan(prompt, use_ml=True)
            status = result.status
            attack_type = result.attack_type
            confidence = result.confidence
            engine_used = result.engine_used
            matched = result.matched_rule
        else:
            result = hybrid_scan(prompt, use_ml=ml_engine.is_available())
            status = result.status
            attack_type = result.attack_type
            confidence = result.confidence
            engine_used = result.engine_used
            matched = result.matched_rule

        attack_enum = AttackType(attack_type) if attack_type in AttackType._value2member_map_ else AttackType.NONE

        output = {
            "status": status,
            "attack_type": attack_type,
            "confidence": confidence,
            "engine_used": engine_used,
            "matched_rule": matched,
            "owasp_ref": OWASP_REFERENCES.get(attack_enum, ""),
            "mitre_ref": MITRE_ATLAS_REFERENCES.get(attack_enum, ""),
            "latency_ms": int((time.time() - start) * 1000),
            "cached": False,
        }

        if status == ScanStatus.BLOCKED:
            output["reason"] = attack_type

        set_shield_cache(cache_key, output)
        return output

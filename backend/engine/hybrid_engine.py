"""
Pilihan 3: Hybrid Detection Engine
Rule-based scan dulu (laju) → jika lepas, ML scan (dalam)
Pematuhan: OWASP LLM Top 10, NACSA, CWE-20, JPDP
"""

from dataclasses import dataclass

from engine import ml_engine, rule_engine


@dataclass
class HybridResult:
    status: str         # ALLOWED | BLOCKED
    attack_type: str    # NONE | PROMPT_INJECTION | JAILBREAK | TOXIC
    confidence: float   # 0.0 - 1.0
    engine_used: str    # rule | ml | hybrid
    matched_rule: str   # rule name atau model name
    rule_result: dict
    ml_result: dict


def scan(text: str, use_ml: bool = True) -> HybridResult:
    """
    Hybrid scan:
    1. Rule-based scan dulu — laju, tiada overhead
    2. Jika ALLOWED dan ML tersedia, hantar ke ML untuk pengesahan lebih dalam
    3. Jika mana-mana BLOCKED, terus return BLOCKED
    """
    # Step 1: Rule-based
    rule = rule_engine.scan(text)
    rule_dict = {
        "status": rule.status,
        "attack_type": rule.attack_type,
        "confidence": rule.confidence,
        "matched_rule": rule.matched_rule,
    }

    if rule.status == "BLOCKED":
        return HybridResult(
            status="BLOCKED",
            attack_type=rule.attack_type,
            confidence=rule.confidence,
            engine_used="rule",
            matched_rule=rule.matched_rule,
            rule_result=rule_dict,
            ml_result={},
        )

    # Step 2: ML scan (jika tersedia dan diminta)
    ml_dict = {}
    if use_ml and ml_engine.is_available():
        ml = ml_engine.scan(text)
        ml_dict = {
            "status": ml.status,
            "attack_type": ml.attack_type,
            "confidence": ml.confidence,
            "model_used": ml.model_used,
        }

        if ml.status == "BLOCKED":
            return HybridResult(
                status="BLOCKED",
                attack_type=ml.attack_type,
                confidence=ml.confidence,
                engine_used="ml",
                matched_rule=ml.model_used,
                rule_result=rule_dict,
                ml_result=ml_dict,
            )

    return HybridResult(
        status="ALLOWED",
        attack_type="NONE",
        confidence=1.0,
        engine_used="hybrid" if ml_dict else "rule",
        matched_rule="none",
        rule_result=rule_dict,
        ml_result=ml_dict,
    )

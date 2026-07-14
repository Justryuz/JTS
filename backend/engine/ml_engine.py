"""
Pilihan 2: ML Detection Engine (HuggingFace Transformers)
Model: deepset/deberta-v3-base-injection (offline selepas download pertama)
Pematuhan: OWASP LLM01, CWE-20, NACSA AI Security Framework
"""

import logging
from dataclasses import dataclass
from functools import lru_cache

logger = logging.getLogger(__name__)


@dataclass
class MLResult:
    status: str        # ALLOWED | BLOCKED
    attack_type: str   # NONE | PROMPT_INJECTION | JAILBREAK | TOXIC
    confidence: float  # 0.0 - 1.0
    model_used: str


# Threshold — tukar ikut keperluan
INJECTION_THRESHOLD = 0.75
TOXIC_THRESHOLD = 0.80


@lru_cache(maxsize=1)
def _load_injection_model():
    """Lazy load — model didownload sekali sahaja (~500MB)"""
    try:
        from transformers import pipeline
        return pipeline(
            "text-classification",
            model="deepset/deberta-v3-base-injection",
            truncation=True,
            max_length=512,
        )
    except Exception as e:
        logger.warning(f"Injection model gagal diload: {e}")
        return None


@lru_cache(maxsize=1)
def _load_toxic_model():
    """Model untuk kesan kandungan toksik/berbahaya"""
    try:
        from transformers import pipeline
        return pipeline(
            "text-classification",
            model="martin-ha/toxic-comment-model",
            truncation=True,
            max_length=512,
        )
    except Exception as e:
        logger.warning(f"Toxic model gagal diload: {e}")
        return None


def scan(text: str) -> MLResult:
    # --- Injection Model ---
    injection_pipe = _load_injection_model()
    if injection_pipe:
        try:
            result = injection_pipe(text)[0]
            label = result["label"].upper()
            score = result["score"]

            if label == "INJECTION" and score >= INJECTION_THRESHOLD:
                return MLResult(
                    status="BLOCKED",
                    attack_type="PROMPT_INJECTION",
                    confidence=round(score, 4),
                    model_used="deepset/deberta-v3-base-injection",
                )
        except Exception as e:
            logger.error(f"Injection scan error: {e}")

    # --- Toxic Model ---
    toxic_pipe = _load_toxic_model()
    if toxic_pipe:
        try:
            result = toxic_pipe(text)[0]
            label = result["label"].upper()
            score = result["score"]

            if label == "TOXIC" and score >= TOXIC_THRESHOLD:
                return MLResult(
                    status="BLOCKED",
                    attack_type="JAILBREAK",
                    confidence=round(score, 4),
                    model_used="martin-ha/toxic-comment-model",
                )
        except Exception as e:
            logger.error(f"Toxic scan error: {e}")

    return MLResult(
        status="ALLOWED",
        attack_type="NONE",
        confidence=1.0,
        model_used="none",
    )


def is_available() -> bool:
    """Semak sama ada model ML boleh digunakan"""
    try:
        import transformers  # noqa
        return True
    except ImportError:
        return False

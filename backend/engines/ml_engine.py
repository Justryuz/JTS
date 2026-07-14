"""
TrustGuard v2.0 — ML Detection Engine (HuggingFace Transformers)
Models:
  - deepset/deberta-v3-base-injection          (Prompt Injection)
  - protectai/deberta-v3-base-prompt-injection-v2 (Prompt Injection v2 — more accurate)
  - martin-ha/toxic-comment-model              (Toxic / Jailbreak)
  - unitary/toxic-bert                         (Toxic — broader coverage)
  - mrm8488/codebert-base-finetuned-detect-insecure-code (Insecure Code)
Compliance: OWASP LLM01, CWE-20, NACSA AI Security Framework
"""

import logging
from dataclasses import dataclass
from functools import lru_cache

logger = logging.getLogger(__name__)


@dataclass
class MLResult:
    status: str        # ALLOWED | BLOCKED
    attack_type: str   # NONE | PROMPT_INJECTION | JAILBREAK | TOXIC | INSECURE_CODE
    confidence: float  # 0.0 - 1.0
    model_used: str


INJECTION_THRESHOLD = 0.75
TOXIC_THRESHOLD = 0.80
CODE_THRESHOLD = 0.75


@lru_cache(maxsize=1)
def _load_injection_model():
    """deepset — original injection model"""
    try:
        from transformers import pipeline
        return pipeline(
            "text-classification",
            model="deepset/deberta-v3-base-injection",
            truncation=True,
            max_length=512,
        )
    except Exception as e:
        logger.warning(f"deepset injection model failed to load: {e}")
        return None


@lru_cache(maxsize=1)
def _load_injection_v2_model():
    """protectai — more accurate injection v2 model"""
    try:
        from transformers import pipeline
        return pipeline(
            "text-classification",
            model="protectai/deberta-v3-base-prompt-injection-v2",
            truncation=True,
            max_length=512,
        )
    except Exception as e:
        logger.warning(f"protectai injection v2 model failed to load: {e}")
        return None


@lru_cache(maxsize=1)
def _load_toxic_model():
    """martin-ha — toxic/jailbreak model"""
    try:
        from transformers import pipeline
        return pipeline(
            "text-classification",
            model="martin-ha/toxic-comment-model",
            truncation=True,
            max_length=512,
        )
    except Exception as e:
        logger.warning(f"martin-ha toxic model failed to load: {e}")
        return None


@lru_cache(maxsize=1)
def _load_toxic_bert_model():
    """unitary/toxic-bert — broader toxic content coverage"""
    try:
        from transformers import pipeline
        return pipeline(
            "text-classification",
            model="unitary/toxic-bert",
            truncation=True,
            max_length=512,
        )
    except Exception as e:
        logger.warning(f"toxic-bert model failed to load: {e}")
        return None


@lru_cache(maxsize=1)
def _load_code_model():
    """mrm8488/codebert — insecure code detection"""
    try:
        from transformers import pipeline
        return pipeline(
            "text-classification",
            model="mrm8488/codebert-base-finetuned-detect-insecure-code",
            truncation=True,
            max_length=512,
        )
    except Exception as e:
        logger.warning(f"codebert insecure code model failed to load: {e}")
        return None


def scan(text: str) -> MLResult:
    # --- Injection Model (deepset) ---
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
            logger.error(f"deepset injection scan error: {e}")

    # --- Injection Model v2 (protectai) ---
    injection_v2_pipe = _load_injection_v2_model()
    if injection_v2_pipe:
        try:
            result = injection_v2_pipe(text)[0]
            label = result["label"].upper()
            score = result["score"]
            if label in ("INJECTION", "PROMPT_INJECTION") and score >= INJECTION_THRESHOLD:
                return MLResult(
                    status="BLOCKED",
                    attack_type="PROMPT_INJECTION",
                    confidence=round(score, 4),
                    model_used="protectai/deberta-v3-base-prompt-injection-v2",
                )
        except Exception as e:
            logger.error(f"protectai injection v2 scan error: {e}")

    # --- Toxic Model (martin-ha) ---
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
            logger.error(f"martin-ha toxic scan error: {e}")

    # --- Toxic BERT (unitary) ---
    toxic_bert_pipe = _load_toxic_bert_model()
    if toxic_bert_pipe:
        try:
            result = toxic_bert_pipe(text)[0]
            label = result["label"].upper()
            score = result["score"]
            if label == "TOXIC" and score >= TOXIC_THRESHOLD:
                return MLResult(
                    status="BLOCKED",
                    attack_type="TOXIC",
                    confidence=round(score, 4),
                    model_used="unitary/toxic-bert",
                )
        except Exception as e:
            logger.error(f"toxic-bert scan error: {e}")

    return MLResult(
        status="ALLOWED",
        attack_type="NONE",
        confidence=1.0,
        model_used="none",
    )


def scan_code(text: str) -> MLResult:
    """Scan source code for insecure patterns using CodeBERT."""
    code_pipe = _load_code_model()
    if code_pipe:
        try:
            result = code_pipe(text)[0]
            label = result["label"].upper()
            score = result["score"]
            if label in ("INSECURE", "1") and score >= CODE_THRESHOLD:
                return MLResult(
                    status="BLOCKED",
                    attack_type="INSECURE_CODE",
                    confidence=round(score, 4),
                    model_used="mrm8488/codebert-base-finetuned-detect-insecure-code",
                )
        except Exception as e:
            logger.error(f"codebert scan error: {e}")

    return MLResult(
        status="ALLOWED",
        attack_type="NONE",
        confidence=1.0,
        model_used="none",
    )


def is_available() -> bool:
    try:
        import transformers  # noqa
        return True
    except ImportError:
        return False

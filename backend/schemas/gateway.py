"""
TrustGuard v2.0 — Gateway & Shield Schemas
Input validation for prompt scanning and response firewall.
Standards: Part 3 §28, §33, §34
"""

from __future__ import annotations

from pydantic import BaseModel, Field, field_validator

from config.constants import EngineMode


class ShieldRequest(BaseModel):
    prompt: str = Field(min_length=1, max_length=10_000)
    engine_mode: EngineMode = EngineMode.HYBRID
    source_page: str | None = Field(default=None, max_length=500)

    @field_validator("prompt")
    @classmethod
    def sanitize_prompt(cls, v: str) -> str:
        # Strip null bytes — prevent null byte injection
        return v.replace("\x00", "").strip()


class ShieldResponse(BaseModel):
    status: str          # ALLOWED | BLOCKED
    reason: str | None = None
    attack_type: str = "NONE"
    confidence: float = 0.0
    engine_used: str = "hybrid"
    owasp_ref: str = ""
    mitre_ref: str = ""


class ResponseFirewallRequest(BaseModel):
    """Scan LLM response for secrets, PII, and prompt leakage."""
    response_text: str = Field(min_length=1, max_length=100_000)
    policy: str = "mask"  # mask | block


class ResponseFirewallResult(BaseModel):
    status: str           # CLEAN | MASKED | BLOCKED
    original_length: int
    findings: list[dict]
    masked_response: str | None = None

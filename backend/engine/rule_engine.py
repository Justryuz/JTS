"""
Pilihan 1: Rule-Based Detection Engine
Mengesan Prompt Injection & Jailbreak menggunakan regex/keyword patterns
Pematuhan: OWASP LLM Top 10, NACSA, CWE-20 (Improper Input Validation)
"""

import re
from dataclasses import dataclass


@dataclass
class RuleResult:
    status: str        # ALLOWED | BLOCKED
    attack_type: str   # NONE | PROMPT_INJECTION | JAILBREAK
    confidence: float  # 0.0 - 1.0
    matched_rule: str  # rule yang dicetuskan


# OWASP LLM01 - Prompt Injection Patterns
PROMPT_INJECTION_RULES = [
    (r"ignore\s+(all\s+)?previous\s+instructions?", "ignore_previous_instructions"),
    (r"disregard\s+(all\s+)?previous\s+instructions?", "disregard_instructions"),
    (r"forget\s+(your\s+)?(system\s+prompt|instructions?|context)", "forget_system_prompt"),
    (r"override\s+(system|instructions?|prompt)", "override_system"),
    (r"bypass\s+(safety|filter|restriction|guideline|content\s+policy)", "bypass_safety"),
    (r"reveal\s+(your\s+)?(system\s+prompt|instructions?|prompt)", "reveal_prompt"),
    (r"print\s+(your\s+)?(system\s+prompt|instructions?)", "print_prompt"),
    (r"what\s+(are|were)\s+your\s+(original\s+)?instructions?", "extract_instructions"),
    (r"show\s+me\s+your\s+(system\s+)?prompt", "show_prompt"),
    (r"repeat\s+(everything|all)\s+(above|before|prior)", "repeat_context"),
    (r"output\s+(your\s+)?(initial|original|system)\s+(prompt|instructions?)", "output_prompt"),
    (r"translate\s+(your\s+)?(system\s+)?prompt\s+to", "translate_prompt"),
    (r"(start|begin)\s+prompt\s+with\s+[\"']", "prompt_prefix_injection"),
    (r"###\s*(instruction|system|prompt)", "markdown_injection"),
    (r"<\s*(system|instruction|prompt)\s*>", "xml_tag_injection"),
]

# OWASP LLM02 - Jailbreak Patterns
JAILBREAK_RULES = [
    (r"you\s+are\s+now\s+in\s+DAN\s+mode", "dan_mode"),
    (r"do\s+anything\s+now", "do_anything_now"),
    (r"DAN\s+mode\s+(enabled|activated|on)", "dan_mode_enabled"),
    (r"act\s+as\s+(a\s+)?(developer|AI|assistant|human)\s+with\s+no\s+restrictions?", "act_no_restrictions"),
    (r"you\s+have\s+no\s+(restrictions?|limitations?|rules?|guidelines?|filters?)", "no_restrictions"),
    (r"pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(evil|unrestricted|unfiltered|uncensored)", "pretend_evil"),
    (r"system\s+override", "system_override"),
    (r"\bjailbreak\b", "jailbreak_keyword"),
    (r"developer\s+mode\s+(enabled|on|activated)", "developer_mode"),
    (r"enable\s+developer\s+mode", "enable_dev_mode"),
    (r"you\s+are\s+now\s+(free|unrestricted|unfiltered|uncensored)", "now_unrestricted"),
    (r"remove\s+(all\s+)?(your\s+)?(restrictions?|limitations?|filters?|safety)", "remove_restrictions"),
    (r"(sudo|root)\s+(mode|access|override)", "sudo_mode"),
    (r"grandma\s+(trick|exploit|hack|loophole)", "grandma_trick"),
    (r"hypothetically\s+speaking.{0,30}(how\s+to|explain|describe)\s+(hack|exploit|attack|bypass)", "hypothetical_attack"),
    (r"for\s+(educational|research|fictional)\s+purposes?.{0,30}(hack|exploit|malware|weapon)", "educational_bypass"),
    (r"(roleplay|role\s+play).{0,50}(no\s+rules?|unrestricted|evil|villain)", "roleplay_bypass"),
    (r"you\s+are\s+(now\s+)?(evil|malicious|hacker|villain|dark\s+AI)", "evil_persona"),
    (r"(token\s+limit|context\s+window).{0,30}(ignore|bypass|override)", "context_manipulation"),
]


def scan(text: str) -> RuleResult:
    normalized = text.lower().strip()

    for pattern, rule_name in PROMPT_INJECTION_RULES:
        if re.search(pattern, normalized, re.IGNORECASE):
            return RuleResult(
                status="BLOCKED",
                attack_type="PROMPT_INJECTION",
                confidence=0.95,
                matched_rule=rule_name,
            )

    for pattern, rule_name in JAILBREAK_RULES:
        if re.search(pattern, normalized, re.IGNORECASE):
            return RuleResult(
                status="BLOCKED",
                attack_type="JAILBREAK",
                confidence=0.95,
                matched_rule=rule_name,
            )

    return RuleResult(status="ALLOWED", attack_type="NONE", confidence=1.0, matched_rule="none")

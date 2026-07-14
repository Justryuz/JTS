"""
Engine Updater — Auto-update rule patterns & ML models
Sumber rules: OWASP LLM Top 10 (community patterns)
"""

import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from functools import lru_cache

logger = logging.getLogger(__name__)


@dataclass
class UpdateResult:
    success: bool
    rules_updated: bool = False
    models_refreshed: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# Latest OWASP LLM01/LLM02 patterns — dikemaskini secara manual mengikut OWASP releases
LATEST_INJECTION_RULES = [
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
    # New patterns — LLM01 v2.0
    (r"(act|behave)\s+as\s+if\s+(you\s+have\s+no|without)\s+(restrictions?|guidelines?)", "act_no_guidelines"),
    (r"your\s+(new|updated|real)\s+(instructions?|system\s+prompt)\s+(is|are)", "new_instructions_injection"),
    (r"(inject|insert)\s+(malicious\s+)?(prompt|instruction|command)", "direct_injection"),
    (r"<\s*\|?\s*(im_start|im_end|endoftext)\s*\|?\s*>", "special_token_injection"),
    (r"(assistant|system)\s*:\s*you\s+(must|should|will)\s+now", "role_prefix_injection"),
]

LATEST_JAILBREAK_RULES = [
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
    # New patterns — LLM02 v2.0
    (r"(STAN|DUDE|KEVIN|AIM|ANTI-DAN)\s+mode", "alternative_dan_modes"),
    (r"opposite\s+(mode|day).{0,20}(answer|respond|reply)", "opposite_mode"),
    (r"(evil\s+confidant|shadow\s+self|alter\s+ego).{0,30}(respond|answer|tell)", "alter_ego_jailbreak"),
    (r"(many\s+shot|multi\s+shot)\s+(jailbreak|bypass|prompt)", "many_shot_jailbreak"),
    (r"(crescendo|incremental).{0,30}(bypass|jailbreak|escalat)", "crescendo_attack"),
]

MODELS_TO_UPDATE = [
    "deepset/deberta-v3-base-injection",
    "martin-ha/toxic-comment-model",
]


def update_rules() -> bool:
    """Kemaskini rule patterns dalam rule_engine.py dengan patterns terkini."""
    try:
        import engine.rule_engine as rule_engine
        rule_engine.PROMPT_INJECTION_RULES = LATEST_INJECTION_RULES
        rule_engine.JAILBREAK_RULES = LATEST_JAILBREAK_RULES
        logger.info(f"Rules updated: {len(LATEST_INJECTION_RULES)} injection + {len(LATEST_JAILBREAK_RULES)} jailbreak patterns")
        return True
    except Exception as e:
        logger.error(f"Rule update failed: {e}")
        return False


def refresh_models() -> tuple[list, list]:
    """Clear HuggingFace cache dan invalidate lru_cache supaya model re-download."""
    refreshed = []
    errors = []

    try:
        import huggingface_hub
        cache_dir = huggingface_hub.constants.HF_HUB_CACHE
    except Exception:
        import os
        cache_dir = os.path.expanduser("~/.cache/huggingface/hub")

    for model_id in MODELS_TO_UPDATE:
        try:
            # Clear cache folder untuk model ini
            folder_name = "models--" + model_id.replace("/", "--")
            import os
            model_cache_path = os.path.join(cache_dir, folder_name)
            if os.path.exists(model_cache_path):
                shutil.rmtree(model_cache_path)
                logger.info(f"Cache cleared: {model_id}")

            refreshed.append(model_id)
        except Exception as e:
            errors.append(f"{model_id}: {str(e)}")
            logger.error(f"Model cache clear failed for {model_id}: {e}")

    # Invalidate lru_cache — model akan re-download semasa scan seterusnya
    try:
        from engine import ml_engine
        ml_engine._load_injection_model.cache_clear()
        ml_engine._load_toxic_model.cache_clear()
        logger.info("ML model cache invalidated — will re-download on next scan")
    except Exception as e:
        errors.append(f"lru_cache clear: {str(e)}")

    return refreshed, errors


def run_update(update_rules_flag: bool = True, update_models_flag: bool = True) -> UpdateResult:
    result = UpdateResult(success=False)

    if update_rules_flag:
        result.rules_updated = update_rules()

    if update_models_flag:
        refreshed, errors = refresh_models()
        result.models_refreshed = refreshed
        result.errors.extend(errors)

    result.success = result.rules_updated or len(result.models_refreshed) > 0
    return result

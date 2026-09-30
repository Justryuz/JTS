"""
TrustGuard v2.0 — Loop Engineering Miner

Extracts conservative, human-reviewable rule candidates from prompts that
analysts have labelled as attacks (TP / FN). Never auto-applies anything —
it only proposes RuleSuggestion rows for human approval.

Safety:
  - Candidate regexes are ESCAPED literal phrases (no analyst-controlled regex
    metacharacters), so generated patterns cannot cause ReDoS or match broadly.
  - A phrase must recur across at least MIN_OCCURRENCE distinct prompts before
    it is suggested, to avoid noise / single-sample poisoning.
  - Phrases already covered by existing rules are skipped.
"""

from __future__ import annotations

import re
from collections import Counter

# Minimum distinct labelled prompts a phrase must appear in to be suggested.
MIN_OCCURRENCE = 3
# N-gram window (words) used to build candidate phrases.
NGRAM_MIN = 3
NGRAM_MAX = 6
# Ignore very common english words when they stand alone (kept inside n-grams).
_STOPWORD_ONLY = {"the", "a", "an", "to", "of", "and", "or", "is", "are", "you", "your", "me", "my", "i"}
_WORD_RE = re.compile(r"[a-z0-9']+")
# Reject candidate phrases that are purely stopwords / too short overall.
_MIN_PHRASE_CHARS = 10
_MAX_PATTERN_LEN = 200


def _normalize(text: str) -> str:
    return text.lower().strip()


def _tokens(text: str) -> list[str]:
    return _WORD_RE.findall(_normalize(text))


def _ngrams(tokens: list[str], lo: int, hi: int) -> list[str]:
    out = []
    n = len(tokens)
    for size in range(lo, hi + 1):
        for i in range(0, n - size + 1):
            out.append(" ".join(tokens[i:i + size]))
    return out


def _is_meaningful(phrase: str) -> bool:
    if len(phrase) < _MIN_PHRASE_CHARS:
        return False
    words = phrase.split()
    # at least one non-stopword token
    return any(w not in _STOPWORD_ONLY for w in words)


def phrase_to_pattern(phrase: str) -> str:
    """Turn a literal phrase into a SAFE regex: escape everything, allow flexible
    whitespace between words. No user-controlled metacharacters survive."""
    words = phrase.split()
    escaped = [re.escape(w) for w in words]
    return r"\s+".join(escaped)


def is_safe_pattern(pattern: str) -> bool:
    """Validate a regex is compilable and bounded (defence against ReDoS / bad input)."""
    if not pattern or len(pattern) > _MAX_PATTERN_LEN:
        return False
    # Reject nested/unbounded quantifiers that enable catastrophic backtracking.
    if re.search(r"(\(.*[+*].*\)[+*])|(\.\*){2,}|(\.\+){2,}", pattern):
        return False
    try:
        re.compile(pattern)
        return True
    except re.error:
        return False


def _covered_by_existing(phrase: str, existing_patterns: list[str]) -> bool:
    """Skip phrases already caught by an existing rule."""
    for pat in existing_patterns:
        try:
            if re.search(pat, phrase, re.IGNORECASE):
                return True
        except re.error:
            continue
    return False


def mine_candidates(
    attack_prompts: list[str],
    existing_patterns: list[str],
    known_suggested: set[str] | None = None,
    min_occurrence: int = MIN_OCCURRENCE,
) -> list[dict]:
    """Return a list of candidate rule dicts:
        { pattern, rule_name, sample_prompt, occurrence_count }

    attack_prompts   : prompts labelled TP or FN by analysts
    existing_patterns : regex strings already active in the rule engine
    known_suggested  : patterns already stored as suggestions (avoid duplicates)
    """
    known_suggested = known_suggested or set()
    phrase_counter: Counter[str] = Counter()
    phrase_sample: dict[str, str] = {}

    for prompt in attack_prompts:
        toks = _tokens(prompt)
        seen_in_prompt = set()
        for ph in _ngrams(toks, NGRAM_MIN, NGRAM_MAX):
            if ph in seen_in_prompt:
                continue
            seen_in_prompt.add(ph)
            if not _is_meaningful(ph):
                continue
            phrase_counter[ph] += 1
            phrase_sample.setdefault(ph, prompt)

    candidates: list[dict] = []
    used_patterns: set[str] = set()

    # Prefer longer, higher-frequency phrases first.
    for phrase, count in sorted(phrase_counter.items(), key=lambda kv: (-kv[1], -len(kv[0]))):
        if count < min_occurrence:
            continue
        if _covered_by_existing(phrase, existing_patterns):
            continue
        pattern = phrase_to_pattern(phrase)
        if not is_safe_pattern(pattern):
            continue
        if pattern in used_patterns or pattern in known_suggested:
            continue
        # Skip a phrase that is a sub-phrase of one we already accepted.
        if any(phrase in c["_phrase"] for c in candidates):
            continue
        used_patterns.add(pattern)
        rule_name = "mined_" + re.sub(r"[^a-z0-9]+", "_", phrase)[:40].strip("_")
        candidates.append({
            "pattern": pattern,
            "rule_name": rule_name,
            "sample_prompt": phrase_sample[phrase][:500],
            "occurrence_count": count,
            "_phrase": phrase,
        })

    for c in candidates:
        c.pop("_phrase", None)
    return candidates

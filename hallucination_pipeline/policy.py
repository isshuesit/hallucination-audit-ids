"""
Two-tier hallucination taxonomy and the strict / lenient policies (DECISIONS D3, D15-D19).

  Tier 1 - unsupported specifics: factual, reasoning, certainty, outdated
  Tier 2 - external knowledge:    port, protocol, encryption, baseline, unit
  strict  policy: Tier 1 and Tier 2 are hallucinations
  lenient policy: only Tier 1 is

Design: the rule engine (detection/patterns.py, detection/rules.py) is NOT edited, so
RULES_VERSION and both rule fingerprints stay as they are. Everything added on top lives
here and is fingerprinted by policy_stamp():
  - RULE_TIERS: tier and subtype per rule, keyed by the rule's description string;
  - SUBTYPES: the exact subtype vocabulary (docs/SUBTYPES.md is generated from it);
  - HEDGE_LEXICON (D17): every rule hit carries `hedged`; it never changes a tier;
  - the duration check (D19): Flow Duration is in microseconds; a sentence that states a
    duration contradicting it is Tier 1 factual `unit_wrong` under both policies;
  - stated durations (D20): with the Tier 2 layer on, a duration stated with an explicit unit
    is a Tier 2 `unit` hit when the rule engine produced no `unit` hit for that sentence;
  - catch-all subtypes (D21): other_fabrication / other_knowledge, for the judge and the
    annotators only (never produced by rules), always with a free-text note.

Detection runs the rules once and keeps every hit with its tier (D18: all subtypes are
kept, not only the deciding one); both policies are derived from that single pass.
"""

from __future__ import annotations

import hashlib
import json
import re
import string
from dataclasses import asdict, dataclass

from . import config
from .detection import (SOFT_CERTAINTY_RE, check_external_knowledge, rule_based_detect_explanation,
                        rule_classify_sentence, split_sentences)
from .detection.patterns import ALL_RULE_PATTERNS, EXTERNAL_KNOWLEDGE_PATTERNS, TYPE_PRIORITY

POLICY_VERSION = "1.2.0"
TIER1, TIER2 = 1, 2
POLICY_TIERS: dict[str, frozenset[int]] = {"strict": frozenset({TIER1, TIER2}), "lenient": frozenset({TIER1})}


# ── subtype vocabulary ────────────────────────────────────────────────────

@dataclass(frozen=True)
class Subtype:
    tier: int
    type: str
    meaning: str
    label: bool = True       # False: rule-internal marker, never a hallucination label
    catch_all: bool = False  # D21: judge/annotators only, needs a note, counted separately


SUBTYPES: dict[str, Subtype] = {
    # Tier 1 - factual
    "cve": Subtype(TIER1, "factual", "a CVE identifier"),
    "tool": Subtype(TIER1, "factual", "a named exploit, malware family or attack/security tool"),
    "version": Subtype(TIER1, "factual", "a specific software version"),
    "ip_address": Subtype(TIER1, "factual", "an IP address"),
    "port_not_in_evidence": Subtype(TIER1, "factual", "a port number that is absent from the evidence (D16)"),
    "protocol_without_port": Subtype(TIER1, "factual",
                                     "a protocol/service named whose well-known port is absent from the evidence (D16)"),
    "unit_wrong": Subtype(TIER1, "factual",
                          "a stated duration that contradicts Flow Duration read as microseconds (D19)"),
    # Tier 1 - outdated
    "patch_reference": Subtype(TIER1, "outdated", "a specific patch, update or release-date reference"),
    # Tier 1 - reasoning
    "attack_technique": Subtype(TIER1, "reasoning", "a named attack technique or attack class, hedged or not (D17)"),
    "impact_claim": Subtype(TIER1, "reasoning", "a resource-exhaustion / denial-of-service impact claim"),
    "inferred_outcome": Subtype(TIER1, "reasoning", "an inferred attack outcome (breach, unauthorized access, ...)"),
    "threat_actor": Subtype(TIER1, "reasoning", "attacker / threat-actor framing"),
    # Tier 1 - certainty
    "attacker_intent": Subtype(TIER1, "certainty", "a definitive statement of attacker intent"),
    "compromise_claim": Subtype(TIER1, "certainty", "a definitive claim that a system was compromised"),
    "hard_certainty": Subtype(TIER1, "certainty", "definitive language such as 'definitely is'"),
    "other_fabrication": Subtype(TIER1, "factual",
                                 "an invented specific that fits no listed subtype (e.g. an invented hostname); "
                                 "needs a note (D21)", catch_all=True),
    # Tier 2 - external knowledge
    "port": Subtype(TIER2, "external_knowledge", "what a port PRESENT in the evidence is used for (D16)"),
    "protocol": Subtype(TIER2, "external_knowledge", "TCP/HTTP session or protocol-behaviour norms"),
    "encryption": Subtype(TIER2, "external_knowledge", "an assumption that traffic is (un)encrypted"),
    "baseline": Subtype(TIER2, "external_knowledge", "a comparison with typical/normal traffic"),
    "unit": Subtype(TIER2, "external_knowledge",
                    "a unit attached to a raw duration, consistent with microseconds (D19)"),
    "other_knowledge": Subtype(TIER2, "external_knowledge",
                               "outside knowledge that fits no listed subtype; needs a note (D21)", catch_all=True),
    # rule-internal
    "soft_certainty": Subtype(TIER1, "certainty", "soft certainty words; sends the item to the LLM judge", False),
}
TIER2_SUBTYPES = tuple(k for k, v in SUBTYPES.items() if v.tier == TIER2 and not v.catch_all)
CATCH_ALL_SUBTYPES = tuple(k for k, v in SUBTYPES.items() if v.catch_all)


def is_catch_all(subtype: str | None) -> bool:
    """D21: catch-all subtypes are counted separately in every report."""
    return subtype in CATCH_ALL_SUBTYPES


# ── rule -> tier/subtype ──────────────────────────────────────────────────

@dataclass(frozen=True)
class RuleTier:
    tier: int
    type: str      # the rule engine's hallucination_type
    subtype: str


# Keyed by the exact description string in detection/patterns.py. Rule layers that build
# their description at run time, and the checks added here, use the stable keys in brackets.
PORT_MISMATCH = "[port number not in evidence]"
PROTOCOL_INJECTION = "[protocol named without its well-known port in evidence]"
SOFT_CERTAINTY = "[soft certainty language]"
UNIT_WRONG = "[stated duration contradicts Flow Duration in microseconds]"
UNIT_STATED = "[duration stated with an explicit unit]"

RULE_TIERS: dict[str, RuleTier] = {
    "CVE identifier not present in evidence": RuleTier(TIER1, "factual", "cve"),
    "Named exploit or attack tool": RuleTier(TIER1, "factual", "tool"),
    "Specific software version": RuleTier(TIER1, "factual", "version"),
    "IP address stated — not in evidence": RuleTier(TIER1, "factual", "ip_address"),
    "Specific patch or version reference": RuleTier(TIER1, "outdated", "patch_reference"),
    "Named attack technique — not derivable from flow numbers": RuleTier(TIER1, "reasoning", "attack_technique"),
    "Resource exhaustion / DoS impact claim": RuleTier(TIER1, "reasoning", "impact_claim"),
    "Inferred attack outcome": RuleTier(TIER1, "reasoning", "inferred_outcome"),
    "Threat-actor framing — not supportable from flow features": RuleTier(TIER1, "reasoning", "threat_actor"),
    "Definitive attacker intent": RuleTier(TIER1, "certainty", "attacker_intent"),
    "Definitive compromise claim": RuleTier(TIER1, "certainty", "compromise_claim"),
    "Hard certainty language": RuleTier(TIER1, "certainty", "hard_certainty"),
    PORT_MISMATCH: RuleTier(TIER1, "factual", "port_not_in_evidence"),
    PROTOCOL_INJECTION: RuleTier(TIER1, "factual", "protocol_without_port"),
    "Port characterization — labelling a port's purpose is external knowledge":
        RuleTier(TIER2, "external_knowledge", "port"),
    "Protocol behavior knowledge — TCP/HTTP session norms are external knowledge":
        RuleTier(TIER2, "external_knowledge", "protocol"),
    "Encryption assumption — not in flow evidence": RuleTier(TIER2, "external_knowledge", "encryption"),
    "External baseline comparison — requires outside knowledge": RuleTier(TIER2, "external_knowledge", "baseline"),
    "Unit assumption — raw flow duration has no guaranteed unit": RuleTier(TIER2, "external_knowledge", "unit"),
    UNIT_STATED: RuleTier(TIER2, "external_knowledge", "unit"),
    UNIT_WRONG: RuleTier(TIER1, "factual", "unit_wrong"),
    SOFT_CERTAINTY: RuleTier(TIER1, "certainty", "soft_certainty"),
}
UNIT_RULE = "Unit assumption — raw flow duration has no guaranteed unit"

# Order in which the sentence engine checks the layers (first that fires decides).
LAYER_ORDER: list[str] = ([d for _, _, d in ALL_RULE_PATTERNS] + [PORT_MISMATCH, PROTOCOL_INJECTION]
                          + [d for _, d in EXTERNAL_KNOWLEDGE_PATTERNS] + [UNIT_STATED, UNIT_WRONG, SOFT_CERTAINTY])
_LAYER_INDEX = {k: i for i, k in enumerate(LAYER_ORDER)}

# Tier of a hallucination_type returned by the v1 judge (no subtype unless it names one).
TYPE_TIERS = {"factual": TIER1, "reasoning": TIER1, "certainty": TIER1, "outdated": TIER1,
              "external_knowledge": TIER2}


# ── D17: hedging lexicon (frozen) ─────────────────────────────────────────

HEDGE_LEXICON = ("could", "may", "might", "possibly", "potentially", "perhaps", "appear", "appears",
                 "seem", "seems", "suggest", "suggests", "suggesting", "consistent with", "compatible with",
                 "likely", "probably")
HEDGE_RE = re.compile(r"\b(?:" + "|".join(w.replace(" ", r"\s+") for w in HEDGE_LEXICON) + r")\b", re.IGNORECASE)


def is_hedged(text: str) -> bool:
    return HEDGE_RE.search(text) is not None


# ── D19: stated durations versus Flow Duration (microseconds) ─────────────

DURATION_UNITS = {"microsecond": 1e-6, "millisecond": 1e-3, "second": 1.0, "minute": 60.0, "hour": 3600.0}
DURATION_TOLERANCE = 0.10
DURATION_CLAIM_RE = re.compile(
    r"(?<![\w.,])(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d+))?\s*(microsecond|millisecond|second|minute|hour)s?\b",
    re.IGNORECASE)
_FLOW_DURATION_RE = re.compile(r"Flow Duration:\s*(-?\d+)")


def flow_duration_from_evidence(evidence: str) -> int | None:
    m = _FLOW_DURATION_RE.search(evidence or "")
    return int(m.group(1)) if m else None


def duration_claims(sentence: str, flow_duration_us: int | None) -> list[dict]:
    """Every '<number> <unit>' duration in the sentence, judged against Flow Duration (µs).
    Consistent if within 10% of the true value in that unit, or equal to the true value
    rounded to the number of decimals stated ('0.09 seconds' for 92,190 µs).
    Without a Flow Duration, `consistent` is None (the claim is still found, D20)."""
    claims = []
    for m in DURATION_CLAIM_RE.finditer(sentence):
        whole, frac, unit = m.group(1), m.group(2), m.group(3).lower()
        value = float(whole.replace(",", "") + ("." + frac if frac else ""))
        if flow_duration_us is None:
            claims.append({"text": m.group(0), "value": value, "unit": unit, "true_value_in_unit": None,
                           "consistent": None})
            continue
        truth = flow_duration_us * 1e-6 / DURATION_UNITS[unit]
        decimals = len(frac) if frac else 0
        if truth == 0:
            ok = value == 0
        else:
            ok = abs(value - truth) <= DURATION_TOLERANCE * abs(truth) or round(truth, decimals) == value
        claims.append({"text": m.group(0), "value": value, "unit": unit, "true_value_in_unit": truth,
                       "consistent": ok})
    return claims


# ── stamps and small helpers ──────────────────────────────────────────────

def policy_stamp() -> dict:
    """Version + fingerprint of everything this module adds on top of the rule engine."""
    blob = json.dumps({
        "rule_tiers": {k: asdict(v) for k, v in RULE_TIERS.items()},
        "subtypes": {k: asdict(v) for k, v in SUBTYPES.items()},
        "policies": {k: sorted(v) for k, v in POLICY_TIERS.items()},
        "hedge_lexicon": HEDGE_LEXICON,
        "duration": {"units": DURATION_UNITS, "tolerance": DURATION_TOLERANCE, "regex": DURATION_CLAIM_RE.pattern},
    }, sort_keys=True, ensure_ascii=False)
    return {"policy_version": POLICY_VERSION, "tier_map_sha256": hashlib.sha256(blob.encode("utf-8")).hexdigest()}


def check_policy(policy: str) -> str:
    if policy not in POLICY_TIERS:
        raise ValueError(f"Unknown policy {policy!r}; use one of {sorted(POLICY_TIERS)}")
    return policy


def counts_as_hallucination(tier: int | None, policy: str) -> bool:
    return tier is not None and tier in POLICY_TIERS[check_policy(policy)]


def tier_for_type(h_type: str | None) -> tuple[int | None, str | None]:
    """(tier, subtype) for a hallucination_type returned by the v1 judge."""
    if not h_type:
        return None, None
    t = str(h_type).strip().lower()
    for sub in TIER2_SUBTYPES:
        if t in (f"external_knowledge_{sub}", f"external_knowledge/{sub}"):
            return TIER2, sub
    return TYPE_TIERS.get(t), None


# ── one rule pass -> tagged hits ──────────────────────────────────────────

def _rule_key(hit: dict) -> str:
    rule = hit["rule"]
    if rule in RULE_TIERS:
        return rule
    if re.fullmatch(r"Port \d+ mentioned but not in evidence", rule):
        return PORT_MISMATCH
    if rule.startswith("Protocol '"):
        return PROTOCOL_INJECTION
    raise KeyError(f"No tier for rule {rule!r}: add it to policy.RULE_TIERS")


def _tag(hit: dict, key: str, hedged: bool) -> dict:
    t = RULE_TIERS[key]
    return {**hit, "key": key, "tier": t.tier, "type": t.type, "subtype": t.subtype, "hedged": hedged}


def _containing(sentences: list[str], matched: list[str]) -> list[str]:
    needles = [str(m).lower() for m in matched if str(m).strip()]
    return [s for s in sentences if any(n in s.lower() for n in needles)]


def _hits_for_text(text: str, sentences: list[str], evidence_tokens, *, tier2: bool,
                   flow_duration_us: int | None) -> tuple[list[dict], list[dict]]:
    """All hits in `text` (in layer order) plus the duration claims checked.

    `sentences` are where hedging and duration claims are looked up: a hit is hedged if
    every sentence containing its match is hedged. With the Tier 2 layer on:
      D20  a sentence stating a duration with an explicit unit gets a Tier 2 `unit` hit
           unless the rule engine already produced a `unit` hit for that sentence;
      D19  every `unit` hit in a sentence with a contradicted duration becomes Tier 1
           `unit_wrong` (keeping `original_subtype: unit`)."""
    raw = rule_based_detect_explanation(text, evidence_tokens)["matched_rules"]
    if tier2:
        raw = raw + check_external_knowledge(text)
    hits = []
    for h in raw:
        where = _containing(sentences, h["matched"])
        hits.append(_tag(h, _rule_key(h), bool(where) and all(is_hedged(s) for s in where)))

    claims = []
    if tier2:
        rule_unit_sentences = {s for h in hits if h["key"] == UNIT_RULE for s in _containing(sentences, h["matched"])}
        wrong_sentences = set()
        for s in sentences:
            cs = duration_claims(s, flow_duration_us)
            claims += [{**c, "sentence": s} for c in cs]
            if cs and s not in rule_unit_sentences:
                hits.append(_tag({"rule": UNIT_STATED, "type": "external_knowledge",
                                  "matched": [c["text"] for c in cs][:3]}, UNIT_STATED, is_hedged(s)))
            if any(c["consistent"] is False for c in cs):
                wrong_sentences.add(s)
        for i, h in enumerate(hits):
            if h["key"] not in (UNIT_RULE, UNIT_STATED):
                continue
            if any(s in wrong_sentences for s in _containing(sentences, h["matched"])):
                hits[i] = {**_tag(h, UNIT_WRONG, h["hedged"]), "rule": h["rule"], "unit_wrong": True,
                           "original_subtype": "unit", "original_key": h["key"]}
            else:
                hits[i] = {**h, "unit_wrong": False}
    hits.sort(key=lambda h: _LAYER_INDEX[h["key"]])
    return hits, claims


# ── explanation level (Phase 2) ───────────────────────────────────────────

def explanation_rule_hits(explanation: str, evidence_tokens, *, use_tier2_rules: bool,
                          flow_duration_us: int | None = None) -> dict:
    """One rule pass over an explanation. Tier 1 layers always run (exactly the old Phase 2
    rules); the Tier 2 layer and the D19 duration check run if use_tier2_rules (C1, C3), so
    C0 and C2 keep the old rule engine unchanged.
    Returns {"hits", "soft_certainty", "duration_claims"}."""
    hits, claims = _hits_for_text(explanation, split_sentences(explanation), evidence_tokens,
                                  tier2=use_tier2_rules, flow_duration_us=flow_duration_us)
    return {"hits": hits, "soft_certainty": SOFT_CERTAINTY_RE.findall(explanation), "duration_claims": claims}


def explanation_rule_decision(rule_pass: dict, policy: str) -> dict:
    """Apply a policy to one rule pass. Same shape as rule_based_detect_explanation():
    triggered True (counted hit), None (only soft certainty: escalate), False (clean).
    Hits the policy does not count are kept under `uncounted_rules`."""
    counted = [h for h in rule_pass["hits"] if counts_as_hallucination(h["tier"], policy)]
    uncounted = [h for h in rule_pass["hits"] if not counts_as_hallucination(h["tier"], policy)]
    if counted:
        counted = sorted(counted, key=lambda r: TYPE_PRIORITY.get(r["type"], 99))
        return {"triggered": True, "confidence": "high", "matched_rules": counted,
                "hallucination_type": counted[0]["type"], "tier": counted[0]["tier"],
                "subtype": counted[0]["subtype"], "reason": "; ".join(r["rule"] for r in counted[:2]),
                "uncounted_rules": uncounted}
    if rule_pass["soft_certainty"]:
        return {"triggered": None, "confidence": "medium", "matched_rules": [],
                "hallucination_type": "certainty", "tier": TIER1, "subtype": "soft_certainty",
                "reason": f"Soft certainty markers: {rule_pass['soft_certainty'][:3]}",
                "uncounted_rules": uncounted}
    return {"triggered": False, "confidence": "high", "matched_rules": [], "hallucination_type": None,
            "tier": None, "subtype": None, "reason": "No rule patterns matched.", "uncounted_rules": uncounted}


# ── sentence level (Phase 3) ──────────────────────────────────────────────

def _legacy_key(result: dict) -> str | None:
    method = result["detection_method"]
    if method == "rule_port_mismatch":
        return PORT_MISMATCH
    if method == "rule_protocol_injection":
        return PROTOCOL_INJECTION
    if method == "rule_soft_certainty":
        return SOFT_CERTAINTY
    if method in ("rule_pattern", "rule_external_knowledge"):
        for desc in RULE_TIERS:          # reason is "<description>: [matches]"
            if result["reason"].startswith(desc + ": "):
                return desc
        raise KeyError(f"No tier for sentence rule reason {result['reason']!r}")
    return None                           # rule_clean


def classify_sentence_rules(sentence: str, evidence_tokens: set[str], flow_duration_us: int | None = None) -> dict:
    """rule_classify_sentence() (unchanged) plus, from one pass over every layer:
    `hits` (all matched rules with tier/subtype/hedged, D18), `subtypes`, `hedged`,
    `duration_claims` (D19), and the tier/subtype of the engine's own deciding rule."""
    legacy = rule_classify_sentence(sentence, evidence_tokens)
    key = _legacy_key(legacy)
    hits, claims = _hits_for_text(sentence, [sentence], evidence_tokens, tier2=True, flow_duration_us=flow_duration_us)
    t = RULE_TIERS[key] if key else None
    return {**legacy, "key": key, "tier": t.tier if t else None, "subtype": t.subtype if t else None,
            "hits": hits, "subtypes": list(dict.fromkeys(h["subtype"] for h in hits)),
            "hedged": is_hedged(sentence), "duration_claims": claims}


def sentence_policy_decision(tagged: dict, sentence: str, policy: str) -> dict:
    """Verdict under `policy` from one rule pass: label 'hallucinated' | 'grounded' |
    'ambiguous', plus the primary hit (Tier 1 first, then the engine's layer order, so
    without a contradicted duration the primary is the engine's own deciding rule)."""
    counted = [h for h in tagged["hits"] if counts_as_hallucination(h["tier"], policy)]
    if counted:
        primary = min(counted, key=lambda h: (h["tier"], _LAYER_INDEX[h["key"]]))
        return {"label": "hallucinated", "primary": primary}
    if SOFT_CERTAINTY_RE.search(sentence):
        return {"label": "ambiguous", "primary": None}
    return {"label": "grounded", "primary": None}


# ── v2 judge replies ──────────────────────────────────────────────────────

def _parse_tier(value) -> tuple[int | None, bool]:
    if value is None or (isinstance(value, str) and value.strip().lower() in ("", "null", "none")):
        return None, True
    if isinstance(value, bool):
        return None, False
    if isinstance(value, int) and value in (1, 2):
        return value, True
    if isinstance(value, str) and value.strip() in ("1", "2"):
        return int(value.strip()), True
    return None, False


def parse_v2_reply(raw: dict, level: str) -> dict:
    """Normalise a v2 judge reply.
    explanation level: contains_hallucination, confidence, tier (1, 2 or null), subtype, reason
    sentence level:    label, confidence, tier, subtype, reason
    plus `note`, required (non-empty) whenever the subtype is a D21 catch-all.
    Returns the verdict (True / False / None), tier, subtype, hallucination_type (from the
    subtype vocabulary) and a list of `reply_problems` (empty when the reply is well-formed)."""
    problems = []
    if level == "explanation":
        v = raw.get("contains_hallucination")
        verdict = v if isinstance(v, bool) else None
        if verdict is None:
            problems.append(f"contains_hallucination is {v!r}")
    elif level == "sentence":
        v = str(raw.get("label", "")).strip().lower()
        verdict = {"hallucinated": True, "grounded": False}.get(v)
        if verdict is None:
            problems.append(f"label is {raw.get('label')!r}")
    else:
        raise ValueError(level)
    tier, ok = _parse_tier(raw.get("tier"))
    if not ok:
        problems.append(f"tier is {raw.get('tier')!r}")
    sub = raw.get("subtype")
    sub = None if sub is None or str(sub).strip().lower() in ("", "null", "none") else str(sub).strip()
    note = raw.get("note")
    note = None if note is None or str(note).strip().lower() in ("", "null", "none") else str(note).strip()
    if is_catch_all(sub) and not note:
        problems.append(f"subtype {sub!r} needs a short free-text note (D21)")
    h_type = None
    if sub is not None:
        if sub not in SUBTYPES or not SUBTYPES[sub].label:
            problems.append(f"unknown subtype {sub!r}")
        else:
            h_type = SUBTYPES[sub].type
            if tier is not None and SUBTYPES[sub].tier != tier:
                problems.append(f"subtype {sub!r} is tier {SUBTYPES[sub].tier}, reply says tier {tier}")
    if verdict is True and tier is None:
        problems.append("hallucination without a tier")
    if verdict is False and (tier is not None or sub is not None):
        problems.append("no hallucination but a tier/subtype was given")
    return {"verdict": verdict, "tier": tier, "subtype": sub, "hallucination_type": h_type,
            "catch_all": is_catch_all(sub), "note": note,
            "confidence": raw.get("confidence"), "reason": raw.get("reason"), "reply_problems": problems}


# ── Phase 2 / 3 options and the detection configurations C0-C3 ───────────

# The v2 files are supplied by the paper side (docs/HANDOFF.md); asking for a missing one
# gives a clear error. Templates must contain the placeholders listed in PROMPT_PLACEHOLDERS.
JUDGE_PROMPTS = {
    "v1": ("detect_explanation_system.txt", "detect_explanation_template.txt"),
    "v2-strict": ("detect_explanation_system_v2_strict.txt", "detect_explanation_template_v2.txt"),
    "v2-lenient": ("detect_explanation_system_v2_lenient.txt", "detect_explanation_template_v2.txt"),
}
# v1 has no template file: its user message stays in detection_pipeline.py, unchanged.
SENTENCE_PROMPTS = {
    "v1": ("localize_sentence_system.txt", None),
    "v2-strict": ("localize_sentence_system_v2_strict.txt", "localize_sentence_template_v2.txt"),
    "v2-lenient": ("localize_sentence_system_v2_lenient.txt", "localize_sentence_template_v2.txt"),
}
GENERATION_PROMPTS = {"v1": "generate_system.txt", "v2": "generate_system_v2.txt"}
PROMPT_PLACEHOLDERS = {
    "detect_explanation_template_v2.txt": {"evidence", "explanation"},
    "localize_sentence_template_v2.txt": {"evidence", "sentence"},
}
EXPECTED_V2_PROMPTS = sorted({n for p in (JUDGE_PROMPTS, SENTENCE_PROMPTS) for k, files in p.items()
                              if k != "v1" for n in files if n} | {GENERATION_PROMPTS["v2"]})

ESCALATE_CLEAN = ("all", "attack_only")   # D15: "all" for fresh runs, "attack_only" = old behaviour

# EXPERIMENT_PLAN section 7: C0 Tier 1 rules + old judge; C1 Tier 1+2 + old judge;
# C2 Tier 1 + policy-aligned judge; C3 Tier 1+2 + aligned judge.
DETECTION_CONFIGS = {
    "C0": {"use_tier2_rules": False, "aligned_judge": False},
    "C1": {"use_tier2_rules": True, "aligned_judge": False},
    "C2": {"use_tier2_rules": False, "aligned_judge": True},
    "C3": {"use_tier2_rules": True, "aligned_judge": True},
}


def detection_options(config_name: str, policy: str) -> dict:
    """Phase 2 options for one ablation cell, e.g. ("C3", "lenient") ->
    {"use_tier2_rules": True, "judge_prompt": "v2-lenient", "policy": "lenient"}."""
    check_policy(policy)
    c = DETECTION_CONFIGS[config_name]
    return {"use_tier2_rules": c["use_tier2_rules"],
            "judge_prompt": f"v2-{policy}" if c["aligned_judge"] else "v1", "policy": policy}


def _require(name: str) -> str:
    path = config.PROMPTS_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"Prompt file {name} is missing from {config.PROMPTS_DIR}. v2 prompts are "
                                "supplied by the paper side (docs/HANDOFF.md); add it as a new file.")
    if name in PROMPT_PLACEHOLDERS:
        found = {f for _, f, _, _ in string.Formatter().parse(path.read_text(encoding="utf-8")) if f}
        if found != PROMPT_PLACEHOLDERS[name]:
            raise ValueError(f"{name} must use exactly the placeholders {sorted(PROMPT_PLACEHOLDERS[name])} "
                             f"(found {sorted(found)}); write literal JSON braces as {{{{ and }}}}")
    return name


def judge_prompt_files(judge_prompt: str) -> tuple[str, str]:
    if judge_prompt not in JUDGE_PROMPTS:
        raise ValueError(f"Unknown judge_prompt {judge_prompt!r}; use one of {sorted(JUDGE_PROMPTS)}")
    return tuple(_require(n) for n in JUDGE_PROMPTS[judge_prompt])


def sentence_prompt_files(sentence_prompt: str) -> tuple[str, str | None]:
    if sentence_prompt not in SENTENCE_PROMPTS:
        raise ValueError(f"Unknown sentence_prompt {sentence_prompt!r}; use one of {sorted(SENTENCE_PROMPTS)}")
    system, template = SENTENCE_PROMPTS[sentence_prompt]
    return _require(system), (_require(template) if template else None)

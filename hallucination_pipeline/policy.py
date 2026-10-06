"""
M2: two-tier hallucination taxonomy and the strict / lenient policies (DECISIONS D3).

  Tier 1 - unsupported specifics: factual, reasoning, certainty, outdated
  Tier 2 - external knowledge:    port, protocol, encryption, baseline, unit
  strict  policy: Tier 1 and Tier 2 are hallucinations
  lenient policy: only Tier 1 is

Design: the rule engine (detection/patterns.py, detection/rules.py) is NOT edited, so
RULES_VERSION and both rule fingerprints stay as they are. Tier and subtype live here,
in RULE_TIERS, keyed by each rule's description string. A test checks that every rule
description has an entry and that the entry's type matches the rule's own type.

Detection runs the rules once and keeps the tier of every hit; both policies are then
derived from that single pass (explanation_rule_decision / sentence_policy_label).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass

from . import config
from .detection import (SOFT_CERTAINTY_RE, check_external_knowledge, rule_based_detect_explanation,
                        rule_classify_sentence)
from .detection.patterns import TYPE_PRIORITY

POLICY_VERSION = "1.0.0"
TIER1, TIER2 = 1, 2
POLICY_TIERS: dict[str, frozenset[int]] = {"strict": frozenset({TIER1, TIER2}), "lenient": frozenset({TIER1})}


@dataclass(frozen=True)
class RuleTier:
    tier: int
    type: str      # the rule engine's hallucination_type
    subtype: str


# Keyed by the exact description string in detection/patterns.py. Three rule layers build
# their description at run time (it contains the matched port / protocol), so they use
# the stable keys in brackets.
PORT_MISMATCH = "[port number not in evidence]"
PROTOCOL_INJECTION = "[protocol named without its well-known port in evidence]"
SOFT_CERTAINTY = "[soft certainty language]"

RULE_TIERS: dict[str, RuleTier] = {
    # Tier 1 - factual
    "CVE identifier not present in evidence": RuleTier(TIER1, "factual", "cve"),
    "Named exploit or attack tool": RuleTier(TIER1, "factual", "tool"),
    "Specific software version": RuleTier(TIER1, "factual", "version"),
    "IP address stated — not in evidence": RuleTier(TIER1, "factual", "ip_address"),
    PORT_MISMATCH: RuleTier(TIER1, "factual", "port_not_in_evidence"),
    PROTOCOL_INJECTION: RuleTier(TIER1, "factual", "protocol_without_port"),
    # Tier 1 - outdated
    "Specific patch or version reference": RuleTier(TIER1, "outdated", "patch_reference"),
    # Tier 1 - reasoning
    "Named attack technique — not derivable from flow numbers": RuleTier(TIER1, "reasoning", "attack_technique"),
    "Resource exhaustion / DoS impact claim": RuleTier(TIER1, "reasoning", "impact_claim"),
    "Inferred attack outcome": RuleTier(TIER1, "reasoning", "inferred_outcome"),
    "Threat-actor framing — not supportable from flow features": RuleTier(TIER1, "reasoning", "threat_actor"),
    # Tier 1 - certainty
    "Definitive attacker intent": RuleTier(TIER1, "certainty", "attacker_intent"),
    "Definitive compromise claim": RuleTier(TIER1, "certainty", "compromise_claim"),
    "Hard certainty language": RuleTier(TIER1, "certainty", "hard_certainty"),
    SOFT_CERTAINTY: RuleTier(TIER1, "certainty", "soft_certainty"),   # never decisive: escalates to the LLM
    # Tier 2 - external knowledge
    "Port characterization — labelling a port's purpose is external knowledge":
        RuleTier(TIER2, "external_knowledge", "port"),
    "Protocol behavior knowledge — TCP/HTTP session norms are external knowledge":
        RuleTier(TIER2, "external_knowledge", "protocol"),
    "Encryption assumption — not in flow evidence": RuleTier(TIER2, "external_knowledge", "encryption"),
    "External baseline comparison — requires outside knowledge": RuleTier(TIER2, "external_knowledge", "baseline"),
    "Unit assumption — raw flow duration has no guaranteed unit": RuleTier(TIER2, "external_knowledge", "unit"),
}

# Tier of a hallucination_type returned by an LLM judge (no subtype unless it names one,
# e.g. "external_knowledge_port").
TYPE_TIERS = {"factual": TIER1, "reasoning": TIER1, "certainty": TIER1, "outdated": TIER1,
              "external_knowledge": TIER2}
TIER2_SUBTYPES = ("port", "protocol", "encryption", "baseline", "unit")


def policy_stamp() -> dict:
    """Version + fingerprint of the tier map and policies, written to every record."""
    blob = json.dumps({"rule_tiers": {k: asdict(v) for k, v in RULE_TIERS.items()},
                       "policies": {k: sorted(v) for k, v in POLICY_TIERS.items()}},
                      sort_keys=True, ensure_ascii=False)
    return {"policy_version": POLICY_VERSION, "tier_map_sha256": hashlib.sha256(blob.encode("utf-8")).hexdigest()}


def check_policy(policy: str) -> str:
    if policy not in POLICY_TIERS:
        raise ValueError(f"Unknown policy {policy!r}; use one of {sorted(POLICY_TIERS)}")
    return policy


def counts_as_hallucination(tier: int | None, policy: str) -> bool:
    return tier is not None and tier in POLICY_TIERS[check_policy(policy)]


def tier_for_type(h_type: str | None) -> tuple[int | None, str | None]:
    """(tier, subtype) for an LLM-returned hallucination_type."""
    if not h_type:
        return None, None
    t = str(h_type).strip().lower()
    for sub in TIER2_SUBTYPES:
        if t in (f"external_knowledge_{sub}", f"external_knowledge/{sub}"):
            return TIER2, sub
    return TYPE_TIERS.get(t), None


# ── explanation level (Phase 2) ───────────────────────────────────────────

def _key_for_explanation_hit(hit: dict) -> str:
    rule = hit["rule"]
    if rule in RULE_TIERS:
        return rule
    if re.fullmatch(r"Port \d+ mentioned but not in evidence", rule):
        return PORT_MISMATCH
    if rule.startswith("Protocol '"):
        return PROTOCOL_INJECTION
    raise KeyError(f"No tier for rule {rule!r}: add it to policy.RULE_TIERS")


def tag_hit(hit: dict) -> dict:
    t = RULE_TIERS[_key_for_explanation_hit(hit)]
    return {**hit, "tier": t.tier, "subtype": t.subtype}


def explanation_rule_hits(explanation: str, evidence_tokens, *, use_tier2_rules: bool) -> dict:
    """One rule pass over an explanation. Tier 1 layers always run (exactly the legacy
    explanation-level rules); the Tier 2 external-knowledge layer runs if use_tier2_rules.
    Returns {"hits": [...each with tier/subtype...], "soft_certainty": [...markers...]}."""
    legacy = rule_based_detect_explanation(explanation, evidence_tokens)
    hits = [tag_hit(h) for h in legacy["matched_rules"]]
    if use_tier2_rules:
        hits += [tag_hit(h) for h in check_external_knowledge(explanation)]
    return {"hits": hits, "soft_certainty": SOFT_CERTAINTY_RE.findall(explanation)}


def explanation_rule_decision(rule_pass: dict, policy: str) -> dict:
    """Apply a policy to one rule pass. Same shape as rule_based_detect_explanation():
    triggered True (counted hit), None (only soft certainty: escalate), False (clean).
    Hits the policy does not count are kept under `uncounted_rules` for transparency."""
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

def _key_for_sentence_result(result: dict) -> str | None:
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


def classify_sentence_rules(sentence: str, evidence_tokens: set[str]) -> dict:
    """rule_classify_sentence() (unchanged) plus tier and subtype of the deciding rule."""
    result = rule_classify_sentence(sentence, evidence_tokens)
    key = _key_for_sentence_result(result)
    t = RULE_TIERS[key] if key else None
    return {**result, "tier": t.tier if t else None, "subtype": t.subtype if t else None}


def sentence_policy_label(tagged: dict, sentence: str, policy: str) -> str:
    """'hallucinated' | 'grounded' | 'ambiguous' under `policy`, from one rule pass.

    The rule engine stops at the first layer that fires and checks Tier 1 layers before
    Tier 2, so a Tier 2 result means no Tier 1 rule fired. Under lenient such a sentence
    is not a hallucination; it is 'ambiguous' if it also has soft certainty language
    (which the engine never reached), else 'grounded'."""
    label = tagged["label"]
    if label != "hallucinated" or counts_as_hallucination(tagged["tier"], policy):
        return label
    return "ambiguous" if SOFT_CERTAINTY_RE.search(sentence) else "grounded"


# ── Phase 2 / 3 options and the detection configurations C0-C3 ───────────

# Judge prompt name -> (system prompt file, template file). The v2 files are supplied by
# the paper side (docs/HANDOFF.md) and do not exist yet; asking for them gives a clear error.
JUDGE_PROMPTS = {
    "v1": ("detect_explanation_system.txt", "detect_explanation_template.txt"),
    "v2-strict": ("detect_explanation_system_v2_strict.txt", "detect_explanation_template.txt"),
    "v2-lenient": ("detect_explanation_system_v2_lenient.txt", "detect_explanation_template.txt"),
}
SENTENCE_PROMPTS = {
    "v1": "localize_sentence_system.txt",
    "v2-strict": "localize_sentence_system_v2_strict.txt",
    "v2-lenient": "localize_sentence_system_v2_lenient.txt",
}

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
    if not (config.PROMPTS_DIR / name).exists():
        raise FileNotFoundError(f"Prompt file {name} is missing from {config.PROMPTS_DIR}. v2 prompts are "
                                "supplied by the paper side (docs/HANDOFF.md); add it as a new file.")
    return name


def judge_prompt_files(judge_prompt: str) -> tuple[str, str]:
    if judge_prompt not in JUDGE_PROMPTS:
        raise ValueError(f"Unknown judge_prompt {judge_prompt!r}; use one of {sorted(JUDGE_PROMPTS)}")
    return tuple(_require(n) for n in JUDGE_PROMPTS[judge_prompt])


def sentence_prompt_file(sentence_prompt: str) -> str:
    if sentence_prompt not in SENTENCE_PROMPTS:
        raise ValueError(f"Unknown sentence_prompt {sentence_prompt!r}; use one of {sorted(SENTENCE_PROMPTS)}")
    return _require(SENTENCE_PROMPTS[sentence_prompt])

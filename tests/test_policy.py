"""M2: two-tier taxonomy, strict/lenient policies, Phase 2/3 options (no v2 prompt files yet)."""

import os
import random
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import fakes
from fakes import FakeGemini
from hallucination_pipeline import policy as POL
from hallucination_pipeline.detection import patterns as P
from hallucination_pipeline.detection import rule_based_detect_explanation, rule_classify_sentence
from hallucination_pipeline.detection.version import RULES_VERSION, rules_patterns_sha256, rules_source_sha256
from hallucination_pipeline.detection_pipeline import classify_sentence, detect_explanation

# ── pins ──────────────────────────────────────────────────────────────────

def test_rule_patterns_are_untouched_by_the_tier_refactor():
    # M2 must not edit the pattern tuples: tier and subtype live in policy.RULE_TIERS.
    assert rules_patterns_sha256() == "1d10799fee96d6fb918bc2242fc744d3ac424f3bdc13d10c9e545bc3690c98b0"
    assert rules_source_sha256() == "e2d2e17c8c786603aca128a0fb253360bb524aaf1dd4d57dacd13bd0f2cc22b8"
    assert RULES_VERSION == "1.0.0"


# POLICY_VERSION -> tier map fingerprint. Changing a tier/subtype fails this test: bump
# POLICY_VERSION in policy.py and ADD a line (and a DECISIONS entry after freeze-1).
POLICY_PINS = {"1.0.0": "85b280287c3eca908a59189d8f49b8b89b8683d6c865c91aa5d57dd38f2a2ff6"}


def test_tier_map_matches_pinned_fingerprint():
    stamp = POL.policy_stamp()
    assert POLICY_PINS.get(stamp["policy_version"]) == stamp["tier_map_sha256"], \
        "The tier map changed: bump POLICY_VERSION and add a POLICY_PINS entry"


# ── the mapping ───────────────────────────────────────────────────────────

def test_every_rule_has_a_tier_with_a_matching_type():
    for _, h_type, desc in P.ALL_RULE_PATTERNS:
        assert desc in POL.RULE_TIERS, desc
        assert POL.RULE_TIERS[desc].type == h_type and POL.RULE_TIERS[desc].tier == POL.TIER1
    for _, desc in P.EXTERNAL_KNOWLEDGE_PATTERNS:
        assert POL.RULE_TIERS[desc].tier == POL.TIER2 and POL.RULE_TIERS[desc].type == "external_knowledge"
    real = {d for _, _, d in P.ALL_RULE_PATTERNS} | {d for _, d in P.EXTERNAL_KNOWLEDGE_PATTERNS}
    special = {POL.PORT_MISMATCH, POL.PROTOCOL_INJECTION, POL.SOFT_CERTAINTY}
    assert set(POL.RULE_TIERS) == real | special          # no stale entries


def test_tier2_subtypes_are_exactly_the_planned_five():
    subs = sorted(t.subtype for t in POL.RULE_TIERS.values() if t.tier == POL.TIER2)
    assert subs == sorted(POL.TIER2_SUBTYPES) == ["baseline", "encryption", "port", "protocol", "unit"]


def test_policies():
    assert POL.counts_as_hallucination(1, "strict") and POL.counts_as_hallucination(2, "strict")
    assert POL.counts_as_hallucination(1, "lenient") and not POL.counts_as_hallucination(2, "lenient")
    assert not POL.counts_as_hallucination(None, "strict")
    with pytest.raises(ValueError):
        POL.counts_as_hallucination(1, "medium")


@pytest.mark.parametrize("h_type,expected", [
    ("factual", (1, None)), ("reasoning", (1, None)), ("certainty", (1, None)), ("outdated", (1, None)),
    ("external_knowledge", (2, None)), ("external_knowledge_unit", (2, "unit")), (None, (None, None)),
    ("something_else", (None, None)),
])
def test_tier_for_llm_types(h_type, expected):
    assert POL.tier_for_type(h_type) == expected


# ── sentence level ────────────────────────────────────────────────────────

TOKENS = {"22", "80", "450", "1234"}

SENTENCES = [  # sentence, tier, subtype, strict label, lenient label
    ("This flow exploits CVE-2017-0144 to gain access.", 1, "cve", "hallucinated", "hallucinated"),
    ("An attacker is targeting the host through this connection.", 1, "threat_actor", "hallucinated", "hallucinated"),
    ("The server has been compromised by this traffic pattern.", 1, "compromise_claim", "hallucinated", "hallucinated"),
    ("Traffic to port 3389 was observed in this flow record.", 1, "port_not_in_evidence", "hallucinated", "hallucinated"),
    ("The HTTPS session carried 450 packets in total here.", 1, "protocol_without_port", "hallucinated", "hallucinated"),
    ("Source 192.168.1.10 sent the packets to the host.", 1, "ip_address", "hallucinated", "hallucinated"),
    ("Apply patch MS17010 now for safety.", 1, "patch_reference", "hallucinated", "hallucinated"),
    ("The flow lasted approximately 17 hours based on the duration value.", 2, "unit", "hallucinated", "grounded"),
    ("Port 80 is commonly used for web traffic on most networks.", 2, "port", "hallucinated", "grounded"),
    ("The connection uses encryption for this session.", 2, "encryption", "hallucinated", "grounded"),
    ("ACK flags are expected in a fully established TCP connection here.", 2, "protocol", "hallucinated", "grounded"),
    ("This is definitely unusual for a flow of this size.", 1, "soft_certainty", "ambiguous", "ambiguous"),
    ("This is definitely unusual and lasted approximately 3 hours.", 2, "unit", "hallucinated", "ambiguous"),
    ("The flow recorded 450 forward packets in this record.", None, None, "grounded", "grounded"),
]


@pytest.mark.parametrize("sentence,tier,subtype,strict,lenient", SENTENCES)
def test_sentence_tier_subtype_and_both_policies(sentence, tier, subtype, strict, lenient):
    r = POL.classify_sentence_rules(sentence, TOKENS)
    assert (r["tier"], r["subtype"]) == (tier, subtype)
    assert POL.sentence_policy_label(r, sentence, "strict") == strict
    assert POL.sentence_policy_label(r, sentence, "lenient") == lenient


def corpus(n=300, seed=0):
    """Explanations and sentences mixing the fake LLM's clean and hallucinated sentences."""
    rng = random.Random(seed)
    extra = [s for s, *_ in SENTENCES]
    out = []
    for _ in range(n):
        port = rng.choice(["22", "80", "443", "3389", "53"])
        tokens = {port, str(rng.randint(1, 900)), str(rng.randint(0, 60)), "1234"}
        sents = [rng.choice(fakes._CLEAN).format(fwd=1, bwd=2, port=port, syn=3, dur=4, rate=5.0)
                 for _ in range(rng.randint(1, 4))]
        sents += rng.sample(fakes._BAD + extra, rng.randint(0, 3))
        rng.shuffle(sents)
        out.append((" ".join(sents), tokens))
    return out


def test_tiered_sentence_rules_never_change_the_original_verdict():
    for text, tokens in corpus():
        for s in P.split_sentences(text):
            legacy, tagged = rule_classify_sentence(s, tokens), POL.classify_sentence_rules(s, tokens)
            assert {k: tagged[k] for k in legacy} == legacy
            assert POL.sentence_policy_label(tagged, s, "strict") == legacy["label"]


# ── explanation level ─────────────────────────────────────────────────────

def strip_tiers(result):
    return {**result, "matched_rules": [{k: v for k, v in h.items() if k not in ("tier", "subtype")}
                                        for h in result["matched_rules"]]}


@pytest.mark.parametrize("policy", ["strict", "lenient"])
def test_c0_reproduces_the_original_explanation_rules_under_both_policies(policy):
    # C0 = Tier 1 rule layers only, which is exactly the old Phase 2 rule engine.
    for text, tokens in corpus():
        legacy = rule_based_detect_explanation(text, tokens)
        new = POL.explanation_rule_decision(POL.explanation_rule_hits(text, tokens, use_tier2_rules=False), policy)
        assert {k: strip_tiers(new)[k] for k in legacy} == legacy
        assert new["uncounted_rules"] == []


def test_tier2_layer_and_policies_at_explanation_level():
    text = "The flow recorded 450 packets. It lasted approximately 17 hours based on the duration."
    without = POL.explanation_rule_hits(text, TOKENS, use_tier2_rules=False)
    with_t2 = POL.explanation_rule_hits(text, TOKENS, use_tier2_rules=True)
    assert without["hits"] == [] and [h["subtype"] for h in with_t2["hits"]] == ["unit"]
    strict = POL.explanation_rule_decision(with_t2, "strict")
    lenient = POL.explanation_rule_decision(with_t2, "lenient")
    assert (strict["triggered"], strict["tier"], strict["subtype"]) == (True, 2, "unit")
    assert lenient["triggered"] is False and [h["subtype"] for h in lenient["uncounted_rules"]] == ["unit"]
    soft = POL.explanation_rule_hits(text + " This is definitely odd.", TOKENS, use_tier2_rules=True)
    assert POL.explanation_rule_decision(soft, "lenient")["triggered"] is None   # escalate to the judge


def test_tier1_hit_wins_over_tier2_under_both_policies():
    text = "An attacker sent 450 packets. The flow lasted approximately 3 hours."
    rp = POL.explanation_rule_hits(text, TOKENS, use_tier2_rules=True)
    for policy in ("strict", "lenient"):
        d = POL.explanation_rule_decision(rp, policy)
        assert d["triggered"] is True and d["tier"] == 1 and d["hallucination_type"] == "reasoning"


# ── options: C0-C3 and prompt names ───────────────────────────────────────

@pytest.mark.parametrize("cfg,policy,tier2,judge", [
    ("C0", "strict", False, "v1"), ("C0", "lenient", False, "v1"),
    ("C1", "strict", True, "v1"), ("C1", "lenient", True, "v1"),
    ("C2", "strict", False, "v2-strict"), ("C2", "lenient", False, "v2-lenient"),
    ("C3", "strict", True, "v2-strict"), ("C3", "lenient", True, "v2-lenient"),
])
def test_detection_configs(cfg, policy, tier2, judge):
    assert POL.detection_options(cfg, policy) == {"use_tier2_rules": tier2, "judge_prompt": judge, "policy": policy}


def test_v1_prompts_resolve_and_missing_v2_prompts_give_a_clear_error():
    assert POL.judge_prompt_files("v1") == ("detect_explanation_system.txt", "detect_explanation_template.txt")
    assert POL.sentence_prompt_file("v1") == "localize_sentence_system.txt"
    for name in ("v2-strict", "v2-lenient"):
        with pytest.raises(FileNotFoundError, match="supplied by the paper side"):
            POL.judge_prompt_files(name)
        with pytest.raises(FileNotFoundError, match="supplied by the paper side"):
            POL.sentence_prompt_file(name)
    with pytest.raises(ValueError):
        POL.judge_prompt_files("v3")


# ── wired into Phase 2 and Phase 3 ────────────────────────────────────────

ALERT = {"alert_id": "A0001", "alert_type": "DoS Hulk", "label_coarse": "DoS",
         "evidence": "Destination Port: 80\nForward Packets: 450", "evidence_tokens": ["450", "80"]}
LEGACY_KEYS = {"alert_id", "alert_type", "contains_hallucination", "confidence", "hallucination_type",
               "reason", "matched_rules", "detection_method", "gold_label"}


def expl(text):
    return {"alert_id": "A0001", "alert_type": "DoS Hulk", "explanation": text}


def test_phase2_without_policy_keeps_the_original_record_shape():
    rec = detect_explanation(FakeGemini(), ALERT, expl("An attacker sent 450 packets."), sleep=False)
    assert set(rec) == LEGACY_KEYS and rec["detection_method"] == "rule"
    with pytest.raises(ValueError):
        detect_explanation(FakeGemini(), ALERT, expl("x"), sleep=False, use_tier2_rules=True)


def test_phase2_with_policy_records_tier_and_options():
    text = "The flow had 450 packets. It lasted approximately 17 hours based on the duration."
    strict = detect_explanation(FakeGemini(), ALERT, expl(text), sleep=False, policy="strict", use_tier2_rules=True)
    assert (strict["contains_hallucination"], strict["tier"], strict["subtype"]) == (True, 2, "unit")
    assert strict["detection_method"] == "rule" and strict["judge_prompt"] == "v1"
    # lenient: the Tier 2 hit is not counted, the explanation is rule-clean, and because the alert
    # is an attack class the (v1) judge is consulted - the fake returns some verdict.
    lenient = detect_explanation(FakeGemini(), ALERT, expl(text), sleep=False, policy="lenient", use_tier2_rules=True)
    assert lenient["detection_method"] != "rule" and [h["subtype"] for h in lenient["uncounted_rules"]] == ["unit"]
    assert set(lenient) >= LEGACY_KEYS | {"policy", "use_tier2_rules", "judge_prompt", "tier", "subtype", "rule_hits"}


def test_phase2_escalation_uses_the_coarse_label_for_fine_labelled_alerts():
    # "DoS Hulk" is not in ATTACK_ALERT_TYPES; label_coarse "DoS" is, so a clean explanation is double-checked.
    clean = expl("The flow recorded 450 forward packets in this record.")
    assert detect_explanation(FakeGemini(), ALERT, clean, sleep=False)["detection_method"] != "rule"
    benign = {**ALERT, "alert_type": "BENIGN", "label_coarse": "Benign"}
    assert detect_explanation(FakeGemini(), benign, {**clean, "alert_type": "BENIGN"},
                              sleep=False)["detection_method"] == "rule"


def test_phase2_aligned_judge_needs_the_v2_prompt():
    clean = expl("The flow recorded 450 forward packets in this record.")
    with pytest.raises(FileNotFoundError, match="detect_explanation_system_v2_strict.txt"):
        detect_explanation(FakeGemini(), ALERT, clean, sleep=False, policy="strict", judge_prompt="v2-strict")


def test_phase3_sentence_records_tier_and_policy_label():
    s = "The flow lasted approximately 17 hours based on the duration value."
    legacy, _ = classify_sentence(FakeGemini(), ALERT, "S1", s, sleep=False)
    assert "tier" not in legacy and legacy["predicted_label"] == "hallucinated"
    strict, used = classify_sentence(FakeGemini(), ALERT, "S1", s, sleep=False, policy="strict")
    assert not used and (strict["predicted_label"], strict["tier"], strict["subtype"]) == ("hallucinated", 2, "unit")
    lenient, used = classify_sentence(FakeGemini(), ALERT, "S1", s, sleep=False, policy="lenient")
    assert not used and lenient["predicted_label"] == "grounded" and lenient["tier"] is None
    assert (lenient["rule_label"], lenient["rule_tier"], lenient["rule_subtype"]) == ("hallucinated", 2, "unit")
    assert "not counted under the lenient policy" in lenient["reason"]


def test_phase3_llm_fallback_tier_comes_from_the_llm_type():
    s = "This is definitely unusual for a flow of this size."
    rec, used = classify_sentence(FakeGemini(), ALERT, "S1", s, sleep=False, policy="strict")
    assert used and rec["rule_subtype"] == "soft_certainty"
    if rec["predicted_label"] == "hallucinated":
        assert rec["tier"] == POL.tier_for_type(rec["hallucination_type"])[0]
    else:
        assert rec["tier"] is None
    with pytest.raises(FileNotFoundError):
        classify_sentence(FakeGemini(), ALERT, "S1", s, sleep=False, policy="strict", sentence_prompt="v2-strict")


def test_rule_tier_table_in_docs_is_up_to_date():
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
    import export_rule_tiers
    assert export_rule_tiers.OUT.read_text(encoding="utf-8") == export_rule_tiers.render(), \
        "run: python tools/export_rule_tiers.py"
    assert len(export_rule_tiers.LAYERS) == len(POL.RULE_TIERS)


def test_p1b_outbox_contains_the_rule_tier_table(tmp_path):
    import zipfile
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
    from make_outbox import make_outbox
    zpath = make_outbox("P1b", None, tmp_path, "ok", label="abc123")
    with zipfile.ZipFile(zpath) as z:
        assert sorted(z.namelist()) == ["DECISIONS.md", "RULE_TIERS.md", "test_summary.txt"]
    with pytest.raises(ValueError):
        make_outbox("P1", None, tmp_path, "ok")

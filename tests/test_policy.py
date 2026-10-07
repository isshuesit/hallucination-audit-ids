"""M2: two-tier taxonomy, strict/lenient policies, D15-D19, Phase 2/3 options, v2 judge replies."""

import json
import os
import random
import shutil
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

import fakes
from fakes import FakeGemini
from hallucination_pipeline import config
from hallucination_pipeline import policy as POL
from hallucination_pipeline.detection import patterns as P
from hallucination_pipeline.detection import rule_based_detect_explanation, rule_classify_sentence
from hallucination_pipeline.detection.version import RULES_VERSION, rules_patterns_sha256, rules_source_sha256
from hallucination_pipeline.detection_pipeline import classify_sentence, detect_explanation, should_invoke_llm
from hallucination_pipeline.prompt_store import load_prompt

# ── pins ──────────────────────────────────────────────────────────────────

def test_rule_patterns_are_untouched():
    # Tier, subtype, hedging and the duration check live in policy.py, never in the rule patterns.
    assert rules_patterns_sha256() == "1d10799fee96d6fb918bc2242fc744d3ac424f3bdc13d10c9e545bc3690c98b0"
    assert rules_source_sha256() == "e2d2e17c8c786603aca128a0fb253360bb524aaf1dd4d57dacd13bd0f2cc22b8"
    assert RULES_VERSION == "1.0.0"


# POLICY_VERSION -> fingerprint of the tier map, subtype vocabulary, policies, hedge lexicon and
# duration check. A change fails this test: bump POLICY_VERSION and ADD a line.
POLICY_PINS = {
    "1.0.0": "85b280287c3eca908a59189d8f49b8b89b8683d6c865c91aa5d57dd38f2a2ff6",
    "1.1.0": "a7cd9218334bb702d5b5b7f9253da33a58c949ce0a7ef5c0a856566308732b98",   # D15-D19
    "1.2.0": "f83ccde8857c4117158c3231884d1e56997f2035aa6ac995252a2339a1b4d8be",   # D20, D21
}


def test_policy_matches_pinned_fingerprint():
    stamp = POL.policy_stamp()
    assert POLICY_PINS.get(stamp["policy_version"]) == stamp["tier_map_sha256"], \
        "policy.py changed: bump POLICY_VERSION and add a POLICY_PINS entry"


# ── vocabulary and mapping ────────────────────────────────────────────────

def test_every_rule_has_a_tier_with_a_matching_type():
    for _, h_type, desc in P.ALL_RULE_PATTERNS:
        assert POL.RULE_TIERS[desc].type == h_type and POL.RULE_TIERS[desc].tier == POL.TIER1
    for _, desc in P.EXTERNAL_KNOWLEDGE_PATTERNS:
        assert POL.RULE_TIERS[desc].tier == POL.TIER2 and POL.RULE_TIERS[desc].type == "external_knowledge"
    real = {d for _, _, d in P.ALL_RULE_PATTERNS} | {d for _, d in P.EXTERNAL_KNOWLEDGE_PATTERNS}
    special = {POL.PORT_MISMATCH, POL.PROTOCOL_INJECTION, POL.SOFT_CERTAINTY, POL.UNIT_WRONG, POL.UNIT_STATED}
    assert set(POL.RULE_TIERS) == real | special == set(POL.LAYER_ORDER)


def test_rule_subtypes_come_from_the_vocabulary():
    for key, rt in POL.RULE_TIERS.items():
        st = POL.SUBTYPES[rt.subtype]
        assert (st.tier, st.type) == (rt.tier, rt.type), key
    # D21: every subtype is produced by some rule, except the two catch-alls, which no rule produces
    assert set(POL.SUBTYPES) - {rt.subtype for rt in POL.RULE_TIERS.values()} == set(POL.CATCH_ALL_SUBTYPES)
    assert POL.CATCH_ALL_SUBTYPES == ("other_fabrication", "other_knowledge")
    assert (POL.SUBTYPES["other_fabrication"].tier, POL.SUBTYPES["other_knowledge"].tier) == (1, 2)


def test_tier2_subtypes_are_exactly_the_planned_five():
    assert sorted(POL.TIER2_SUBTYPES) == ["baseline", "encryption", "port", "protocol", "unit"]


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
def test_tier_for_v1_judge_types(h_type, expected):
    assert POL.tier_for_type(h_type) == expected


# ── sentence level: tiers, both policies, all subtypes ────────────────────

TOKENS = {"22", "80", "450", "1234"}

SENTENCES = [  # sentence, primary tier, primary subtype, strict label, lenient label
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
    ("This is definitely unusual for a flow of this size.", None, None, "ambiguous", "ambiguous"),
    ("This is definitely unusual and lasted approximately 3 hours.", 2, "unit", "hallucinated", "ambiguous"),
    ("The flow recorded 450 forward packets in this record.", None, None, "grounded", "grounded"),
]


@pytest.mark.parametrize("sentence,tier,subtype,strict,lenient", SENTENCES)
def test_sentence_tier_subtype_and_both_policies(sentence, tier, subtype, strict, lenient):
    r = POL.classify_sentence_rules(sentence, TOKENS)
    for policy, label in (("strict", strict), ("lenient", lenient)):
        d = POL.sentence_policy_decision(r, sentence, policy)
        assert d["label"] == label
    d = POL.sentence_policy_decision(r, sentence, "strict")
    assert ((d["primary"] or {}).get("tier"), (d["primary"] or {}).get("subtype")) == (tier, subtype)


def test_d18_all_matched_subtypes_are_kept():
    s = "An attacker sent traffic to port 80, which is commonly used for web traffic."
    r = POL.classify_sentence_rules(s, TOKENS)
    assert r["subtypes"] == ["threat_actor", "port"]
    assert [(h["tier"], h["subtype"]) for h in r["hits"]] == [(1, "threat_actor"), (2, "port")]
    assert POL.sentence_policy_decision(r, s, "strict")["primary"]["subtype"] == "threat_actor"
    assert POL.sentence_policy_decision(r, s, "lenient")["primary"]["subtype"] == "threat_actor"


def corpus(n=300, seed=0):
    """Explanations mixing the fake LLM's clean and hallucinated sentences with SENTENCES."""
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


def test_without_durations_the_strict_verdict_is_the_original_engine_verdict():
    for text, tokens in corpus():
        for s in P.split_sentences(text):
            legacy, tagged = rule_classify_sentence(s, tokens), POL.classify_sentence_rules(s, tokens)
            assert {k: tagged[k] for k in legacy} == legacy
            d = POL.sentence_policy_decision(tagged, s, "strict")
            assert d["label"] == legacy["label"]
            if legacy["label"] == "hallucinated":
                assert d["primary"]["key"] == tagged["key"] and tagged["subtype"] in tagged["subtypes"]


# ── D17 hedging ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("word", POL.HEDGE_LEXICON)
def test_every_lexicon_entry_marks_a_sentence_hedged(word):
    assert POL.is_hedged(f"The pattern {word} port scanning activity.")


@pytest.mark.parametrize("text", ["This is port scanning.", "It is unlikely to matter.", "Maybe it is a scan.",
                                  "The appearance of the flow."])
def test_words_outside_the_lexicon_do_not_count(text):
    assert not POL.is_hedged(text)


def test_hedged_is_recorded_on_every_hit_and_never_changes_the_tier():
    hedged = POL.classify_sentence_rules("This may indicate port scanning by an attacker.", TOKENS)
    plain = POL.classify_sentence_rules("This is port scanning by an attacker.", TOKENS)
    assert [h["hedged"] for h in hedged["hits"]] == [True, True] and hedged["hedged"]
    assert [h["hedged"] for h in plain["hits"]] == [False, False]
    assert [h["tier"] for h in hedged["hits"]] == [h["tier"] for h in plain["hits"]] == [1, 1]
    assert POL.sentence_policy_decision(hedged, "x", "lenient")["label"] == "hallucinated"


def test_explanation_hits_are_hedged_only_if_every_occurrence_is():
    text = "This may be port scanning from a host. The flow is port scanning again here."
    hits = POL.explanation_rule_hits(text, TOKENS, use_tier2_rules=False)["hits"]
    assert [h["hedged"] for h in hits] == [False]
    text = "This may be port scanning from a host. The flow recorded 450 packets."
    assert [h["hedged"] for h in POL.explanation_rule_hits(text, TOKENS, use_tier2_rules=False)["hits"]] == [True]


# ── D19 durations ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("duration,sentence,consistent", [
    (92190, "The flow lasted 92 seconds.", False),                   # the old run's 92,190 -> "92 seconds"
    (86, "The flow lasted 86 seconds.", False),
    (36203, "The flow duration was 36,203 microseconds.", True),
    (92190, "That is about 0.09 seconds.", True),                    # rounding to the stated decimals
    (92190, "It took 92 milliseconds.", True),                       # within 10%
    (92190, "It took 0.1 seconds.", True),
    (92190, "It took approximately 1.5 minutes.", False),
    (3_600_000_000, "The flow lasted 1 hour.", True),
    (0, "It lasted 0 seconds.", True),
])
def test_d19_duration_claims(duration, sentence, consistent):
    claims = POL.duration_claims(sentence, duration)
    assert len(claims) == 1 and claims[0]["consistent"] is consistent


def test_d20_stated_duration_is_a_tier2_unit_hit_when_the_rule_engine_has_none():
    s = "The flow lasted 36.2 milliseconds."                 # the old unit pattern misses milliseconds
    assert rule_classify_sentence(s, TOKENS)["label"] == "grounded"
    r = POL.classify_sentence_rules(s, TOKENS, flow_duration_us=36203)
    (hit,) = r["hits"]
    assert (hit["tier"], hit["subtype"], hit["unit_wrong"], hit["key"]) == (2, "unit", False, POL.UNIT_STATED)
    assert POL.sentence_policy_decision(r, s, "strict")["label"] == "hallucinated"
    assert POL.sentence_policy_decision(r, s, "lenient")["label"] == "grounded"


def test_d20_and_d19_wrong_stated_duration_is_tier1_unit_wrong():
    s = "The flow lasted 92 seconds."
    r = POL.classify_sentence_rules(s, TOKENS, flow_duration_us=92190)
    (hit,) = r["hits"]
    assert (hit["tier"], hit["subtype"], hit["unit_wrong"]) == (1, "unit_wrong", True)
    assert POL.sentence_policy_decision(r, s, "lenient")["label"] == "hallucinated"


def test_d20_no_extra_hit_when_the_rule_engine_already_has_a_unit_hit():
    r = POL.classify_sentence_rules("The flow lasted approximately 0.09 seconds.", TOKENS, flow_duration_us=92190)
    assert [h["key"] for h in r["hits"]] == ["Unit assumption — raw flow duration has no guaranteed unit"]


def test_d20_applies_without_a_flow_duration_but_cannot_judge_it():
    s = "It lasted 5 seconds."
    r = POL.classify_sentence_rules(s, TOKENS, flow_duration_us=None)
    assert [(h["tier"], h["subtype"]) for h in r["hits"]] == [(2, "unit")]
    assert r["duration_claims"][0]["consistent"] is None


def test_d20_only_with_the_tier2_layer_at_explanation_level():
    text = "The flow had 450 packets in this record. It lasted 36.2 milliseconds in total."
    on = POL.explanation_rule_hits(text, TOKENS, use_tier2_rules=True, flow_duration_us=36203)
    off = POL.explanation_rule_hits(text, TOKENS, use_tier2_rules=False, flow_duration_us=36203)
    assert [(h["tier"], h["subtype"]) for h in on["hits"]] == [(2, "unit")] and off["hits"] == []


def test_d19_no_claims_without_a_unit():
    assert POL.duration_claims("The rate was 1,500 packets per second and 92190 overall.", 92190) == []


def test_d19_wrong_unit_hit_becomes_tier1_under_both_policies():
    s = "The flow lasted approximately 92 seconds."
    r = POL.classify_sentence_rules(s, TOKENS, flow_duration_us=92190)
    assert r["label"] == "hallucinated" and r["subtype"] == "unit"   # the rule engine alone: Tier 2 unit
    (hit,) = r["hits"]
    assert (hit["tier"], hit["subtype"], hit["unit_wrong"], hit["original_subtype"]) == (1, "unit_wrong", True, "unit")
    for policy in ("strict", "lenient"):
        d = POL.sentence_policy_decision(r, s, policy)
        assert d["label"] == "hallucinated" and d["primary"]["subtype"] == "unit_wrong"


def test_d19_consistent_unit_stays_tier2():
    s = "The flow lasted approximately 0.09 seconds."
    r = POL.classify_sentence_rules(s, TOKENS, flow_duration_us=92190)
    (hit,) = r["hits"]
    assert (hit["tier"], hit["subtype"], hit["unit_wrong"]) == (2, "unit", False)
    assert POL.sentence_policy_decision(r, s, "lenient")["label"] == "grounded"


def test_d19_wrong_duration_without_the_unit_pattern_is_tier1():
    s = "The flow duration is 92 seconds in total."
    r = POL.classify_sentence_rules(s, TOKENS, flow_duration_us=92190)
    assert r["label"] == "grounded"                       # the rule engine alone sees nothing
    assert r["subtypes"] == ["unit_wrong"] and r["hits"][0]["original_key"] == POL.UNIT_STATED
    assert POL.sentence_policy_decision(r, s, "lenient")["label"] == "hallucinated"
    # a correct restatement in microseconds is still a stated unit (D20): Tier 2, not wrong
    ok = "The flow duration was 36,203 microseconds."
    r = POL.classify_sentence_rules(ok, TOKENS, flow_duration_us=36203)
    assert [(h["tier"], h["subtype"], h["unit_wrong"]) for h in r["hits"]] == [(2, "unit", False)]
    assert POL.sentence_policy_decision(r, ok, "lenient")["label"] == "grounded"


def test_d19_explanation_level_runs_with_the_tier2_layer_only():
    text = "The flow had 450 packets in this record. Its duration is 92 seconds in total."
    c1 = POL.explanation_rule_hits(text, TOKENS, use_tier2_rules=True, flow_duration_us=92190)
    assert [h["subtype"] for h in c1["hits"]] == ["unit_wrong"]
    assert POL.explanation_rule_decision(c1, "lenient")["triggered"] is True
    c0 = POL.explanation_rule_hits(text, TOKENS, use_tier2_rules=False, flow_duration_us=92190)
    assert c0["hits"] == [] and c0["duration_claims"] == []


# ── explanation level ─────────────────────────────────────────────────────

ADDED = ("tier", "subtype", "hedged", "key", "unit_wrong", "original_subtype")   # "type" is the engine's own


def strip_added(result):
    return {**result, "matched_rules": [{k: v for k, v in h.items() if k not in ADDED}
                                        for h in result["matched_rules"]]}


@pytest.mark.parametrize("policy", ["strict", "lenient"])
def test_c0_reproduces_the_original_explanation_rules_under_both_policies(policy):
    for text, tokens in corpus():
        legacy = rule_based_detect_explanation(text, tokens)
        new = POL.explanation_rule_decision(
            POL.explanation_rule_hits(text, tokens, use_tier2_rules=False, flow_duration_us=92190), policy)
        assert {k: strip_added(new)[k] for k in legacy} == legacy
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


# ── v2 judge replies ──────────────────────────────────────────────────────

@pytest.mark.parametrize("reply,verdict,tier,subtype,problems", [
    ({"contains_hallucination": True, "confidence": "high", "tier": 1, "subtype": "cve", "reason": "r"},
     True, 1, "cve", []),
    ({"contains_hallucination": True, "tier": "2", "subtype": "unit"}, True, 2, "unit", []),
    ({"contains_hallucination": False, "tier": None, "subtype": None}, False, None, None, []),
    ({"contains_hallucination": False, "tier": "null", "subtype": "null"}, False, None, None, []),
    ({"contains_hallucination": True, "tier": 2, "subtype": "cve"}, True, 2, "cve", ["tier 1"]),
    ({"contains_hallucination": True, "tier": 3, "subtype": "port"}, True, None, "port",
     ["tier is 3", "without a tier"]),
    ({"contains_hallucination": True, "tier": 1, "subtype": "made_up"}, True, 1, "made_up", ["unknown subtype"]),
    ({"contains_hallucination": True, "tier": 1, "subtype": "soft_certainty"}, True, 1, "soft_certainty",
     ["unknown subtype"]),
    ({"contains_hallucination": True, "tier": None}, True, None, None, ["without a tier"]),
    ({"contains_hallucination": "yes", "tier": 1, "subtype": "cve"}, None, 1, "cve", ["contains_hallucination"]),
])
def test_parse_v2_explanation_reply(reply, verdict, tier, subtype, problems):
    p = POL.parse_v2_reply(reply, "explanation")
    assert (p["verdict"], p["tier"], p["subtype"]) == (verdict, tier, subtype)
    assert len(p["reply_problems"]) == len(problems)
    for want, got in zip(problems, p["reply_problems"]):
        assert want in got


@pytest.mark.parametrize("subtype,tier", [("other_fabrication", 1), ("other_knowledge", 2)])
def test_d21_catch_all_subtypes_need_a_note(subtype, tier):
    with_note = POL.parse_v2_reply({"contains_hallucination": True, "tier": tier, "subtype": subtype,
                                    "note": "invented hostname srv-db-01"}, "explanation")
    assert with_note["reply_problems"] == [] and with_note["catch_all"] and with_note["note"]
    for note in (None, "", "  ", "null"):
        p = POL.parse_v2_reply({"label": "hallucinated", "tier": tier, "subtype": subtype, "note": note}, "sentence")
        assert any("needs a short free-text note" in x for x in p["reply_problems"])
    assert POL.is_catch_all(subtype) and not POL.is_catch_all("cve") and not POL.is_catch_all(None)


def test_d21_no_rule_ever_produces_a_catch_all():
    for text, tokens in corpus():
        for s in P.split_sentences(text):
            assert not set(POL.classify_sentence_rules(s, tokens, 92190)["subtypes"]) & set(POL.CATCH_ALL_SUBTYPES)


def test_parse_v2_sentence_reply():
    p = POL.parse_v2_reply({"label": "hallucinated", "confidence": "low", "tier": 2, "subtype": "baseline",
                            "reason": "r"}, "sentence")
    assert (p["verdict"], p["tier"], p["subtype"], p["hallucination_type"], p["reply_problems"]) == \
        (True, 2, "baseline", "external_knowledge", [])
    assert POL.parse_v2_reply({"label": "grounded", "tier": None, "subtype": None}, "sentence")["verdict"] is False
    assert POL.parse_v2_reply({"label": "maybe"}, "sentence")["reply_problems"]


# ── options: C0-C3, D15, prompt names ─────────────────────────────────────

@pytest.mark.parametrize("cfg,policy,tier2,judge", [
    ("C0", "strict", False, "v1"), ("C0", "lenient", False, "v1"),
    ("C1", "strict", True, "v1"), ("C1", "lenient", True, "v1"),
    ("C2", "strict", False, "v2-strict"), ("C2", "lenient", False, "v2-lenient"),
    ("C3", "strict", True, "v2-strict"), ("C3", "lenient", True, "v2-lenient"),
])
def test_detection_configs(cfg, policy, tier2, judge):
    assert POL.detection_options(cfg, policy) == {"use_tier2_rules": tier2, "judge_prompt": judge, "policy": policy}


def test_expected_v2_prompt_names_are_the_paper_sides():
    assert POL.EXPECTED_V2_PROMPTS == sorted([
        "detect_explanation_system_v2_strict.txt", "detect_explanation_system_v2_lenient.txt",
        "detect_explanation_template_v2.txt", "localize_sentence_system_v2_strict.txt",
        "localize_sentence_system_v2_lenient.txt", "localize_sentence_template_v2.txt", "generate_system_v2.txt"])


# D22: the paper side's v2 prompts, byte-exact as delivered. Never edit in place: new wording = new file.
V2_PROMPT_PINS = {
    "detect_explanation_system_v2_lenient.txt": "4183b2026e0b6f7dba27f4e065e5f08e067b59e6d62cb387327414077e01040b",
    "detect_explanation_system_v2_strict.txt": "9fa8ae5a44a8187a9242287e2d5e02933b516bb0b3ccdfeb280499e09b9a1aee",
    "detect_explanation_template_v2.txt": "01d628aec0cbd068967897dc87a6960e97825c6bc58ca29b30f9ce720d80a8ce",
    "generate_system_v2.txt": "8f1c9d795b85518539a468a447af6d252f2eb5b2b16cd5d4846c705129bf920d",
    "localize_sentence_system_v2_lenient.txt": "9b080ad8366a0525edf9e772076de7d07e8ddb2e79679414948a6a1de9016651",
    "localize_sentence_system_v2_strict.txt": "8bc188cf5ee136f43aa53082c5c9687e77796017c97b1994ae7d413926ee77ed",
    "localize_sentence_template_v2.txt": "f1510d3cff7065c0308118508c7b35f73585e6ee5a455d83a951ed95722b7827",
}


def test_v2_prompts_are_present_and_unchanged():
    from hallucination_pipeline.prompt_store import prompt_hashes
    hashes = prompt_hashes()
    assert sorted(V2_PROMPT_PINS) == POL.EXPECTED_V2_PROMPTS
    for name, digest in V2_PROMPT_PINS.items():
        assert hashes[name] == digest, f"{name} was edited in place; add a new file instead"


def test_all_prompts_resolve_through_the_registry():
    assert POL.judge_prompt_files("v1") == ("detect_explanation_system.txt", "detect_explanation_template.txt")
    assert POL.sentence_prompt_files("v1") == ("localize_sentence_system.txt", None)
    for policy in ("strict", "lenient"):
        assert POL.judge_prompt_files(f"v2-{policy}") == (f"detect_explanation_system_v2_{policy}.txt",
                                                          "detect_explanation_template_v2.txt")
        assert POL.sentence_prompt_files(f"v2-{policy}") == (f"localize_sentence_system_v2_{policy}.txt",
                                                             "localize_sentence_template_v2.txt")
    with pytest.raises(ValueError):
        POL.judge_prompt_files("v3")


def test_v2_templates_format_with_their_placeholders_only():
    e = load_prompt("detect_explanation_template_v2.txt").format(evidence="EVID", explanation="EXPL")
    s = load_prompt("localize_sentence_template_v2.txt").format(evidence="EVID", sentence="SENT")
    for text, filled in ((e, "EXPL"), (s, "SENT")):
        assert "EVID" in text and filled in text
        start = text.index("{")
        reply = json.loads(text[start:].replace("true or false", "true").replace(
            '"high" or "medium" or "low"', '"high"').replace("1 or 2 or null", "1").replace(
            '"one subtype name from the lists above" or null', '"cve"').replace(
            'null or "a few words (REQUIRED when the subtype is other_fabrication or other_knowledge)"', "null").replace(
            '"hallucinated" or "grounded"', '"hallucinated"'))
        assert set(reply) - {"contains_hallucination", "label"} == {"confidence", "tier", "subtype", "reason", "note"}
    with pytest.raises(KeyError):
        load_prompt("detect_explanation_template_v2.txt").format(evidence="E")


def test_a_missing_v2_prompt_gives_a_clear_error(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "PROMPTS_DIR", tmp_path)
    for name in ("v2-strict", "v2-lenient"):
        with pytest.raises(FileNotFoundError, match="supplied by the paper side"):
            POL.judge_prompt_files(name)
        with pytest.raises(FileNotFoundError, match="supplied by the paper side"):
            POL.sentence_prompt_files(name)


def test_d15_escalation_option():
    clean, soft, hit = {"triggered": False}, {"triggered": None}, {"triggered": True}
    assert should_invoke_llm(clean, "Benign", "all") and should_invoke_llm(clean, "DoS", "all")
    assert not should_invoke_llm(clean, "Benign", "attack_only") and should_invoke_llm(clean, "DoS", "attack_only")
    assert should_invoke_llm(soft, "Benign", "attack_only") and not should_invoke_llm(hit, "DoS", "all")
    assert not should_invoke_llm(clean, "Benign")                       # default = legacy
    with pytest.raises(ValueError):
        should_invoke_llm(clean, "DoS", "sometimes")


# ── wired into Phase 2 and Phase 3 ────────────────────────────────────────

ALERT = {"alert_id": "A0001", "alert_type": "DoS Hulk", "label_coarse": "DoS",
         "evidence": "Destination Port: 80\nFlow Duration: 92190\nForward Packets: 450",
         "evidence_tokens": ["450", "80", "92190"]}
BENIGN = {**ALERT, "alert_type": "BENIGN", "label_coarse": "Benign"}
LEGACY_KEYS = {"alert_id", "alert_type", "contains_hallucination", "confidence", "hallucination_type",
               "reason", "matched_rules", "detection_method", "gold_label"}
CLEAN = "The flow recorded 450 forward packets in this record."


def expl(text, alert=ALERT):
    return {"alert_id": "A0001", "alert_type": alert["alert_type"], "explanation": text}


def test_phase2_without_policy_keeps_the_original_record_and_escalation():
    rec = detect_explanation(FakeGemini(), ALERT, expl("An attacker sent 450 packets."), sleep=False)
    assert set(rec) == LEGACY_KEYS and rec["detection_method"] == "rule"
    assert detect_explanation(FakeGemini(), BENIGN, expl(CLEAN, BENIGN), sleep=False)["detection_method"] == "rule"
    with pytest.raises(ValueError):
        detect_explanation(FakeGemini(), ALERT, expl("x"), sleep=False, use_tier2_rules=True)


def test_phase2_with_policy_escalates_every_clean_explanation_by_default():
    rec = detect_explanation(FakeGemini(), BENIGN, expl(CLEAN, BENIGN), sleep=False, policy="strict")
    assert rec["escalate_clean"] == "all" and rec["detection_method"] != "rule"
    old = detect_explanation(FakeGemini(), BENIGN, expl(CLEAN, BENIGN), sleep=False, policy="strict",
                             escalate_clean="attack_only")
    assert old["detection_method"] == "rule"


def test_phase2_with_policy_records_tier_hits_and_duration_claims():
    text = "The flow had 450 packets. It lasted approximately 0.09 seconds in total."
    strict = detect_explanation(FakeGemini(), ALERT, expl(text), sleep=False, policy="strict", use_tier2_rules=True)
    assert (strict["contains_hallucination"], strict["tier"], strict["subtype"]) == (True, 2, "unit")
    assert strict["duration_claims"][0]["consistent"] is True
    wrong = "The flow had 450 packets. It lasted approximately 92 seconds in total."
    rec = detect_explanation(FakeGemini(), ALERT, expl(wrong), sleep=False, policy="lenient", use_tier2_rules=True)
    assert (rec["contains_hallucination"], rec["tier"], rec["subtype"]) == (True, 1, "unit_wrong")
    assert set(rec) >= LEGACY_KEYS | {"policy", "use_tier2_rules", "judge_prompt", "escalate_clean", "tier",
                                      "subtype", "rule_hits", "uncounted_rules", "duration_claims"}


def test_v2_catch_all_reply_is_recorded_with_its_note(v2_prompts):
    client = Reply({"contains_hallucination": True, "confidence": "low", "tier": 1, "subtype": "other_fabrication",
                    "note": "invented hostname", "reason": "r"})
    rec = detect_explanation(client, ALERT, expl(CLEAN), sleep=False, policy="lenient", judge_prompt="v2-lenient")
    assert rec["contains_hallucination"] is True and rec["subtype"] == "other_fabrication"
    assert rec["judge"]["catch_all"] is True and rec["judge"]["note"] == "invented hostname"


def test_phase3_sentence_records_all_new_fields():
    s = "The flow lasted approximately 92 seconds based on the duration value."
    legacy, _ = classify_sentence(FakeGemini(), ALERT, "S1", s, sleep=False)
    assert "tier" not in legacy and legacy["predicted_label"] == "hallucinated"
    rec, used = classify_sentence(FakeGemini(), ALERT, "S1", s, sleep=False, policy="lenient")
    assert not used and (rec["predicted_label"], rec["tier"], rec["subtype"]) == ("hallucinated", 1, "unit_wrong")
    assert rec["detection_method"] == "rule_unit_check" and rec["subtypes"] == ["unit_wrong"]
    assert (rec["rule_label"], rec["rule_tier"], rec["rule_subtype"]) == ("hallucinated", 2, "unit")
    assert rec["hedged"] is False and rec["duration_claims"][0]["consistent"] is False
    ok = "The flow lasted approximately 0.09 seconds based on the duration value."
    rec, _ = classify_sentence(FakeGemini(), ALERT, "S1", ok, sleep=False, policy="lenient")
    assert rec["predicted_label"] == "grounded" and "not counted under the lenient policy" in rec["reason"]


# ── v2 prompts end to end (temporary prompt dir; the real v2 files come from the paper side) ──

class Reply:
    """A client that answers every call with one fixed JSON reply and remembers the prompts."""

    def __init__(self, reply: dict):
        self.models, self.reply, self.prompts = self, reply, []

    def generate_content(self, model, contents, config=None):
        self.prompts.append(contents)
        return fakes._Resp(json.dumps(self.reply))


@pytest.fixture
def v2_prompts(tmp_path, monkeypatch):
    d = tmp_path / "prompts"
    shutil.copytree(config.PROMPTS_DIR, d)
    for name in POL.EXPECTED_V2_PROMPTS:
        (d / name).write_text(f"SYSTEM {name}\n", encoding="utf-8")
    (d / "detect_explanation_template_v2.txt").write_text(
        "EVIDENCE:\n{evidence}\nEXPLANATION:\n{explanation}\nReply as {{\"tier\": 1}}\n", encoding="utf-8")
    (d / "localize_sentence_template_v2.txt").write_text(
        "EVIDENCE:\n{evidence}\nSENTENCE TO JUDGE:\n{sentence}\n", encoding="utf-8")
    monkeypatch.setattr(config, "PROMPTS_DIR", d)
    load_prompt.cache_clear()
    yield d
    load_prompt.cache_clear()


def test_v2_explanation_judge_reply_is_parsed_and_the_policy_applied(v2_prompts):
    reply = {"contains_hallucination": True, "confidence": "high", "tier": 2, "subtype": "baseline", "reason": "r"}
    for policy, counted in (("strict", True), ("lenient", False)):
        client = Reply(reply)
        rec = detect_explanation(client, ALERT, expl(CLEAN), sleep=False, policy=policy, judge_prompt=f"v2-{policy}")
        assert rec["contains_hallucination"] is counted and (rec["tier"], rec["subtype"]) == (2, "baseline")
        j = rec["judge"]
        assert (j["verdict"], j["tier"], j["subtype"], j["reply_problems"], j["catch_all"], j["note"]) == \
            (True, 2, "baseline", [], False, None)
        assert j["prompt"] == f"v2-{policy}" and j["reply"]["subtype"] == "baseline"
        assert rec["policy_version"] == POL.POLICY_VERSION and rec["tier_map_sha256"]
        assert client.prompts[0].startswith(f"SYSTEM detect_explanation_system_v2_{policy}.txt")
        assert 'Reply as {"tier": 1}' in client.prompts[0] and CLEAN in client.prompts[0]


def test_v2_sentence_judge_uses_the_template_file(v2_prompts):
    s = "This is definitely unusual for a flow of this size."
    client = Reply({"label": "hallucinated", "confidence": "medium", "tier": 1, "subtype": "hard_certainty",
                    "reason": "r"})
    rec, used = classify_sentence(client, ALERT, "S1", s, sleep=False, policy="lenient", sentence_prompt="v2-lenient")
    assert used and (rec["predicted_label"], rec["tier"], rec["subtype"]) == ("hallucinated", 1, "hard_certainty")
    assert client.prompts[0] == ("SYSTEM localize_sentence_system_v2_lenient.txt\n\nEVIDENCE:\n" + ALERT["evidence"]
                                 + "\nSENTENCE TO JUDGE:\n" + s + "\n")
    t2 = Reply({"label": "hallucinated", "tier": 2, "subtype": "baseline"})
    rec, _ = classify_sentence(t2, ALERT, "S1", s, sleep=False, policy="lenient", sentence_prompt="v2-lenient")
    assert rec["predicted_label"] == "grounded" and rec["judge"]["tier"] == 2


def test_v1_sentence_message_is_unchanged(v2_prompts):
    client = Reply({"label": "grounded"})
    classify_sentence(client, ALERT, "S1", "This is definitely unusual for a flow.", sleep=False)
    assert client.prompts[0].endswith('Respond ONLY with this JSON (no markdown):\n'
                                      '{"label":"...","confidence":"...","hallucination_type":"...","reason":"..."}')


def test_v2_template_with_wrong_placeholders_is_refused(v2_prompts):
    (v2_prompts / "localize_sentence_template_v2.txt").write_text("{evidence} {text}", encoding="utf-8")
    with pytest.raises(ValueError, match="placeholders"):
        POL.sentence_prompt_files("v2-strict")


# ── generated docs and the handoff bundle ─────────────────────────────────

def test_generated_docs_are_up_to_date():
    import export_rule_tiers
    for path, text in export_rule_tiers.documents().items():
        assert path.read_text(encoding="utf-8") == text, "run: python tools/export_rule_tiers.py"
    assert len(export_rule_tiers.LAYERS) == len(POL.RULE_TIERS)


def test_p1b_bundle_contents(tmp_path):
    import zipfile
    from make_outbox import make_outbox
    zpath = make_outbox("P1b", None, tmp_path, "ok", label="abc123", extra={"reproduce_frozen_report.md": "x"})
    with zipfile.ZipFile(zpath) as z:
        assert sorted(z.namelist()) == ["DECISIONS.md", "RULE_TIERS.md", "SUBTYPES.md",
                                        "reproduce_frozen_report.md", "test_summary.txt"]
    with pytest.raises(ValueError):
        make_outbox("P1", None, tmp_path, "ok")

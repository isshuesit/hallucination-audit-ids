"""docs/KNOWN_RULE_GAPS.md: each test shows the frozen rules MISS a claim the annotation guide counts.

If one of these starts failing, a rule now catches the gap: that is a rule change (bump RULES_VERSION,
add a DECISIONS entry) and the gap must be removed from docs/KNOWN_RULE_GAPS.md.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hallucination_pipeline import policy as POL

GAPS = [  # id, sentence, evidence tokens, what the guide says it is
    ("G1", "Traffic used ports 80 and 443 during this flow.", {"80"}, "port_not_in_evidence"),
    ("G2", "Traffic went to port 80/443 during this flow.", {"80"}, "port_not_in_evidence"),
    ("G3", "The attacker is probing this host repeatedly.", {"80"}, "threat_actor"),
    ("G4", "Port 22, which is SSH, was the destination.", {"22"}, "port"),
]


@pytest.mark.parametrize("gap,sentence,tokens,guide_subtype", GAPS, ids=[g[0] for g in GAPS])
def test_rules_miss_the_gap(gap, sentence, tokens, guide_subtype):
    r = POL.classify_sentence_rules(sentence, tokens, flow_duration_us=92190)
    assert r["label"] == "grounded" and r["hits"] == [], f"{gap} is now caught: update docs/KNOWN_RULE_GAPS.md"
    for policy in ("strict", "lenient"):
        assert POL.sentence_policy_decision(r, sentence, policy)["label"] == "grounded"
    rp = POL.explanation_rule_hits(sentence, tokens, use_tier2_rules=True, flow_duration_us=92190)
    assert rp["hits"] == [] and POL.explanation_rule_decision(rp, "strict")["triggered"] is False
    assert guide_subtype in POL.SUBTYPES                 # the guide's answer is a valid subtype


def test_the_caught_variant_of_g3_is_caught():
    r = POL.classify_sentence_rules("An attacker is probing this host repeatedly.", {"80"})
    assert r["subtypes"] == ["threat_actor"]


def test_every_gap_is_documented():
    doc = open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs",
                            "KNOWN_RULE_GAPS.md"), encoding="utf-8").read()
    for gap, sentence, _, subtype in GAPS:
        assert f"| {gap} |" in doc and sentence in doc and f"`{subtype}`" in doc

"""
Tests for the rule-based hallucination classifiers.

Test cases are drawn directly from the worked examples in the original
project's ANNOTATION_GUIDE.md, not invented for this rebuild - this checks
the rebuilt rule engine agrees with the same standard the original project
defined, not a new one.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hallucination_pipeline.detection import rule_classify_sentence, rule_based_detect_explanation


def test_named_cve_is_factual_hallucination():
    # ANNOTATION_GUIDE.md: "exploits CVE-2017-0144" when evidence has no CVE
    sentence = "This flow exploits CVE-2017-0144 to gain access."
    result = rule_classify_sentence(sentence, evidence_tokens=set())
    assert result["label"] == "hallucinated"
    assert result["hallucination_type"] == "factual"


def test_attacker_targeting_claim_is_reasoning_hallucination():
    # ANNOTATION_GUIDE.md: "attacker is targeting the database server" when
    # only port 22 is mentioned. NOTE: the original regex only matches
    # "an attacker" (indefinite article), not "the attacker" - a real,
    # narrow gap in the original pattern, preserved here rather than
    # silently widened, since changing it would change pipeline behavior
    # away from what produced the paper's reported numbers.
    sentence = "An attacker is targeting the database server through this connection."
    result = rule_classify_sentence(sentence, evidence_tokens={"22"})
    assert result["label"] == "hallucinated"
    assert result["hallucination_type"] == "reasoning"


def test_attacker_with_definite_article_is_a_known_gap():
    # Documents the gap found above: "the attacker" (vs "an attacker") is
    # NOT caught by REASONING_PATTERNS's threat-actor-framing rule. This is
    # a real limitation in the original pipeline, not a porting error -
    # confirmed by testing the exact same regex against both phrasings.
    sentence = "The attacker is targeting the database server through this connection."
    result = rule_classify_sentence(sentence, evidence_tokens={"22"})
    assert result["label"] == "grounded"  # documents the gap, does not endorse it


def test_definitive_compromise_claim_is_certainty_hallucination():
    sentence = "The server has been compromised by this traffic pattern."
    result = rule_classify_sentence(sentence, evidence_tokens=set())
    assert result["label"] == "hallucinated"
    assert result["hallucination_type"] == "certainty"


def test_grounded_restatement_of_evidence_passes():
    # ANNOTATION_GUIDE.md: "repeated failed logins -> brute force" type
    # restatement using evidence numbers should NOT be flagged.
    sentence = "The flow shows 450 SYN flag counts directed at destination port 22."
    result = rule_classify_sentence(sentence, evidence_tokens={"450", "22"})
    assert result["label"] == "grounded"


def test_hedged_inference_over_pure_numeric_observation_is_grounded():
    # A hedged statement that only restates numeric evidence, with no named
    # attack technique, should be grounded.
    sentence = "This pattern of flag counts may indicate elevated connection activity."
    result = rule_classify_sentence(sentence, evidence_tokens=set())
    assert result["label"] == "grounded"


def test_hedging_does_not_excuse_a_named_attack_technique():
    # Hedging language does NOT suppress REASONING_PATTERNS - a named
    # attack technique (here, "port scanning") is flagged even when hedged,
    # since the pattern matches on the technique name itself, not on
    # certainty language. This is intended behavior, not a bug.
    sentence = "This pattern of flag counts may indicate port scanning activity."
    result = rule_classify_sentence(sentence, evidence_tokens=set())
    assert result["label"] == "hallucinated"
    assert result["hallucination_type"] == "reasoning"


def test_port_service_mapping_is_external_knowledge():
    # "port 443 serves HTTPS" - true, but not derivable from raw numbers
    sentence = "Port 443 is commonly used for HTTPS traffic."
    result = rule_classify_sentence(sentence, evidence_tokens={"443"})
    assert result["label"] == "hallucinated"
    assert result["hallucination_type"] == "external_knowledge"


def test_protocol_named_without_matching_port_is_hallucination():
    sentence = "The connection uses HTTPS encryption for this session."
    result = rule_classify_sentence(sentence, evidence_tokens={"22"})  # no 443
    assert result["label"] == "hallucinated"


def test_protocol_named_with_matching_port_still_flagged_for_encryption_claim():
    # Port matches, but "encryption" itself is a separate external-knowledge
    # pattern (traffic characterized as encrypted is not derivable from
    # flow numbers alone) - this should still be flagged, just for a
    # different reason than protocol injection.
    sentence = "The connection on port 443 uses encryption."
    result = rule_classify_sentence(sentence, evidence_tokens={"443"})
    assert result["label"] == "hallucinated"
    assert result["hallucination_type"] in ("external_knowledge", "factual")


def test_unit_conversion_is_external_knowledge():
    sentence = "The flow lasted approximately 17 hours based on the duration value."
    result = rule_classify_sentence(sentence, evidence_tokens={"61200000"})
    assert result["label"] == "hallucinated"
    assert result["hallucination_type"] == "external_knowledge"


def test_soft_certainty_language_without_named_technique_is_ambiguous():
    sentence = "This must be unusual activity based on the pattern."
    result = rule_classify_sentence(sentence, evidence_tokens=set())
    assert result["label"] == "ambiguous"
    assert result["hallucination_type"] == "certainty"


def test_explanation_level_detection_triggers_on_factual_pattern():
    explanation = (
        "The flow shows 450 SYN packets to port 22. "
        "This is consistent with attempted exploitation of CVE-2021-44228."
    )
    result = rule_based_detect_explanation(explanation, evidence_tokens=["450", "22"])
    assert result["triggered"] is True
    assert result["hallucination_type"] == "factual"


def test_explanation_level_clean_explanation_not_triggered():
    explanation = "The flow shows 450 SYN flag counts directed at destination port 22."
    result = rule_based_detect_explanation(explanation, evidence_tokens=["450", "22"])
    assert result["triggered"] is False


def test_explanation_level_soft_certainty_escalates_to_llm():
    explanation = "This traffic pattern is definitely worth investigating further."
    result = rule_based_detect_explanation(explanation, evidence_tokens=[])
    assert result["triggered"] is None  # medium confidence -> escalate

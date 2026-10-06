"""Regression tests for the sentence-alignment bugs (original BUG 3 and the
qualitative-example misalignment found during verification)."""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest
from hallucination_pipeline.evaluation import corrected_sentence_for, evaluate_explanation_level, gold_to_int
from hallucination_pipeline.impact_analysis import analyze_alerts, aggregate


def test_removed_sentence_is_reported_as_removed():
    assert corrected_sentence_for(0, {"S1": "REMOVE"}, ["kept"]) == "[REMOVED]"


def test_alignment_survives_an_earlier_removal():
    masks = {"S1": "REMOVE", "S2": "KEEP", "S3": "QUALIFY"}
    corrected = ["second sentence", "third sentence rewritten"]
    # indexing the corrected list by the original number (2) would be out of range / wrong
    assert corrected_sentence_for(2, masks, corrected) == "third sentence rewritten"
    assert corrected_sentence_for(1, masks, corrected) == "second sentence"


def _fixture():
    alerts = [{"alert_id": "A1", "evidence": "Destination Port: 22", "evidence_tokens": ["22"]}]
    corrected = [{
        "alert_id": "A1", "alert_type": "DoS",
        "original_explanation": ["Removed sentence goes here.", "Qualified sentence goes here."],
        "corrected_explanation": ["Rewritten qualified sentence."],
        "sentences_removed": 1, "sentences_qualified": 1,
    }]
    preds = [
        {"alert_id": "A1", "sentence_id": "S1", "gold_label": "grounded"},
        {"alert_id": "A1", "sentence_id": "S2", "gold_label": "hallucinated"},
    ]
    masks = [
        {"alert_id": "A1", "sentence_id": "S1", "action": "REMOVE", "hallucination_type": "factual"},
        {"alert_id": "A1", "sentence_id": "S2", "action": "QUALIFY", "hallucination_type": "reasoning"},
    ]
    return alerts, corrected, preds, masks


def test_qualify_pair_is_matched_to_the_right_rewrite_after_a_removal():
    alerts, corrected, preds, masks = _fixture()
    _, pairs, _ = analyze_alerts(alerts, corrected, preds, masks)
    assert len(pairs) == 1
    assert pairs[0]["original"] == "Qualified sentence goes here."
    assert pairs[0]["corrected"] == "Rewritten qualified sentence."


def test_false_removal_is_audited_with_the_gold_label():
    alerts, corrected, preds, masks = _fixture()
    results, pairs, stats = analyze_alerts(alerts, corrected, preds, masks)
    assert stats["factual"]["remove_was_grounded"] == 1     # gold said S1 was grounded
    impact = aggregate(results, pairs, stats, 0, 0)
    assert impact["information_quality"]["false_removals"] == 1
    assert impact["information_quality"]["false_removal_rate"] == 1.0


def test_gold_label_strings_are_not_all_treated_as_hallucinated():
    # the original code treated the string 'grounded' as truthy -> hallucinated
    assert gold_to_int("grounded") == 0 and gold_to_int("hallucinated") == 1
    assert gold_to_int(False) == 0 and gold_to_int(True) == 1


def test_explanation_metrics_with_string_gold_labels():
    det = [
        {"contains_hallucination": True,  "gold_label": "hallucinated"},
        {"contains_hallucination": True,  "gold_label": "grounded"},
        {"contains_hallucination": False, "gold_label": "grounded"},
        {"contains_hallucination": False, "gold_label": "hallucinated"},
    ]
    m = evaluate_explanation_level(det)
    assert (m["precision"], m["recall"]) == (0.5, 0.5) and m["true_hallucinated"] == 2


def test_unrecognised_gold_label_fails_loudly():
    with pytest.raises(ValueError):
        gold_to_int("maybe")

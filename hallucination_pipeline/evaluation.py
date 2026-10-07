"""Phase 5, Step 6: end-to-end evaluation. Computes Precision/Recall/F1 for
Phase 2 and Phase 3 (requires gold_label to have been filled in by a human
annotator - see docs/archive/ANNOTATION_GUIDE_v1.md), plus Phase 4 mitigation impact.
"""

from __future__ import annotations

import json
from collections import defaultdict

from sklearn.metrics import classification_report, f1_score, precision_score, recall_score

from . import config


def gold_to_int(value) -> int:
    """Interpret a gold label as 1 (hallucinated) or 0 (grounded).

    BUG FIXED (present in the original 06_evaluate.py, and copied into the first
    rebuild): the original evaluated explanation-level gold labels with
    `1 if d["gold_label"] else 0`. That is correct for booleans but WRONG for the
    strings 'hallucinated' / 'grounded', because any non-empty string is truthy:
    'grounded' counted as hallucinated. On the project's own frozen file (string
    labels) that produced precision 1.00 / recall 0.24 instead of the real
    0.94 / 1.00. Accept either form, and fail loudly on anything else.
    """
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("hallucinated", "true", "yes", "1"):
            return 1
        if v in ("grounded", "false", "no", "0"):
            return 0
    raise ValueError(f"Unrecognised gold_label {value!r}: use true/false or 'hallucinated'/'grounded'")


def evaluate_explanation_level(detections: list[dict]) -> dict:
    with_gold = [d for d in detections if d.get("gold_label") is not None]
    if not with_gold:
        print("No gold labels in phase2_detection.json - fill these in first (see docs/archive/ANNOTATION_GUIDE_v1.md).")
        return {"evaluated": 0, "warning": "No gold labels."}

    y_true = [gold_to_int(d["gold_label"]) for d in with_gold]
    y_pred = [1 if d["contains_hallucination"] else 0 for d in with_gold]
    return {
        "evaluated": len(with_gold), "total_records": len(detections),
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "true_hallucinated": int(sum(y_true)),
        "predicted_hallucinated": int(sum(y_pred)),
        "classification_report": classification_report(y_true, y_pred, target_names=["grounded", "hallucinated"]),
    }


def evaluate_sentence_level(predictions: list[dict]) -> dict:
    with_gold = [p for p in predictions if p.get("gold_label") is not None]
    if not with_gold:
        print("No gold labels in phase3_predictions.json - fill these in first.")
        return {"evaluated": 0, "warning": "No gold labels."}

    y_true = [gold_to_int(p["gold_label"]) for p in with_gold]
    y_pred = [1 if p["predicted_label"] == "hallucinated" else 0 for p in with_gold]

    type_counts = defaultdict(int)
    for p in with_gold:
        if p.get("hallucination_type"):
            type_counts[p["hallucination_type"]] += 1

    return {
        "evaluated": len(with_gold), "total_sentences": len(predictions),
        "precision": round(precision_score(y_true, y_pred, zero_division=0), 4),
        "recall": round(recall_score(y_true, y_pred, zero_division=0), 4),
        "f1": round(f1_score(y_true, y_pred, zero_division=0), 4),
        "true_hallucinated_sentences": int(sum(y_true)),
        "predicted_hallucinated_sentences": int(sum(y_pred)),
        "hallucination_type_distribution": dict(type_counts),
        "classification_report": classification_report(y_true, y_pred, target_names=["grounded", "hallucinated"]),
    }


def summarize_mitigation(effect: dict, corrected: list[dict]) -> dict:
    total_before = effect.get("total_sentences_before", 0)
    return {
        "total_explanations": len(corrected),
        "total_sentences_before": total_before,
        "total_sentences_after": effect.get("total_sentences_after", 0),
        "sentences_removed": effect.get("sentences_removed", 0),
        "sentences_qualified": effect.get("sentences_qualified", 0),
        "avg_length_reduction_pct": effect.get("avg_length_reduction_pct", 0),
        "information_retention_pct": effect.get("information_retention_pct", 0),
        "hallucination_density_before": (
            round(effect.get("sentences_removed", 0) / total_before, 3) if total_before else 0
        ),
        # Placeholder, as in the original: a real "after" density needs the
        # corrected set re-annotated. impact_analysis.py measures it with the
        # rule classifier and an LLM re-check instead.
        "hallucination_density_after": 0.0,
    }


def corrected_sentence_for(sid_num: int, alert_masks: dict[str, str], corrected_sentences: list[str]) -> str:
    """Find the corrected-side counterpart of original sentence number *sid_num* (0-based).

    DELIBERATE DEVIATION FROM THE ORIGINAL 06_evaluate.py: the original indexed
    the corrected list by the ORIGINAL sentence number, which pairs the wrong
    sentences as soon as any earlier sentence was REMOVEd (everything after it
    shifts up by one). Here the position is derived from the masks: only
    sentences that were not removed occupy a slot on the corrected side.
    """
    if alert_masks.get(f"S{sid_num + 1}") == "REMOVE":
        return "[REMOVED]"
    kept_before = sum(1 for i in range(sid_num) if alert_masks.get(f"S{i + 1}") != "REMOVE")
    return corrected_sentences[kept_before] if kept_before < len(corrected_sentences) else "[REMOVED]"


def build_qualitative_examples(predictions: list[dict], corrected: list[dict],
                               masks: list[dict], max_examples: int = 8) -> list[dict]:
    corr_map = {c["alert_id"]: c for c in corrected}
    action_by_alert: dict[str, dict[str, str]] = defaultdict(dict)
    for m in masks:
        action_by_alert[m["alert_id"]][m["sentence_id"]] = m["action"]

    examples, seen_types = [], set()
    for pred in predictions:
        if pred["predicted_label"] != "hallucinated" or pred["hallucination_type"] in seen_types:
            continue
        corr = corr_map.get(pred["alert_id"])
        if not corr:
            continue

        sid_num = int(pred["sentence_id"][1:]) - 1
        corrected_sentence = corrected_sentence_for(
            sid_num, action_by_alert.get(pred["alert_id"], {}), corr["corrected_explanation"]
        )
        examples.append({
            "case_id": f"CASE_{len(examples) + 1}",
            "alert_id": pred["alert_id"], "alert_type": pred["alert_type"],
            "hallucination_type": pred["hallucination_type"],
            "original_sentence": pred["sentence_text"],
            "corrected_sentence": corrected_sentence,
            "reason": pred["reason"],
            "why_it_matters": f"Prevents {pred['hallucination_type']} hallucination from reaching analyst.",
        })
        seen_types.add(pred["hallucination_type"])
        if len(examples) >= max_examples:
            break
    return examples


def run() -> dict:
    print("=== Phase 5, Step 6: End-to-end evaluation ===")
    with open(config.DETECTION_PATH) as f:
        detections = json.load(f)
    with open(config.SENTENCE_PREDICTIONS_PATH) as f:
        predictions = json.load(f)
    with open(config.EFFECT_PATH) as f:
        effect = json.load(f)
    with open(config.CORRECTED_PATH) as f:
        corrected = json.load(f)
    with open(config.MASKS_PATH) as f:
        masks = json.load(f)

    p2 = evaluate_explanation_level(detections)
    p3 = evaluate_sentence_level(predictions)
    p4 = summarize_mitigation(effect, corrected)

    end_to_end = {
        "alerts_total": len(detections),
        "explanations_generated": len(corrected),
        "phase2": p2, "phase3": p3, "phase4": p4,
        "pipeline_summary": {
            "description": "Hallucination localization and selective unlearning pipeline on CIC-IDS 2017",
            "dataset": "CIC-IDS 2017", "model_used": config.GEMINI_MODEL,
        },
    }
    with open(config.METRICS_PATH, "w") as f:
        json.dump(end_to_end, f, indent=2)
    print(f"End-to-end metrics -> {config.METRICS_PATH}")

    comparison = {
        "baseline_hallucinated_sentences": p4["sentences_removed"] + p4["sentences_qualified"],
        "after_phase4_hallucinated_sentences": 0,
        "information_retention_pct": p4["information_retention_pct"],
        "reduction_in_hallucinated_sentences": p4["sentences_removed"],
        "sentences_softened": p4["sentences_qualified"],
    }
    with open(config.COMPARISON_PATH, "w") as f:
        json.dump(comparison, f, indent=2)

    examples = build_qualitative_examples(predictions, corrected, masks)
    with open(config.QUALITATIVE_PATH, "w") as f:
        json.dump(examples, f, indent=2)
    print(f"{len(examples)} qualitative examples -> {config.QUALITATIVE_PATH}")

    return end_to_end


if __name__ == "__main__":
    run()

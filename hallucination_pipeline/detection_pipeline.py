"""
Phase 2, Step 3: explanation-level hallucination detection (hybrid).
Phase 3, Step 4: sentence-level hallucination localization (hybrid).

Both use the same pattern: deterministic rules run first (free, auditable);
the LLM judge is only called when the rules cannot decide. Judge prompts are
loaded verbatim from prompts/ - they are part of the experimental protocol.

DATASET-VERSION HAZARD: the "clean on an attack-class alert -> double-check
with the LLM" escalation compares alert_type against ATTACK_ALERT_TYPES
below, which uses the COARSE labels (DoS, DDoS, Port Scanning, Brute Force,
Web Attack, Infiltration, Botnet, Heartbleed). Versions of CIC-IDS 2017 that
only have the fine-grained 'Label' column (e.g. "DoS Hulk", "PortScan",
"FTP-Patator") will NOT match most of these, silently reducing how often the
LLM judge is consulted. Use a version with the coarse 'Attack Type' column,
or extend the set - and report which you used.
"""

from __future__ import annotations

import json
import time

from . import config
from .detection import rule_based_detect_explanation, rule_classify_sentence, split_sentences
from .llm_client import call_llm_for_json, get_client
from .prompt_store import load_prompt

ATTACK_ALERT_TYPES = {
    "DDoS", "DoS", "Port Scanning", "Brute Force",
    "Web Attack", "Infiltration", "Botnet", "Heartbleed",
}

_EXPLANATION_FALLBACK = {
    "contains_hallucination": None,
    "confidence": "none",
    "hallucination_type": None,
    "reason": "LLM detection failed.",
    "detection_method": "failed",
}

_SENTENCE_FALLBACK = {
    "label": "grounded",
    "confidence": "none",
    "hallucination_type": None,
    "reason": "LLM call failed.",
    "detection_method": "failed",
}


# ── Phase 2, Step 3: explanation level ────────────────────────────────────

def should_invoke_llm(rule_result: dict, alert_type: str) -> bool:
    if rule_result["triggered"] is None:
        return True  # medium confidence -> always escalate
    if rule_result["triggered"] is False and alert_type in ATTACK_ALERT_TYPES:
        return True  # clean on an attack-class alert -> verify
    return False


def llm_detect_explanation(client, evidence: str, explanation: str, *, sleep: bool = True) -> dict:
    prompt = (
        load_prompt("detect_explanation_system.txt") + "\n"
        + load_prompt("detect_explanation_template.txt").format(evidence=evidence, explanation=explanation)
    )
    result = call_llm_for_json(client, prompt, _EXPLANATION_FALLBACK, sleep=sleep)
    result.setdefault("detection_method", "llm")
    return result


def detect_explanation(client, alert: dict, expl: dict, *, sleep: bool = True) -> dict:
    """Classify one explanation. Returns the Phase 2 detection record."""
    aid, alert_type = expl["alert_id"], expl["alert_type"]
    rule_result = rule_based_detect_explanation(expl["explanation"], alert.get("evidence_tokens", []))

    if rule_result["triggered"] is True:
        return {
            "alert_id": aid, "alert_type": alert_type,
            "contains_hallucination": True, "confidence": "high",
            "hallucination_type": rule_result["hallucination_type"],
            "reason": rule_result["reason"],
            "matched_rules": rule_result["matched_rules"],
            "detection_method": "rule", "gold_label": None,
        }
    if not should_invoke_llm(rule_result, alert_type):
        return {
            "alert_id": aid, "alert_type": alert_type,
            "contains_hallucination": False, "confidence": "high",
            "hallucination_type": None, "reason": rule_result["reason"],
            "matched_rules": [], "detection_method": "rule", "gold_label": None,
        }
    llm = llm_detect_explanation(client, alert["evidence"], expl["explanation"], sleep=sleep)
    return {
        "alert_id": aid, "alert_type": alert_type,
        "contains_hallucination": llm.get("contains_hallucination"),
        "confidence": llm.get("confidence"),
        "hallucination_type": llm.get("hallucination_type"),
        "reason": llm.get("reason"),
        "matched_rules": rule_result["matched_rules"],
        "detection_method": llm.get("detection_method", "llm"),
        "gold_label": None,
    }


def run_explanation_detection() -> list[dict]:
    print("=== Phase 2, Step 3: explanation-level detection ===")
    client = get_client()

    with open(config.ALERTS_PATH) as f:
        alert_map = {a["alert_id"]: a for a in json.load(f)}
    with open(config.EXPLANATIONS_PATH) as f:
        explanations: list[dict] = json.load(f)

    results: list[dict] = []
    done_ids: set[str] = set()
    if config.DETECTION_PATH.exists():
        with open(config.DETECTION_PATH) as f:
            results = json.load(f)
        done_ids = {r["alert_id"] for r in results}
        print(f"Resuming: {len(done_ids)} already processed.")

    new_since_save = 0
    for expl in explanations:
        aid = expl["alert_id"]
        if aid in done_ids:
            continue
        alert = alert_map.get(aid)
        if not alert:
            print(f"  [WARN] No alert record for {aid}, skipping.")
            continue

        results.append(detect_explanation(client, alert, expl))
        done_ids.add(aid)
        new_since_save += 1
        if new_since_save >= config.SAVE_EVERY:
            with open(config.DETECTION_PATH, "w") as f:
                json.dump(results, f, indent=2)
            new_since_save = 0

    with open(config.DETECTION_PATH, "w") as f:
        json.dump(results, f, indent=2)
    flagged = sum(1 for r in results if r["contains_hallucination"] is True)
    print(f"Saved {len(results)} detection results ({flagged} flagged) -> {config.DETECTION_PATH}")
    return results


# ── Phase 3, Step 4: sentence level ───────────────────────────────────────

def llm_classify_sentence(client, evidence: str, sentence: str, *, sleep: bool = True) -> dict:
    user_msg = (
        f"RAW EVIDENCE:\n{evidence}\n\n"
        f"SENTENCE:\n{sentence}\n\n"
        "Is this sentence hallucinated or grounded?\n\n"
        "Respond ONLY with this JSON (no markdown):\n"
        '{"label":"...","confidence":"...","hallucination_type":"...","reason":"..."}'
    )
    prompt = load_prompt("localize_sentence_system.txt") + "\n" + user_msg
    result = call_llm_for_json(client, prompt, _SENTENCE_FALLBACK, sleep=sleep)
    result.setdefault("detection_method", "llm")
    return result


def classify_sentence(client, alert: dict, sentence_id: str, sentence: str, *, sleep: bool = True) -> tuple[dict, bool]:
    """Classify one sentence. Returns (Phase 3 record, used_llm)."""
    evidence_tokens = {str(t).lower() for t in alert.get("evidence_tokens", [])}
    rule_result = rule_classify_sentence(sentence, evidence_tokens)

    used_llm = rule_result["label"] == "ambiguous"
    if used_llm:
        llm = llm_classify_sentence(client, alert["evidence"], sentence, sleep=sleep)
        final = {
            "predicted_label": llm.get("label", "grounded"),
            "confidence": llm.get("confidence", "low"),
            "hallucination_type": llm.get("hallucination_type"),
            "reason": llm.get("reason", ""),
            "detection_method": llm.get("detection_method", "llm"),
        }
        if sleep:
            time.sleep(0.3)
    else:
        final = {
            "predicted_label": rule_result["label"],
            "confidence": rule_result["confidence"],
            "hallucination_type": rule_result["hallucination_type"],
            "reason": rule_result["reason"],
            "detection_method": rule_result["detection_method"],
        }

    record = {
        "alert_id": alert["alert_id"],
        "alert_type": alert["alert_type"],
        "sentence_id": sentence_id,
        "sentence_text": sentence,
        **final,
        "matched": rule_result.get("matched", []),
        "gold_label": None,  # annotator fills this in
    }
    return record, used_llm


def run_sentence_localization(only_flagged: bool = True) -> list[dict]:
    print("=== Phase 3, Step 4: sentence-level localization ===")
    client = get_client()

    with open(config.ALERTS_PATH) as f:
        alert_map = {a["alert_id"]: a for a in json.load(f)}
    with open(config.EXPLANATIONS_PATH) as f:
        expl_map = {e["alert_id"]: e for e in json.load(f)}
    with open(config.DETECTION_PATH) as f:
        detections = json.load(f)

    if only_flagged:
        target_ids = {d["alert_id"] for d in detections if d["contains_hallucination"] is True}
        print(f"Localizing {len(target_ids)} flagged explanations only.")
    else:
        target_ids = set(expl_map)

    predictions: list[dict] = []
    done_keys: set[tuple] = set()
    if config.SENTENCE_PREDICTIONS_PATH.exists():
        with open(config.SENTENCE_PREDICTIONS_PATH) as f:
            predictions = json.load(f)
        done_keys = {(p["alert_id"], p["sentence_id"]) for p in predictions}
        print(f"Resuming: {len(done_keys)} sentences already done.")

    llm_calls = 0
    new_since_save = 0
    for aid in sorted(target_ids):
        alert, expl = alert_map.get(aid), expl_map.get(aid)
        if not alert or not expl:
            continue
        for s_idx, sentence in enumerate(split_sentences(expl["explanation"])):
            sid = f"S{s_idx + 1}"
            if (aid, sid) in done_keys:
                continue
            record, used_llm = classify_sentence(client, alert, sid, sentence)
            llm_calls += used_llm
            predictions.append(record)
            done_keys.add((aid, sid))
            new_since_save += 1
            if new_since_save >= 20:
                with open(config.SENTENCE_PREDICTIONS_PATH, "w") as f:
                    json.dump(predictions, f, indent=2)
                new_since_save = 0

    with open(config.SENTENCE_PREDICTIONS_PATH, "w") as f:
        json.dump(predictions, f, indent=2)
    with open(config.SENTENCE_GOLD_PATH, "w") as f:
        json.dump(predictions, f, indent=2)

    hallucinated = sum(1 for p in predictions if p["predicted_label"] == "hallucinated")
    print(f"Saved {len(predictions)} sentence predictions ({hallucinated} hallucinated, "
          f"{llm_calls} LLM calls) -> {config.SENTENCE_PREDICTIONS_PATH}")
    print(f"ACTION NEEDED: fill 'gold_label' in {config.SENTENCE_GOLD_PATH} (see ANNOTATION_GUIDE.md)")
    return predictions


if __name__ == "__main__":
    run_explanation_detection()
    run_sentence_localization()

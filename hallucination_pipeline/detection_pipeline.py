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
(Fresh-run alerts carry `label_coarse`, which is used for this check when present.)

FRESH-RUN OPTIONS (M2): passing `policy=` switches on the two-tier taxonomy
(policy.py). Phase 2 then takes `use_tier2_rules` and `judge_prompt`
(v1 / v2-strict / v2-lenient); Phase 3 takes `sentence_prompt`; every record
gains tier and subtype. Without `policy=` both phases behave exactly as before
(tools/verify_against_original.py and tools/reproduce_frozen.py rely on that).
"""

from __future__ import annotations

import json
import time

from . import config
from .detection import rule_based_detect_explanation, rule_classify_sentence, split_sentences
from .llm_client import call_llm_for_json, get_client
from .policy import (classify_sentence_rules, counts_as_hallucination, explanation_rule_decision,
                     explanation_rule_hits, flow_duration_from_evidence, judge_prompt_files, parse_v2_reply,
                     sentence_policy_decision, sentence_prompt_files, tier_for_type)
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

def should_invoke_llm(rule_result: dict, alert_type: str, escalate_clean: str = "attack_only") -> bool:
    """escalate_clean (D15): "attack_only" = the original behaviour (a rule-clean explanation is
    double-checked only for attack-class alerts, so the decision reads the label); "all" = every
    rule-clean explanation is double-checked, whatever its label."""
    if rule_result["triggered"] is None:
        return True  # medium confidence -> always escalate
    if rule_result["triggered"] is False:
        if escalate_clean == "all":
            return True
        if escalate_clean != "attack_only":
            raise ValueError(f"escalate_clean must be 'all' or 'attack_only', not {escalate_clean!r}")
        return alert_type in ATTACK_ALERT_TYPES  # clean on an attack-class alert -> verify
    return False


def llm_detect_explanation(client, evidence: str, explanation: str, *, sleep: bool = True,
                           judge_prompt: str = "v1") -> dict:
    system_file, template_file = judge_prompt_files(judge_prompt)
    prompt = (
        load_prompt(system_file) + "\n"
        + load_prompt(template_file).format(evidence=evidence, explanation=explanation)
    )
    result = call_llm_for_json(client, prompt, _EXPLANATION_FALLBACK, sleep=sleep)
    result.setdefault("detection_method", "llm")
    return result


def detect_explanation(client, alert: dict, expl: dict, *, sleep: bool = True, policy: str | None = None,
                       use_tier2_rules: bool = False, judge_prompt: str = "v1",
                       escalate_clean: str | None = None) -> dict:
    """Classify one explanation. Returns the Phase 2 detection record.

    policy=None: the original behaviour (Tier 1 rules, v1 judge, attack-only escalation,
    original record shape).
    policy="strict"/"lenient": one tiered rule pass (the Tier 2 layer and the D19 duration
    check only if use_tier2_rules), the policy decides, rule-clean explanations are escalated
    per `escalate_clean` (default "all", D15), the judge uses `judge_prompt`, and the record
    gains the options, tier, subtype, every rule hit, and the hits the policy did not count.
    A v2 judge reply is parsed for tier/subtype; its verdict counts only if the policy counts
    its tier (the raw reply is kept under `judge`)."""
    if policy is None:
        if use_tier2_rules or judge_prompt != "v1":
            raise ValueError("use_tier2_rules and judge_prompt require a policy")
        return _detect_explanation(client, alert, expl, sleep=sleep, escalate_clean=escalate_clean or "attack_only")
    escalate_clean = escalate_clean or "all"
    rule_pass = explanation_rule_hits(expl["explanation"], alert.get("evidence_tokens", []),
                                      use_tier2_rules=use_tier2_rules,
                                      flow_duration_us=flow_duration_from_evidence(alert.get("evidence", "")))
    rule_result = explanation_rule_decision(rule_pass, policy)
    record = _detect_explanation(client, alert, expl, sleep=sleep, rule_result=rule_result,
                                 judge_prompt=judge_prompt, escalate_clean=escalate_clean)
    llm = record.pop("_llm", None)
    extra = {}
    if llm is None:
        rule_says = record["contains_hallucination"]
        tier, subtype = (rule_result["tier"], rule_result["subtype"]) if rule_says else (None, None)
    elif judge_prompt == "v1":
        tier, subtype = tier_for_type(record["hallucination_type"])
    else:
        parsed = parse_v2_reply(llm, "explanation")
        tier, subtype = parsed["tier"], parsed["subtype"]
        counted = parsed["verdict"] is True and (tier is None or counts_as_hallucination(tier, policy))
        record.update({"contains_hallucination": counted if parsed["verdict"] is not None else None,
                       "hallucination_type": parsed["hallucination_type"]})
        extra = {"judge": {"contains_hallucination": parsed["verdict"], "tier": tier, "subtype": subtype,
                           "reply_problems": parsed["reply_problems"]}}
    return {**record, "policy": policy, "use_tier2_rules": use_tier2_rules, "judge_prompt": judge_prompt,
            "escalate_clean": escalate_clean, "tier": tier, "subtype": subtype,
            "rule_hits": rule_pass["hits"], "uncounted_rules": rule_result["uncounted_rules"],
            "duration_claims": rule_pass["duration_claims"], **extra}


def _detect_explanation(client, alert: dict, expl: dict, *, sleep: bool, rule_result: dict | None = None,
                        judge_prompt: str = "v1", escalate_clean: str = "attack_only") -> dict:
    aid, alert_type = expl["alert_id"], expl["alert_type"]
    with_llm_reply = rule_result is not None
    if rule_result is None:
        rule_result = rule_based_detect_explanation(expl["explanation"], alert.get("evidence_tokens", []))
    escalation_class = alert.get("label_coarse", alert_type)

    if rule_result["triggered"] is True:
        return {
            "alert_id": aid, "alert_type": alert_type,
            "contains_hallucination": True, "confidence": "high",
            "hallucination_type": rule_result["hallucination_type"],
            "reason": rule_result["reason"],
            "matched_rules": rule_result["matched_rules"],
            "detection_method": "rule", "gold_label": None,
        }
    if not should_invoke_llm(rule_result, escalation_class, escalate_clean):
        return {
            "alert_id": aid, "alert_type": alert_type,
            "contains_hallucination": False, "confidence": "high",
            "hallucination_type": None, "reason": rule_result["reason"],
            "matched_rules": [], "detection_method": "rule", "gold_label": None,
        }
    llm = llm_detect_explanation(client, alert["evidence"], expl["explanation"], sleep=sleep,
                                 judge_prompt=judge_prompt)
    record = {
        "alert_id": aid, "alert_type": alert_type,
        "contains_hallucination": llm.get("contains_hallucination"),
        "confidence": llm.get("confidence"),
        "hallucination_type": llm.get("hallucination_type"),
        "reason": llm.get("reason"),
        "matched_rules": rule_result["matched_rules"],
        "detection_method": llm.get("detection_method", "llm"),
        "gold_label": None,
    }
    if with_llm_reply:
        record["_llm"] = llm
    return record


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

def llm_classify_sentence(client, evidence: str, sentence: str, *, sleep: bool = True,
                          sentence_prompt: str = "v1") -> dict:
    system_file, template_file = sentence_prompt_files(sentence_prompt)
    if template_file is None:  # v1: the original user message, kept in code so v1 is unchanged
        user_msg = (
            f"RAW EVIDENCE:\n{evidence}\n\n"
            f"SENTENCE:\n{sentence}\n\n"
            "Is this sentence hallucinated or grounded?\n\n"
            "Respond ONLY with this JSON (no markdown):\n"
            '{"label":"...","confidence":"...","hallucination_type":"...","reason":"..."}'
        )
    else:
        user_msg = load_prompt(template_file).format(evidence=evidence, sentence=sentence)
    prompt = load_prompt(system_file) + "\n" + user_msg
    result = call_llm_for_json(client, prompt, _SENTENCE_FALLBACK, sleep=sleep)
    result.setdefault("detection_method", "llm")
    return result


def classify_sentence(client, alert: dict, sentence_id: str, sentence: str, *, sleep: bool = True,
                      policy: str | None = None, sentence_prompt: str = "v1") -> tuple[dict, bool]:
    """Classify one sentence. Returns (Phase 3 record, used_llm).

    policy=None: the original behaviour and record shape. policy="strict"/"lenient": one pass
    over every rule layer plus the D19 duration check; the policy decides from all hits (a
    Tier 2 hit is not a hallucination under lenient; a contradicted duration is Tier 1 under
    both); the LLM fallback uses `sentence_prompt` (a v2 reply is parsed for tier/subtype).
    The record gains tier/subtype of the verdict, every hit (`rule_hits`, each with tier,
    subtype, hedged), `subtypes` (all, D18), `hedged` (D17), `duration_claims` (D19), and
    `rule_label`/`rule_tier`/`rule_subtype`: what the unchanged rule engine alone decided."""
    evidence_tokens = {str(t).lower() for t in alert.get("evidence_tokens", [])}
    if policy is None:
        if sentence_prompt != "v1":
            raise ValueError("sentence_prompt requires a policy")
        rule_result = rule_classify_sentence(sentence, evidence_tokens)
        label, primary = rule_result["label"], None
    else:
        rule_result = classify_sentence_rules(sentence, evidence_tokens,
                                              flow_duration_from_evidence(alert.get("evidence", "")))
        decision = sentence_policy_decision(rule_result, sentence, policy)
        label, primary = decision["label"], decision["primary"]

    used_llm = label == "ambiguous"
    llm = None
    if used_llm:
        llm = llm_classify_sentence(client, alert["evidence"], sentence, sleep=sleep, sentence_prompt=sentence_prompt)
        final = {
            "predicted_label": llm.get("label", "grounded"),
            "confidence": llm.get("confidence", "low"),
            "hallucination_type": llm.get("hallucination_type"),
            "reason": llm.get("reason", ""),
            "detection_method": llm.get("detection_method", "llm"),
        }
        if sleep:
            time.sleep(0.3)
    elif policy is None or (label == rule_result["label"] and (primary is None or primary["key"] == rule_result["key"])):
        final = {
            "predicted_label": rule_result["label"],
            "confidence": rule_result["confidence"],
            "hallucination_type": rule_result["hallucination_type"],
            "reason": rule_result["reason"],
            "detection_method": rule_result["detection_method"],
        }
    elif primary is not None:  # decided by a hit the engine alone did not pick (D19 unit_wrong)
        final = {
            "predicted_label": "hallucinated",
            "confidence": "high",
            "hallucination_type": primary["type"],
            "reason": f"{primary['rule']}: {primary['matched'][:2]}",
            "detection_method": "rule_unit_check" if primary["subtype"] == "unit_wrong" else "rule_policy",
        }
    else:  # a Tier 2 rule fired but the policy (lenient) does not count Tier 2
        final = {
            "predicted_label": label,
            "confidence": rule_result["confidence"],
            "hallucination_type": None,
            "reason": f"Tier 2 ({rule_result['subtype']}) not counted under the {policy} policy: {rule_result['reason']}",
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
    if policy is None:
        return record, used_llm

    extra = {}
    if final["predicted_label"] != "hallucinated" and not (used_llm and sentence_prompt != "v1"):
        tier, subtype = None, None
    elif not used_llm:
        tier, subtype = primary["tier"], primary["subtype"]
    elif sentence_prompt == "v1":
        tier, subtype = tier_for_type(final["hallucination_type"])
    else:
        parsed = parse_v2_reply(llm, "sentence")
        tier, subtype = parsed["tier"], parsed["subtype"]
        counted = parsed["verdict"] is True and (tier is None or counts_as_hallucination(tier, policy))
        record.update({"predicted_label": "hallucinated" if counted else "grounded",
                       "hallucination_type": parsed["hallucination_type"]})
        if not counted:
            tier, subtype = None, None
        extra = {"judge": {"label": llm.get("label"), "tier": parsed["tier"], "subtype": parsed["subtype"],
                           "reply_problems": parsed["reply_problems"]}}
    record.update({"policy": policy, "sentence_prompt": sentence_prompt, "tier": tier, "subtype": subtype,
                   "subtypes": rule_result["subtypes"], "hedged": rule_result["hedged"],
                   "rule_hits": rule_result["hits"], "duration_claims": rule_result["duration_claims"],
                   "rule_label": rule_result["label"], "rule_tier": rule_result["tier"],
                   "rule_subtype": rule_result["subtype"], **extra})
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

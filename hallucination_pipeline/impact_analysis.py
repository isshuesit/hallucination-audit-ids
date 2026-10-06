"""
Phase 5, Step 8: measure the actual impact of selective unlearning.

Answers the core research question: did selective unlearning improve
explanation quality? The same rule-based classifier is run on BOTH the
original and the corrected explanations, then the counts are compared.

THREE REAL BUGS WERE FOUND AND FIXED IN THE ORIGINAL PROJECT. They are kept
here as permanent documentation because each is a genuine measurement-
validity lesson:

BUG 1 - Measurement asymmetry produced a nonsensical "-413% reduction".
  "Before" counts came from gold labels in a file covering only the ~94
  alerts Phase 3 flagged; the other ~306 alerts counted as 0 before. "After"
  counts ran the rule classifier fresh on ALL 400. Same sentences, 0 counted
  before and N counted after - a fabricated increase from a mismatched
  yardstick. FIX: the identical classifier call, over the identical alerts,
  on both sides (count_hallucinated below).

BUG 2 - The LLM re-check silently "passed" everything.
  gemini-2.5-flash prepends thinking-mode text before its JSON, so plain
  parsing failed and a hardcoded fallback labelled every re-check
  "grounded". FIX: request response_mime_type="application/json" so the API
  returns valid JSON directly, and record how each re-check was resolved
  (ok / json_fallback / failed) so failures can never masquerade as passes.

BUG 3 - Most QUALIFY pairs were silently dropped.
  Original and rewritten sentences were matched by their first 40
  characters, but a rewrite changes those characters - 95 of 115 pairs
  vanished from the re-check sample. FIX: track position explicitly. REMOVE
  drops a sentence (the corrected-side index does not advance); QUALIFY and
  KEEP each keep one (it advances). Indexing the corrected list by the
  ORIGINAL sentence number is wrong as soon as any earlier sentence was
  removed.

METHODOLOGICAL CAVEAT: "hallucinated" in the before/after counts is decided
by the same rule engine that produced most of the Phase 3 labels, so this
measures how well rewrites satisfy the rules, which is circular to a degree.
The independent LLM re-check (QUALIFY effectiveness) is the less circular
signal; report both, and say so.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from . import config
from .detection import rule_classify_sentence
from .llm_client import get_client, get_types
from .prompt_store import load_prompt


def evidence_coverage(sentence: str, evidence_tokens: set[str]) -> float:
    """Fraction of evidence tokens still referenced in *sentence*."""
    if not evidence_tokens:
        return 1.0
    found = sum(1 for tok in evidence_tokens if tok in sentence)
    return round(found / len(evidence_tokens), 3)


def count_hallucinated(sentences: list[str], evidence_tokens: set[str]) -> int:
    """BUG 1 FIX: one classifier, applied identically to both sides."""
    return sum(
        1 for s in sentences
        if rule_classify_sentence(s, evidence_tokens)["label"] == "hallucinated"
    )


def llm_recheck(client, sentence: str, evidence: str, *, sleep: bool = True) -> dict:
    """BUG 2 FIX: independent LLM re-check of a rewritten sentence.

    recheck_status:
      "ok"            JSON parsed cleanly from the API response
      "json_fallback" JSON parse failed anyway; label recovered by keyword
      "failed"        no label could be determined (excluded from effectiveness)
    """
    gtypes = get_types()
    prompt = load_prompt("recheck_template.txt").format(evidence=evidence, sentence=sentence)

    for attempt in range(config.MAX_RETRIES):
        try:
            resp = client.models.generate_content(
                model=config.GEMINI_MODEL,
                contents=prompt,
                config=gtypes.GenerateContentConfig(response_mime_type="application/json"),
            )
            raw = resp.text.strip()
            parsed = json.loads(raw)
            parsed["recheck_status"] = "ok"
            return parsed

        except json.JSONDecodeError:
            raw_lower = raw.lower()
            if "hallucinated" in raw_lower:
                return {"label": "hallucinated", "confidence": "low",
                        "reason": f"Keyword fallback: {raw[:120]}", "recheck_status": "json_fallback"}
            if "grounded" in raw_lower:
                return {"label": "grounded", "confidence": "low",
                        "reason": f"Keyword fallback: {raw[:120]}", "recheck_status": "json_fallback"}
            # cannot extract a label - fall through and retry

        except Exception as e:  # noqa: BLE001
            print(f"    LLM recheck error attempt {attempt + 1}: {e}")
            if attempt < config.MAX_RETRIES - 1 and sleep:
                time.sleep(config.RETRY_DELAY_SECONDS * (attempt + 1))

    return {"label": "recheck_failed", "confidence": "none",
            "reason": "All LLM attempts failed.", "recheck_status": "failed"}


def _new_type_stats() -> dict:
    return {"removed": 0, "qualified": 0, "qualify_still_hallucinated": 0,
            "qualify_now_grounded": 0, "qualify_recheck_failed": 0, "remove_was_grounded": 0}


def analyze_alerts(alerts: list[dict], corrected: list[dict], predictions: list[dict], masks: list[dict]):
    """Deterministic part of the analysis (no LLM calls).

    Returns (alert_results, qualify_pairs, type_stats). The gold label is
    used ONLY to audit false removals, never for the before/after counts.
    """
    alert_map = {a["alert_id"]: a for a in alerts}
    pred_map = {(p["alert_id"], p["sentence_id"]): p for p in predictions}
    mask_map = {(m["alert_id"], m["sentence_id"]): m for m in masks}

    modified_aids = {
        c["alert_id"] for c in corrected
        if c["sentences_removed"] > 0 or c["sentences_qualified"] > 0
    }

    type_stats: dict[str, dict] = defaultdict(_new_type_stats)
    alert_results: list[dict] = []
    qualify_pairs: list[dict] = []

    for c in corrected:
        aid = c["alert_id"]
        alert = alert_map.get(aid, {})
        evidence = alert.get("evidence", "")
        evidence_tokens = {str(t).lower() for t in alert.get("evidence_tokens", [])}

        orig_sentences = c["original_explanation"]
        corr_sentences = c["corrected_explanation"]

        orig_hall = count_hallucinated(orig_sentences, evidence_tokens)
        corr_hall = count_hallucinated(corr_sentences, evidence_tokens)

        avg_coverage = (
            round(sum(evidence_coverage(s, evidence_tokens) for s in corr_sentences) / len(corr_sentences), 3)
            if corr_sentences else 0.0
        )

        # BUG 3 FIX: explicit position tracking on the corrected side.
        corr_idx = 0
        for idx, sent in enumerate(orig_sentences):
            sid = f"S{idx + 1}"
            mask = mask_map.get((aid, sid))
            pred = pred_map.get((aid, sid))
            if not mask:
                corr_idx += 1  # no mask entry -> untouched (KEEP)
                continue

            action = mask["action"]
            h_type = mask.get("hallucination_type") or "unknown"
            gold = pred.get("gold_label") if pred else None

            if action == "REMOVE":
                type_stats[h_type]["removed"] += 1
                if gold == "grounded":
                    type_stats[h_type]["remove_was_grounded"] += 1
                # sentence dropped: corr_idx does NOT advance
            elif action == "QUALIFY":
                type_stats[h_type]["qualified"] += 1
                corr_version = corr_sentences[corr_idx] if corr_idx < len(corr_sentences) else None
                if corr_version:
                    qualify_pairs.append({
                        "alert_id": aid, "sentence_id": sid, "h_type": h_type,
                        "original": sent, "corrected": corr_version,
                        "evidence": evidence, "evidence_tokens": sorted(evidence_tokens),  # sorted: deterministic output
                    })
                corr_idx += 1
            else:  # KEEP
                corr_idx += 1

        alert_results.append({
            "alert_id": aid,
            "alert_type": c["alert_type"],
            "modified": aid in modified_aids,
            "orig_sentences": len(orig_sentences),
            "corr_sentences": len(corr_sentences),
            "orig_hallucinated": orig_hall,
            "corr_hallucinated": corr_hall,
            "sentences_removed": c["sentences_removed"],
            "sentences_qualified": c["sentences_qualified"],
            "avg_evidence_coverage": avg_coverage,
        })

    return alert_results, qualify_pairs, type_stats


def recheck_pairs(client, qualify_pairs: list[dict], type_stats: dict, *, sleep: bool = True) -> tuple[int, int, int]:
    """LLM re-check every QUALIFY rewrite; annotate pairs and type_stats in place.
    Returns (ok, keyword_fallback, failed) counts."""
    ok = fallback = failed = 0
    for pair in qualify_pairs:
        result = llm_recheck(client, pair["corrected"], pair["evidence"], sleep=sleep)
        pair["recheck_label"] = result.get("label", "recheck_failed")
        pair["recheck_confidence"] = result.get("confidence", "none")
        pair["recheck_reason"] = result.get("reason", "")
        pair["recheck_status"] = result.get("recheck_status", "failed")

        h_type, label = pair["h_type"], result.get("label")
        if label == "hallucinated":
            type_stats[h_type]["qualify_still_hallucinated"] += 1
        elif label == "grounded":
            type_stats[h_type]["qualify_now_grounded"] += 1
        else:
            type_stats[h_type]["qualify_recheck_failed"] += 1

        status = result.get("recheck_status", "failed")
        if status == "ok":
            ok += 1
        elif status == "json_fallback":
            fallback += 1
        else:
            failed += 1
    return ok, fallback, failed


def aggregate(alert_results, qualify_pairs, type_stats, recheck_fallback: int, recheck_failed: int) -> dict:
    """Combine per-alert and per-pair results into the impact summary."""
    total_orig_hall = sum(r["orig_hallucinated"] for r in alert_results)
    total_corr_hall = sum(r["corr_hallucinated"] for r in alert_results)
    total_orig_sents = sum(r["orig_sentences"] for r in alert_results)
    total_corr_sents = sum(r["corr_sentences"] for r in alert_results)
    total_removed = sum(r["sentences_removed"] for r in alert_results)
    total_qualified = sum(r["sentences_qualified"] for r in alert_results)

    mod_results = [r for r in alert_results if r["modified"]]
    mod_orig_hall = sum(r["orig_hallucinated"] for r in mod_results)
    mod_corr_hall = sum(r["corr_hallucinated"] for r in mod_results)

    conclusive = [p for p in qualify_pairs if p.get("recheck_label") in ("hallucinated", "grounded")]
    now_grounded = sum(1 for p in conclusive if p["recheck_label"] == "grounded")
    still_hall = sum(1 for p in conclusive if p["recheck_label"] == "hallucinated")
    effectiveness = round(now_grounded / len(conclusive), 3) if conclusive else None

    mod_coverages = [r["avg_evidence_coverage"] for r in mod_results if r["corr_sentences"] > 0]
    avg_coverage = round(sum(mod_coverages) / len(mod_coverages), 3) if mod_coverages else None

    total_false_removals = sum(v["remove_was_grounded"] for v in type_stats.values())
    false_removal_rate = round(total_false_removals / total_removed, 3) if total_removed else 0

    overall_reduction = round((total_orig_hall - total_corr_hall) / total_orig_hall, 3) if total_orig_hall else 0
    modified_reduction = round((mod_orig_hall - mod_corr_hall) / mod_orig_hall, 3) if mod_orig_hall else 0

    return {
        "scope": {
            "total_alerts": len(alert_results),
            "modified_alerts": len(mod_results),
            "total_sentences_before": total_orig_sents,
            "total_sentences_after": total_corr_sents,
            "sentences_removed": total_removed,
            "sentences_qualified": total_qualified,
        },
        "hallucination_reduction": {
            "overall": {"before": total_orig_hall, "after": total_corr_hall,
                        "reduction_pct": round(overall_reduction * 100, 1)},
            "modified_alerts_only": {"before": mod_orig_hall, "after": mod_corr_hall,
                                     "reduction_pct": round(modified_reduction * 100, 1)},
        },
        "qualify_effectiveness": {
            "sentences_checked": len(qualify_pairs),
            "conclusive_rechecks": len(conclusive),
            "recheck_failed": recheck_failed,
            "recheck_json_fallback": recheck_fallback,
            "now_grounded": now_grounded,
            "still_hallucinated": still_hall,
            "effectiveness_rate": effectiveness,
            "note": ("Effectiveness = grounded / conclusive_rechecks. "
                     "Failed re-checks excluded from denominator."),
        },
        "information_quality": {
            "avg_evidence_coverage_after": avg_coverage,
            "false_removal_rate": false_removal_rate,
            "false_removals": total_false_removals,
        },
        "per_type_breakdown": {
            h_type: {
                "removed": s["removed"], "qualified": s["qualified"],
                "qualify_now_grounded": s["qualify_now_grounded"],
                "qualify_still_hallucinated": s["qualify_still_hallucinated"],
                "qualify_recheck_failed": s["qualify_recheck_failed"],
                "false_removals": s["remove_was_grounded"],
                "total_acted_on": s["removed"] + s["qualified"],
            }
            for h_type, s in sorted(type_stats.items(), key=lambda x: -(x[1]["removed"] + x[1]["qualified"]))
        },
        "qualify_sentence_pairs": qualify_pairs,
        "per_alert_results": alert_results,
    }


def run() -> dict:
    print("=== Phase 5, Step 8: measuring impact of selective unlearning ===")
    client = get_client()

    with open(config.ALERTS_PATH) as f:
        alerts = json.load(f)
    with open(config.CORRECTED_PATH) as f:
        corrected = json.load(f)
    with open(config.SENTENCE_PREDICTIONS_PATH) as f:
        predictions = json.load(f)
    with open(config.MASKS_PATH) as f:
        masks = json.load(f)

    alert_results, qualify_pairs, type_stats = analyze_alerts(alerts, corrected, predictions, masks)
    print(f"Alerts modified by Phase 4: {sum(r['modified'] for r in alert_results)} of {len(alert_results)}")

    print(f"LLM re-checking {len(qualify_pairs)} QUALIFY rewrites...")
    ok, fallback, failed = recheck_pairs(client, qualify_pairs, type_stats)
    print(f"Re-check summary: {ok} JSON ok | {fallback} keyword fallback | {failed} failed")

    impact = aggregate(alert_results, qualify_pairs, type_stats, fallback, failed)
    with open(config.IMPACT_PATH, "w") as f:
        json.dump(impact, f, indent=2)
    print(f"Impact data -> {config.IMPACT_PATH}")

    write_report(impact, config.IMPACT_REPORT_PATH)
    print(f"Impact report -> {config.IMPACT_REPORT_PATH}")
    return impact


def write_report(impact: dict, path: Path) -> None:
    scope = impact["scope"]
    red = impact["hallucination_reduction"]
    qual = impact["qualify_effectiveness"]
    info = impact["information_quality"]
    types = impact["per_type_breakdown"]
    pairs = impact["qualify_sentence_pairs"]

    L: list[str] = []
    L.append("# Selective Unlearning Impact Analysis\n")
    L.append(f"> Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")
    L.append("---\n")

    L.append("## Overview\n")
    L.append(
        f"This section measures the direct impact of Phase 4 selective unlearning "
        f"on explanation quality across {scope['total_alerts']} alerts, with "
        f"{scope['modified_alerts']} alerts modified by Phase 4 "
        f"({scope['sentences_removed']} sentences removed, "
        f"{scope['sentences_qualified']} sentences rewritten). "
        f"Both before and after hallucination counts use the same rule-based "
        f"classifier across all alerts, ensuring a consistent yardstick.\n"
    )

    L.append("## Hallucination Reduction\n")
    L.append("| Scope | Before | After | Reduction |")
    L.append("|-------|--------|-------|-----------|")
    o = red["overall"]
    L.append(f"| All alerts ({scope['total_alerts']}) | {o['before']} | "
             f"{o['after']} | **{o['reduction_pct']}%** |")
    m = red["modified_alerts_only"]
    L.append(f"| Modified alerts only ({scope['modified_alerts']}) | {m['before']} | "
             f"{m['after']} | **{m['reduction_pct']}%** |")
    L.append("")
    # (the original hard-coded "all 400 alerts" here; this uses the real count)
    L.append(
        "> Both before and after counts use `rule_classify_sentence()` from "
        "`hallucination_utils` \u2014 the same four-layer rule engine used in Phase 3 "
        f"localisation \u2014 applied to all {scope['total_alerts']} alerts on both sides.\n"
    )

    L.append("## QUALIFY Rewrite Effectiveness\n")
    if qual["sentences_checked"]:
        L.append("| Metric | Value |")
        L.append("|--------|-------|")
        L.append(f"| Sentences rewritten by QUALIFY | {qual['sentences_checked']} |")
        L.append(f"| Conclusive re-checks | {qual['conclusive_rechecks']} |")
        L.append(f"| Re-check failed (parse error) | {qual['recheck_failed']} |")
        L.append(f"| Re-check via keyword fallback | {qual['recheck_json_fallback']} |")
        if qual["conclusive_rechecks"]:
            n_pct = round(100 * qual['now_grounded'] / qual['conclusive_rechecks'], 1)
            s_pct = round(100 * qual['still_hallucinated'] / qual['conclusive_rechecks'], 1)
            L.append(f"| Rewrites now grounded | **{qual['now_grounded']}** ({n_pct}%) |")
            L.append(f"| Rewrites still hallucinated | {qual['still_hallucinated']} ({s_pct}%) |")
        L.append(f"| Effectiveness rate | **{qual['effectiveness_rate']}** |")
        L.append("")
        L.append(
            "> Each QUALIFY rewrite was re-checked by the Gemini LLM judge using "
            "`response_mime_type=application/json` to ensure reliable JSON output. "
            "Effectiveness rate is computed over conclusive re-checks only \u2014 failed "
            "re-checks are excluded from both numerator and denominator.\n"
        )
    else:
        L.append("> No QUALIFY rewrites were produced in this run.\n")

    L.append("## Information Quality After Correction\n")
    L.append("| Metric | Value |")
    L.append("|--------|-------|")
    if info["avg_evidence_coverage_after"] is not None:
        L.append(f"| Avg evidence token coverage (corrected) | "
                 f"**{info['avg_evidence_coverage_after']}** |")
    L.append(f"| False removal rate | {info['false_removal_rate']} |")
    L.append(f"| Grounded sentences incorrectly removed | {info['false_removals']} |")
    L.append("")

    L.append("## Per-Type Unlearning Impact\n")
    if qual["sentences_checked"]:
        L.append("| Hallucination Type | Removed | Qualified | \u2192Grounded | "
                 "\u2192Still Hall | \u2192Failed | False Removals |")
        L.append("|-------------------|---------|-----------|-----------|"
                 "-------------|---------|----------------|")
        for h_type, stats in types.items():
            L.append(
                f"| {h_type} | {stats['removed']} | {stats['qualified']} | "
                f"{stats['qualify_now_grounded']} | {stats['qualify_still_hallucinated']} | "
                f"{stats['qualify_recheck_failed']} | {stats['false_removals']} |"
            )
    else:
        L.append("| Hallucination Type | Removed | False Removals |")
        L.append("|-------------------|---------|----------------|")
        for h_type, stats in types.items():
            L.append(f"| {h_type} | {stats['removed']} | {stats['false_removals']} |")
    L.append("")

    if pairs:
        conclusive = [p for p in pairs if p.get("recheck_label") in ("hallucinated", "grounded")]
        failed_pairs = [p for p in pairs if p.get("recheck_status") == "failed"]
        L.append("## Before / After Sentence Pairs (QUALIFY Rewrites)\n")
        L.append(
            f"{len(conclusive)} of {len(pairs)} re-checks were conclusive; "
            f"{len(failed_pairs)} failed to parse. Showing up to 8 pairs.\n"
        )
        shown = 0
        for pair in pairs:
            if shown >= 8:
                break
            label = pair.get("recheck_label", "recheck_failed")
            status = pair.get("recheck_status", "failed")
            if label == "grounded":
                result_str = "\u2713 Grounded after rewrite"
            elif label == "hallucinated":
                result_str = "\u2717 Still hallucinated after rewrite"
            elif status == "failed":
                result_str = "\u26a0 Re-check failed (parse error)"
            else:
                result_str = f"~ {label} (keyword fallback)"

            L.append(f"### Pair {shown + 1} \u2014 Alert `{pair['alert_id']}` "
                     f"| Type: `{pair['h_type']}`\n")
            L.append(f"**Original:** {pair['original']}\n")
            L.append(f"**Rewritten:** {pair['corrected']}\n")
            L.append(f"**Re-check result:** {result_str}\n")
            reason = pair.get("recheck_reason", "")
            if reason and "failed" not in reason.lower():
                L.append(f"**Reason:** {reason}\n")
            L.append("---\n")
            shown += 1

    L.append("## Interpretation\n")
    o_red = red["overall"]["reduction_pct"]
    m_red = red["modified_alerts_only"]["reduction_pct"]
    frr = info["false_removal_rate"]
    L.append(
        f"Selective unlearning reduced hallucinated sentences by {o_red}% across "
        f"all alerts and by {m_red}% in the subset of alerts that were actually "
        f"modified. The {frr} false removal rate indicates that "
    )
    L.append(
        "Phase 4 rarely removed grounded content \u2014 the pipeline is acting surgically.\n"
        if frr < 0.1 else
        "a non-trivial fraction of removed sentences were grounded, suggesting the "
        "detection rules need further specificity tuning before production use.\n"
    )

    if qual["sentences_checked"] and qual["effectiveness_rate"] is not None:
        eff = qual["effectiveness_rate"]
        L.append(
            f"The QUALIFY path achieved a {eff} effectiveness rate "
            f"({round(eff * 100, 1)}% of conclusive rewrites confirmed grounded). "
        )
        L.append(
            "This demonstrates that evidence-bounded rewriting successfully removes "
            "external knowledge claims while preserving analytical value.\n"
            if eff >= 0.8 else
            "This indicates the QUALIFY rewrite prompt needs further refinement \u2014 "
            "the rewriter is not consistently removing targeted external knowledge claims.\n"
        )

    path.write_text("\n".join(L), encoding="utf-8")


if __name__ == "__main__":
    run()

"""Phase 5, Step 7: generate a paper-ready results report in Markdown.

The report text mirrors the original project's report so reproduced results
read identically. The closing "Discussion" paragraph is boilerplate from the
original; edit it freely for your own paper (it is not a finding).
"""

from __future__ import annotations

import json
from datetime import datetime

from . import config


def fmt(val, is_pct: bool = False) -> str:
    if val is None:
        return "N/A"
    if isinstance(val, float):
        if is_pct:
            return f"{val:.1f}%"
        return f"{val:.4f}"
    return str(val)


_DISCUSSION = """The pipeline demonstrates that span-level hallucination localization followed by selective masking can substantially reduce the proportion of unsupported claims in LLM-generated cybersecurity explanations without full model retraining. Phase 2 provides a rapid gateway to identify problematic explanations, while Phase 3 pinpoints the specific sentences responsible. Phase 4 applies evidence-bounded reconstruction that preserves the informational content of grounded sentences while removing or hedging hallucinated ones.

Key limitations include:
- Implicit hallucinations (knowledge assumed but not stated) are harder to detect
- Over-removal in ambiguous cases may reduce explanation utility
- Pipeline performance varies by attack category
- Gold annotation effort is non-trivial for large datasets

These form the basis of the **Limitations** section of the research paper."""


def build_report(metrics: dict, compare: dict, examples: list[dict]) -> str:
    p2 = metrics.get("phase2", {})
    p3 = metrics.get("phase3", {})
    p4 = metrics.get("phase4", {})
    ps = metrics.get("pipeline_summary", {})

    lines: list[str] = []
    lines.append("# Results: LLM Hallucination Localization and Selective Unlearning")
    lines.append(f"\n> Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    lines.append(f"> Dataset: {ps.get('dataset', 'CIC-IDS 2017')}")
    lines.append(f"> Model: `{ps.get('model_used', config.GEMINI_MODEL)}`\n")
    lines.append("---\n")

    lines.append("## Overview\n")
    lines.append(f"We evaluated a four-phase hallucination handling pipeline on **{metrics.get('alerts_total', 'N/A')} network intrusion alerts** drawn from the CIC-IDS 2017 dataset. For each alert, an LLM was prompted to generate a natural-language cybersecurity explanation. The pipeline then detected, localized, and mitigated hallucinations.\n")

    lines.append("## Phase 2 \u2014 Explanation-level Hallucination Detection\n")
    if "warning" in p2:
        lines.append(f"> \u26a0 {p2['warning']}\n")
    else:
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Evaluated explanations | {p2.get('evaluated', 'N/A')} / {p2.get('total_records', 'N/A')} |")
        lines.append(f"| True hallucinated explanations | {p2.get('true_hallucinated', 'N/A')} |")
        lines.append(f"| Predicted hallucinated | {p2.get('predicted_hallucinated', 'N/A')} |")
        lines.append(f"| Precision | **{fmt(p2.get('precision'))}** |")
        lines.append(f"| Recall    | **{fmt(p2.get('recall'))}** |")
        lines.append(f"| F1        | **{fmt(p2.get('f1'))}** |")
        lines.append("")

    lines.append("## Phase 3 \u2014 Sentence-level Hallucination Localization\n")
    if "warning" in p3:
        lines.append(f"> \u26a0 {p3['warning']}\n")
    else:
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Evaluated sentences | {p3.get('evaluated', 'N/A')} / {p3.get('total_sentences', 'N/A')} |")
        lines.append(f"| True hallucinated sentences | {p3.get('true_hallucinated_sentences', 'N/A')} |")
        lines.append(f"| Predicted hallucinated | {p3.get('predicted_hallucinated_sentences', 'N/A')} |")
        lines.append(f"| Precision | **{fmt(p3.get('precision'))}** |")
        lines.append(f"| Recall    | **{fmt(p3.get('recall'))}** |")
        lines.append(f"| F1        | **{fmt(p3.get('f1'))}** |")
        lines.append("")
        ht = p3.get("hallucination_type_distribution", {})
        if ht:
            lines.append("### Hallucination Type Distribution\n")
            lines.append("| Type | Count |")
            lines.append("|------|-------|")
            for t, c in sorted(ht.items(), key=lambda x: -x[1]):
                lines.append(f"| {t} | {c} |")
            lines.append("")

    lines.append("## Phase 4 \u2014 Selective Unlearning (Mitigation)\n")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
    lines.append(f"| Total sentences before | {p4.get('total_sentences_before', 'N/A')} |")
    lines.append(f"| Total sentences after | {p4.get('total_sentences_after', 'N/A')} |")
    lines.append(f"| Sentences removed (REMOVE) | {p4.get('sentences_removed', 'N/A')} |")
    lines.append(f"| Sentences hedged (QUALIFY) | {p4.get('sentences_qualified', 'N/A')} |")
    lines.append(f"| Avg length reduction | **{fmt(p4.get('avg_length_reduction_pct'), True)}** |")
    lines.append(f"| Information retention | **{fmt(p4.get('information_retention_pct'), True)}** |")
    lines.append(f"| Hallucination density before | {fmt(p4.get('hallucination_density_before'))} |")
    lines.append("")

    lines.append("## Before vs After Comparison\n")
    lines.append("| | Before Phase 4 | After Phase 4 |")
    lines.append("|--|---------------|---------------|")
    lines.append(f"| Hallucinated sentences | {compare.get('baseline_hallucinated_sentences', 'N/A')} | {compare.get('after_phase4_hallucinated_sentences', 0)} |")
    lines.append(f"| Information retained | 100% | {fmt(compare.get('information_retention_pct'), True)} |")
    lines.append("")

    lines.append("## Qualitative Examples\n")
    lines.append("The following examples illustrate the pipeline's behavior across different hallucination types.\n")
    for ex in examples:
        lines.append(f"### {ex['case_id']} \u2014 Alert: `{ex['alert_type']}` | Type: `{ex['hallucination_type']}`\n")
        lines.append("**Original sentence:**")
        lines.append(f"> {ex['original_sentence']}\n")
        lines.append("**Corrected sentence:**")
        lines.append(f"> {ex['corrected_sentence']}\n")
        lines.append(f"**Why it matters:** {ex['why_it_matters']}\n")
        lines.append(f"**Reason flagged:** {ex['reason']}\n")
        lines.append("---\n")

    lines.append("## Discussion\n")
    lines.append(_DISCUSSION)
    return "\n".join(lines)


def run() -> None:
    with open(config.METRICS_PATH) as f:
        metrics = json.load(f)
    with open(config.COMPARISON_PATH) as f:
        compare = json.load(f)
    with open(config.QUALITATIVE_PATH) as f:
        examples = json.load(f)

    config.REPORT_PATH.write_text(build_report(metrics, compare, examples))
    print(f"Final report written -> {config.REPORT_PATH}")


if __name__ == "__main__":
    run()

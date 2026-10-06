# Annotation Guide - Hallucination Labels
## LLM Cybersecurity Explanation Hallucination Study

## Purpose
This guide is for human annotators filling in the `gold_label` fields in:
- `data/processed/phase2_detection.json` (explanation-level)
- `data/annotations/phase3_predictions.json` (sentence-level)

These gold labels are required to compute Precision, Recall, and F1 (see `evaluation.py`).

## Hallucination Definition

A sentence (or explanation) is **hallucinated** if it contains any claim that is:
1. **Not supported by** the alert evidence field
2. **Contradicts** the alert evidence
3. Uses **unjustified certainty** about attacker intent or outcomes

A sentence is **grounded** if every factual claim it makes can be traced back to the alert evidence.

## Hallucination Types

| Type | Description | Example |
|------|-------------|---------|
| `factual` | Specific CVE, tool name, IP, or version not in the evidence | "exploits CVE-2017-0144" when evidence has no CVE |
| `reasoning` | Causal or logical leap far beyond what evidence shows | "attacker is targeting the database server" when only port 22 is mentioned |
| `certainty` | Overconfident language not justified by evidence | "the server will definitely be compromised" |
| `outdated` | Specific patches, timelines, or versions not derivable from evidence | "this was patched in 2018" |

## Decision Rules

### HALLUCINATED if:
- Mentions a specific CVE not in evidence
- Mentions a tool name (Metasploit, EternalBlue, etc.) not in evidence
- Attributes intent to the attacker ("the attacker wants to...")
- States a definitive outcome ("the server was compromised")
- References a specific timeline or date not in evidence
- Makes a statistical claim not in evidence

### GROUNDED if:
- Restates what the evidence shows (repeated failed logins -> brute force)
- Uses appropriately hedged language ("may indicate", "is consistent with")
- Describes the attack category in general terms matching evidence
- Recommends general defensive actions

### BORDERLINE (annotate as grounded):
- General cybersecurity knowledge stated as background context
- Attack descriptions that match the category label without adding specifics
- Recommended responses that are standard for the attack type

## Inter-annotator Agreement

Two annotators should independently label the same 20% of records.
Compute Cohen's Kappa. Report this in your paper. Target: kappa >= 0.70.

## Effort Estimate
- Phase 2 (explanation level): ~2-3 min per explanation
- Phase 3 (sentence level): ~30 sec per sentence

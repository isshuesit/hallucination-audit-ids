"""
Phase 4: selective unlearning via masking and controlled regeneration.

For each sentence:
  KEEP    - grounded
  REMOVE  - factual / outdated hallucination (CVEs, tools, IPs, versions)
  QUALIFY - reasoning / certainty / external_knowledge (rewrite, don't delete)

IMPORTANT METHODOLOGICAL NOTE (for the paper's limitations section):
  Masks are built from the HUMAN gold label whenever one exists, and from
  the pipeline's own prediction otherwise. So the Phase 4 numbers measure
  what mitigation achieves GIVEN accurate localization (an upper bound on
  end-to-end performance), not what the fully automatic pipeline achieves
  when its own Phase 3 mistakes feed into Phase 4. Run Phase 4 on
  predictions only (no gold labels filled in) to measure the latter.

DESIGN NOTE - why QUALIFY is type-aware (kept from the original project's
debugging history because it is a genuine lesson):
  An earlier version used one QUALIFY prompt for every type and got 0%
  effectiveness. Root cause: that prompt only described how to fix
  external-knowledge issues and said nothing about removing named attack
  categories. 45 of 51 QUALIFY sentences were type=reasoning, so their
  attack terms survived the rewrite verbatim and were flagged again.
  Fix: a different, targeted prompt per hallucination type.
"""

from __future__ import annotations

import json
import time
from collections import defaultdict

from . import config
from .detection import split_sentences
from .llm_client import extract_retry_delay, get_types
from .prompt_store import load_prompt

# type -> action. Unknown / missing types are handled by action_for_type().
HALLUCINATION_ACTION_MAP: dict[str | None, str] = {
    "factual": "REMOVE",
    "outdated": "REMOVE",
    "reasoning": "QUALIFY",
    "certainty": "QUALIFY",
    "external_knowledge": "QUALIFY",
    "external_knowledge_port": "QUALIFY",
    "external_knowledge_protocol": "QUALIFY",
    "external_knowledge_unit": "QUALIFY",
    "external_knowledge_encryption": "QUALIFY",
    "external_knowledge_baseline": "QUALIFY",
    "null": "KEEP",
    "rule_clean": "KEEP",
    None: "KEEP",
}

_TYPE_TO_PROMPT_FILE: dict[str, str] = {
    "reasoning": "qualify_reasoning.txt",
    "certainty": "qualify_certainty.txt",
    "external_knowledge": "qualify_external_knowledge.txt",
    "external_knowledge_port": "qualify_external_knowledge.txt",
    "external_knowledge_protocol": "qualify_external_knowledge.txt",
    "external_knowledge_unit": "qualify_external_knowledge.txt",
    "external_knowledge_baseline": "qualify_external_knowledge.txt",
    "external_knowledge_encryption": "qualify_external_knowledge.txt",
    "invalid_knowledge": "qualify_external_knowledge.txt",
    "overconfidence": "qualify_certainty.txt",
}
_DEFAULT_PROMPT_FILE = "qualify_reasoning.txt"  # safest default for unknown types

# Last-resort text fallback if every LLM attempt fails: at minimum soften
# certainty words, and keep the original sentence rather than inventing one.
_FALLBACK_SUBSTITUTIONS = [
    ("definitely ", "may "),
    ("certainly ", "possibly "),
    ("will ", "may "),
    ("must be ", "may be "),
]


def qualify_prompt_for(h_type: str | None) -> str:
    """Return the QUALIFY prompt text appropriate for a hallucination type."""
    return load_prompt(_TYPE_TO_PROMPT_FILE.get(h_type or "", _DEFAULT_PROMPT_FILE))


def action_for_type(h_type: str | None) -> str:
    """Decide the action for a sentence already known to be hallucinated.
    Hard hallucinations are removed; soft ones are qualified; anything
    unknown is qualified rather than removed (never delete on a guess).
    """
    if h_type is None:
        return "QUALIFY"
    if h_type in ("factual", "outdated"):
        return "REMOVE"
    if (h_type.startswith("external_knowledge")
            or h_type in ("reasoning", "certainty", "invalid_knowledge", "overconfidence")):
        return "QUALIFY"
    return "QUALIFY"


def qualify_sentence(client, sentence: str, h_type: str | None = None, *, sleep: bool = True) -> str:
    """Ask Gemini to rewrite one flagged sentence with the type-specific prompt.

    Thinking mode is switched off (thinking_budget=0): with it on, the model
    spends its output budget reasoning and rewrites are less reliable.

    429 RESOURCE_EXHAUSTED is throttling, not failure: the API's own
    retryDelay is respected and the attempt is NOT counted. Any other error
    counts toward MAX_RETRIES. If everything fails, the original sentence is
    returned with certainty words softened (never an invented sentence and
    never a placeholder that could leak into the corrected explanation).
    """
    gtypes = get_types()
    prompt = qualify_prompt_for(h_type) + sentence

    attempt = 0
    while attempt < config.MAX_RETRIES:
        try:
            response = client.models.generate_content(
                model=config.GEMINI_MODEL,
                contents=prompt,
                config=gtypes.GenerateContentConfig(
                    thinking_config=gtypes.ThinkingConfig(thinking_budget=0),
                ),
            )
            result = response.text.strip()
            if result == sentence:
                print(f"    WARNING: QUALIFY returned an identical sentence for {h_type}")
            return result
        except Exception as e:  # noqa: BLE001 - API errors vary by SDK version
            err = str(e)
            if "429" in err or "RESOURCE_EXHAUSTED" in err:
                wait = extract_retry_delay(e)
                print(f"    QUALIFY rate-limited [{h_type}], sleeping {wait:.0f}s (attempt not consumed)")
                if sleep:
                    time.sleep(wait)
            else:
                attempt += 1
                print(f"    QUALIFY attempt {attempt}/{config.MAX_RETRIES} failed [{h_type}]: {err[:120]}")
                if attempt < config.MAX_RETRIES and sleep:
                    time.sleep(config.RETRY_DELAY_SECONDS * attempt)

    print(f"    QUALIFY retries exhausted for [{h_type}], using text fallback")
    hedged = sentence
    for old, new in _FALLBACK_SUBSTITUTIONS:
        hedged = hedged.replace(old, new)
    return hedged


def build_masks(predictions: list[dict]) -> list[dict]:
    """Decide KEEP / REMOVE / QUALIFY for every sentence.

    The gold (human) label always wins when present; otherwise the
    pipeline's own prediction is used. A hallucinated sentence with no
    type is treated as external_knowledge (the mildest, rewrite-not-delete
    category) so a missing type can never cause an accidental REMOVE.
    """
    masks = []
    for pred in predictions:
        gold = pred.get("gold_label")
        label = gold if gold is not None else pred.get("predicted_label")
        h_type = pred.get("hallucination_type")

        if label == "hallucinated" and not h_type:
            h_type = "external_knowledge"

        action = "KEEP" if label == "grounded" else action_for_type(h_type)
        masks.append({
            "alert_id": pred["alert_id"],
            "sentence_id": pred["sentence_id"],
            "action": action,
            "reason": pred.get("reason", ""),
            "hallucination_type": h_type,
        })
    return masks


def reconstruct_explanation(original_sentences: list[str], sentence_masks: dict[str, dict], client) -> list[str]:
    """Apply masks: KEEP passes through, REMOVE drops, QUALIFY rewrites."""
    corrected = []
    for idx, sentence in enumerate(original_sentences):
        sid = f"S{idx + 1}"
        mask = sentence_masks.get(sid, {"action": "KEEP", "h_type": None})
        action = mask["action"]
        if action == "KEEP":
            corrected.append(sentence)
        elif action == "QUALIFY":
            corrected.append(qualify_sentence(client, sentence, mask.get("h_type")))
        # REMOVE: append nothing
    return corrected


def compute_effect(corrected_records: list[dict]) -> dict:
    """Aggregate sentence counts into the Phase 4 effect summary."""
    total_original = sum(r["original_sentence_count"] for r in corrected_records)
    total_corrected = sum(r["corrected_sentence_count"] for r in corrected_records)
    total_removed = sum(r["sentences_removed"] for r in corrected_records)
    total_qualified = sum(r["sentences_qualified"] for r in corrected_records)

    pct_preserved = total_corrected / total_original if total_original else 0
    hall_rate_before = total_removed / total_original if total_original else 0
    return {
        "total_explanations": len(corrected_records),
        "total_sentences_before": total_original,
        "total_sentences_after": total_corrected,
        "sentences_removed": total_removed,
        "sentences_qualified": total_qualified,
        "avg_length_reduction_pct": round((1 - pct_preserved) * 100, 1),
        "hallucination_rate_before": round(hall_rate_before, 3),
        "estimated_hallucination_rate_after": 0.0,  # measured properly in impact_analysis
        "information_retention_pct": round(pct_preserved * 100, 1),
    }


def run(client) -> dict:
    """Full Phase 4: masks -> corrected explanations -> effect summary."""
    print("=== Phase 4: selective unlearning (masking + reconstruction) ===")
    with open(config.EXPLANATIONS_PATH) as f:
        explanations = json.load(f)
    with open(config.SENTENCE_PREDICTIONS_PATH) as f:
        predictions = json.load(f)

    masks = build_masks(predictions)
    with open(config.MASKS_PATH, "w") as f:
        json.dump(masks, f, indent=2)
    print(f"Saved {len(masks)} sentence masks -> {config.MASKS_PATH}")

    masks_by_alert: dict[str, dict[str, dict]] = defaultdict(dict)
    for m in masks:
        masks_by_alert[m["alert_id"]][m["sentence_id"]] = {
            "action": m["action"], "h_type": m["hallucination_type"],
        }

    corrected_records: list[dict] = []
    new_since_save = 0
    for expl in explanations:
        aid = expl["alert_id"]
        original_sentences = split_sentences(expl["explanation"])
        sentence_masks = masks_by_alert.get(aid, {})
        corrected_sentences = reconstruct_explanation(original_sentences, sentence_masks, client)

        removed = sum(1 for v in sentence_masks.values() if v["action"] == "REMOVE")
        qualified = sum(1 for v in sentence_masks.values() if v["action"] == "QUALIFY")
        corrected_records.append({
            "alert_id": aid,
            "alert_type": expl["alert_type"],
            "original_sentence_count": len(original_sentences),
            "corrected_sentence_count": len(corrected_sentences),
            "sentences_removed": removed,
            "sentences_qualified": qualified,
            "original_explanation": original_sentences,
            "corrected_explanation": corrected_sentences,
        })
        new_since_save += 1
        if new_since_save >= 10:
            with open(config.CORRECTED_PATH, "w") as f:
                json.dump(corrected_records, f, indent=2)
            new_since_save = 0

    with open(config.CORRECTED_PATH, "w") as f:
        json.dump(corrected_records, f, indent=2)
    print(f"Saved {len(corrected_records)} corrected explanations -> {config.CORRECTED_PATH}")

    effect = compute_effect(corrected_records)
    with open(config.EFFECT_PATH, "w") as f:
        json.dump(effect, f, indent=2)
    print(f"Effect analysis -> {config.EFFECT_PATH}")
    return effect

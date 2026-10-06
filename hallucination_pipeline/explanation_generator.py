"""
Phase 2, Step 2: generate LLM explanations for each structured alert.

DESIGN NOTE: alert_type is intentionally excluded from the prompt.
Including it would let the model invoke category-level background
knowledge (e.g. "DDoS" -> "resource exhaustion on web server"), making it
impossible to isolate what the model hallucinates versus what the label
implies. This is the single most important design decision in this phase.

The system prompt is loaded verbatim from prompts/generate_system.txt - it
is part of the experimental protocol and must not be paraphrased.

Requires a live GEMINI_API_KEY.
"""

from __future__ import annotations

import json
import time

from . import config
from .llm_client import get_client
from .prompt_store import load_prompt


def build_prompt(alert: dict) -> str:
    return (
        f"{load_prompt('generate_system.txt')}\n"
        f"Evidence:\n{alert['evidence']}\n\n"
        "Explain what this network flow data indicates from a security perspective.\n"
    )


def generate_one(client, alert: dict, *, sleep: bool = True) -> dict:
    prompt = build_prompt(alert)
    base = {
        "alert_id": alert["alert_id"],
        "alert_type": alert["alert_type"],
        "prompt": prompt,
        "model": config.GEMINI_MODEL,
        "input_tokens": 0,
        "output_tokens": 0,
    }
    for attempt in range(config.MAX_RETRIES):
        try:
            response = client.models.generate_content(model=config.GEMINI_MODEL, contents=prompt)
            return {**base, "explanation": response.text.strip()}
        except Exception as e:  # noqa: BLE001
            print(f"    [{alert['alert_id']}] error on attempt {attempt + 1}/{config.MAX_RETRIES}: {e}")
            if sleep:
                time.sleep(config.RETRY_DELAY_SECONDS * (attempt + 1))
    return {**base, "explanation": "[GENERATION FAILED]"}


def run() -> list[dict]:
    print("=== Phase 2, Step 2: generating LLM explanations ===")
    client = get_client()

    with open(config.ALERTS_PATH) as f:
        alerts: list[dict] = json.load(f)
    print(f"Loaded {len(alerts)} alerts.")

    explanations: list[dict] = []
    done_ids: set[str] = set()
    if config.EXPLANATIONS_PATH.exists():
        with open(config.EXPLANATIONS_PATH) as f:
            explanations = json.load(f)
        done_ids = {e["alert_id"] for e in explanations}
        print(f"Resuming: {len(done_ids)} already done.")

    pending = [a for a in alerts if a["alert_id"] not in done_ids]
    print(f"Pending: {len(pending)} alerts.")

    new_since_save = 0
    for i, alert in enumerate(pending):
        print(f"[{i + 1}/{len(pending)}] {alert['alert_id']} - {alert['alert_type']}")
        explanations.append(generate_one(client, alert))
        new_since_save += 1
        if new_since_save >= config.SAVE_EVERY:
            with open(config.EXPLANATIONS_PATH, "w") as f:
                json.dump(explanations, f, indent=2)
            new_since_save = 0
        time.sleep(0.5)  # stay within rate limits

    with open(config.EXPLANATIONS_PATH, "w") as f:
        json.dump(explanations, f, indent=2)
    print(f"Saved {len(explanations)} explanations -> {config.EXPLANATIONS_PATH}")
    return explanations


if __name__ == "__main__":
    run()

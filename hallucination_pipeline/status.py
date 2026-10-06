"""Print the current state of all pipeline artifacts. Run any time to see
what's done and what's missing: python -m hallucination_pipeline.cli status
"""

from __future__ import annotations

import json
from pathlib import Path

from . import config

ARTIFACTS = [
    (config.RAW_DIR / "*.csv", "CIC-IDS 2017 raw CSV files", "load"),
    (config.ALERTS_PATH, "Structured alerts", "load"),
    (config.EXPLANATIONS_PATH, "LLM explanations", "generate"),
    (config.DETECTION_PATH, "Explanation-level hallucination flags", "detect"),
    (config.SENTENCE_PREDICTIONS_PATH, "Sentence-level predictions", "localize"),
    (config.MASKS_PATH, "Hallucination action masks", "unlearn"),
    (config.CORRECTED_PATH, "Corrected explanations", "unlearn"),
    (config.EFFECT_PATH, "Phase 4 effect analysis", "unlearn"),
    (config.METRICS_PATH, "End-to-end metrics", "evaluate"),
    (config.COMPARISON_PATH, "Comparison analysis", "evaluate"),
    (config.QUALITATIVE_PATH, "Qualitative examples", "evaluate"),
    (config.REPORT_PATH, "Final markdown report", "report"),
    (config.IMPACT_PATH, "Unlearning impact analysis", "impact"),
]


def _check_gold_labels(path: Path, key: str = "gold_label") -> str:
    try:
        with open(path) as f:
            data = json.load(f)
        filled = sum(1 for d in data if d.get(key) is not None)
        return f" ({filled}/{len(data)} gold labels filled)"
    except Exception:
        return ""


def run() -> None:
    print("=" * 65)
    print("Pipeline Status")
    print("=" * 65)

    for path_or_glob, description, phase in ARTIFACTS:
        if "*" in str(path_or_glob):
            matches = list(config.RAW_DIR.glob("*.csv"))
            status_line = f"[{len(matches)} file(s)]" if matches else f"[MISSING - run '{phase}']"
            icon = "OK " if matches else "-- "
        else:
            p = Path(path_or_glob)
            if p.exists():
                extra = _check_gold_labels(p) if ("detection" in p.name or "predictions" in p.name) else ""
                status_line = f"[{p.stat().st_size / 1024:.1f} KB]{extra}"
                icon = "OK "
            else:
                status_line = f"[MISSING - run '{phase}']"
                icon = "-- "
        print(f"  {icon} {description:<40} {status_line}")

    print()
    for path in [config.DETECTION_PATH, config.SENTENCE_PREDICTIONS_PATH]:
        if path.exists():
            with open(path) as f:
                data = json.load(f)
            unfilled = sum(1 for d in data if d.get("gold_label") is None)
            if unfilled:
                print(f"NOTE: {unfilled} records in {path.name} still need gold_label annotation.")


if __name__ == "__main__":
    run()

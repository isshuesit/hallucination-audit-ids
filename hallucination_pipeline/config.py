"""
Central configuration for the hallucination detection/mitigation pipeline.

IMPORTANT FIX: the original project's README said `ANTHROPIC_API_KEY`, but
every script actually reads `GEMINI_API_KEY` (this project uses Google's
Gemini, not Claude, as the explanation-generating LLM). That mismatch is
fixed here and in the README - this is the single source of truth for the
env var name so it can't drift out of sync again.
"""

from __future__ import annotations

import os
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────
# HALLUC_ROOT lets you point the pipeline at a different data root (used by
# the verification harness and for running experiments side by side, e.g. a
# "frozen" reproduction run and a "fresh" run, without mixing their files).
ROOT_DIR = Path(os.environ.get("HALLUC_ROOT") or Path(__file__).resolve().parent.parent)
PROMPTS_DIR = Path(__file__).resolve().parent / "prompts"

RAW_DIR = ROOT_DIR / "data" / "raw"
PROCESSED_DIR = ROOT_DIR / "data" / "processed"
ANNOTATIONS_DIR = ROOT_DIR / "data" / "annotations"
OUTPUTS_DIR = ROOT_DIR / "outputs"

for _d in (RAW_DIR, PROCESSED_DIR, ANNOTATIONS_DIR, OUTPUTS_DIR):
    _d.mkdir(parents=True, exist_ok=True)

ALERTS_PATH = PROCESSED_DIR / "alerts.json"
EXPLANATIONS_PATH = PROCESSED_DIR / "llm_explanations.json"
DETECTION_PATH = PROCESSED_DIR / "phase2_detection.json"
SENTENCE_PREDICTIONS_PATH = ANNOTATIONS_DIR / "phase3_predictions.json"
SENTENCE_GOLD_PATH = ANNOTATIONS_DIR / "sentence_gold_labels.json"
MASKS_PATH = PROCESSED_DIR / "hallucination_masks.json"
CORRECTED_PATH = PROCESSED_DIR / "corrected_explanations.json"
EFFECT_PATH = PROCESSED_DIR / "phase4_effect_analysis.json"

METRICS_PATH = OUTPUTS_DIR / "end_to_end_metrics.json"
COMPARISON_PATH = OUTPUTS_DIR / "comparison_analysis.json"
QUALITATIVE_PATH = OUTPUTS_DIR / "qualitative_examples.json"
REPORT_PATH = OUTPUTS_DIR / "final_report.md"
IMPACT_PATH = OUTPUTS_DIR / "unlearning_impact.json"
IMPACT_REPORT_PATH = OUTPUTS_DIR / "unlearning_impact_report.md"

# ── LLM settings ──────────────────────────────────────────────────────────
GEMINI_MODEL = "gemini-2.5-flash"
GEMINI_API_KEY_ENV_VAR = "GEMINI_API_KEY"  # <- the actually-correct name
MAX_RETRIES = 3
RETRY_DELAY_SECONDS = 5

# Labels that mean "not an attack". CIC-IDS 2017 copies name benign flows differently:
# the original CSVs use "BENIGN"; the processed 'Attack Type' version uses "Normal Traffic".
# The original loader excluded only "BENIGN", so on the 'Attack Type' version 337 of the
# 400 "attack" alerts were actually benign traffic (see tools/reproduce_frozen.py).
BENIGN_LABELS = {"benign", "normal traffic", "normal"}

# ── Pipeline settings ─────────────────────────────────────────────────────
TARGET_ALERT_COUNT = 400
RANDOM_SEED = 42
SAVE_EVERY = 5


def get_api_key() -> str:
    """Read the Gemini API key from the environment, or raise a clear error."""
    key = os.environ.get(GEMINI_API_KEY_ENV_VAR)
    if not key:
        raise EnvironmentError(
            f"{GEMINI_API_KEY_ENV_VAR} is not set. "
            f"Run: export {GEMINI_API_KEY_ENV_VAR}='your-key-here'"
        )
    return key

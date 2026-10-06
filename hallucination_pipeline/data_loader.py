"""
Load CIC-IDS 2017 and build structured, evidence-pure alert objects.

EVIDENCE PURITY (this is the whole point of this module):
  Evidence strings contain ONLY raw observables - numbers, ports, flag
  counts, flow statistics. Zero interpretive language. The attack label is
  stored separately and NEVER included in the evidence field fed to the LLM.

  Why this matters: hallucination is defined here as "the LLM said
  something not derivable from the evidence." That test is only valid if
  the evidence itself contains no interpretation. If evidence said "This
  looks like a brute-force" and the LLM echoed it, that's not a detectable
  hallucination - it would just be copying. Evidence that says only
  "SYN Flag Count: 450, Destination Port: 22" forces any claim about
  brute-forcing to be an inference the LLM adds - which can be audited.

Download the dataset: https://www.unb.ca/cic/datasets/ids-2017.html
Place CSV files in: data/raw/
"""

from __future__ import annotations

import json
import re

import numpy as np
import pandas as pd

from . import config


def safe_int(val) -> str:
    try:
        v = float(val)
        if np.isfinite(v):
            return str(int(v))
    except (TypeError, ValueError):
        pass
    return ""


def safe_float(val) -> str:
    try:
        v = float(val)
        if np.isfinite(v):
            return f"{v:.2f}"
    except (TypeError, ValueError):
        pass
    return ""


def build_evidence_string(row: pd.Series) -> str:
    """Build an evidence-pure string from raw CIC-IDS 2017 flow features.
    Only numeric observables go in - no interpretive language, ever.
    """
    fields = []

    def get(col: str):
        return row.get(col, row.get(col.strip(), None))

    if safe_int(get("Destination Port")):
        fields.append(f"Destination Port: {safe_int(get('Destination Port'))}")
    if safe_int(get("Flow Duration")):
        fields.append(f"Flow Duration: {safe_int(get('Flow Duration'))}")
    if safe_int(get("Total Fwd Packets")):
        fields.append(f"Forward Packets: {safe_int(get('Total Fwd Packets'))}")
    if safe_int(get("Total Backward Packets")):
        fields.append(f"Backward Packets: {safe_int(get('Total Backward Packets'))}")
    if safe_float(get("Flow Bytes/s")):
        fields.append(f"Flow Bytes/s: {safe_float(get('Flow Bytes/s'))}")
    if safe_float(get("Flow Packets/s")):
        fields.append(f"Flow Packets/s: {safe_float(get('Flow Packets/s'))}")
    for flag in ["SYN", "ACK", "RST"]:
        val = safe_int(get(f"{flag} Flag Count"))
        if val:
            fields.append(f"{flag} Flag Count: {val}")

    return "\n".join(fields)


def extract_evidence_tokens(evidence: str) -> list[str]:
    """Pull out the numeric tokens actually present in the evidence string,
    for later use checking whether the LLM's explanation references
    numbers/ports that were never in the evidence.
    """
    return sorted(set(re.findall(r"\d+", evidence)))  # sorted: deterministic output


def load_raw_csvs() -> pd.DataFrame:
    files = list(config.RAW_DIR.glob("*.csv"))
    if not files:
        raise FileNotFoundError(
            f"No CSV files found in {config.RAW_DIR}. "
            "Download CIC-IDS 2017 from https://www.unb.ca/cic/datasets/ids-2017.html"
        )
    dfs = []
    for f in files:
        print(f"Loading {f.name}")
        df = pd.read_csv(f, low_memory=False)
        df.columns = df.columns.str.strip()  # CIC-IDS CSVs have inconsistent whitespace
        dfs.append(df)
    combined = pd.concat(dfs, ignore_index=True)
    print(f"Loaded {len(combined):,} rows total")
    return combined


def sample_attack_alerts(
    df: pd.DataFrame,
    target_count: int = config.TARGET_ALERT_COUNT,
    seed: int = config.RANDOM_SEED,
) -> pd.DataFrame:
    if "Attack Type" in df.columns:
        df = df.copy()
        df["Label"] = df["Attack Type"]
    elif "Label" not in df.columns:
        raise ValueError("Dataset has neither 'Attack Type' nor 'Label' column")

    df["Label"] = df["Label"].astype(str).str.strip()
    # DELIBERATE DEVIATION FROM THE ORIGINAL: drop every benign spelling, not just "BENIGN".
    attacks = df[~df["Label"].str.lower().isin(config.BENIGN_LABELS)]
    print("Attack-class label counts available:", dict(attacks["Label"].value_counts()))

    n = min(len(attacks), target_count)
    sampled = attacks.sample(n=n, random_state=seed)
    print(f"Sampled {len(sampled)} attack alerts (target was {target_count})")
    return sampled


def build_alert(idx: int, row: pd.Series) -> dict:
    evidence = build_evidence_string(row)
    return {
        "alert_id": f"A{idx:03d}",
        "alert_type": row["Label"],
        "evidence": evidence,
        "evidence_tokens": extract_evidence_tokens(evidence),
    }


def run() -> list[dict]:
    print("=== Loading CIC-IDS 2017 and building evidence-pure alerts ===")
    df = load_raw_csvs()
    sampled = sample_attack_alerts(df)

    alerts = [
        build_alert(i + 1, row)
        for i, (_, row) in enumerate(sampled.iterrows())
    ]

    with open(config.ALERTS_PATH, "w") as f:
        json.dump(alerts, f, indent=2)

    print(f"Saved {len(alerts)} alerts -> {config.ALERTS_PATH}")
    return alerts


if __name__ == "__main__":
    run()

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
from pathlib import Path

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


# ── fresh-run loader: validated columns + dataset fingerprint ─────────────

# Columns the evidence builder reads, plus the label. Names as in the original UNB
# CSVs after stripping their leading spaces (e.g. " Destination Port").
REQUIRED_COLUMNS = (
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Flow Bytes/s", "Flow Packets/s", "SYN Flag Count", "ACK Flag Count", "RST Flag Count", "Label",
)


EVIDENCE_COLUMNS = tuple(c for c in REQUIRED_COLUMNS if c != "Label")


class MissingColumnsError(ValueError):
    pass


# The UNB Thursday file spells three labels with U+FFFD (the Unicode replacement character)
# where a dash belongs: "Web Attack � Brute Force", "... XSS", "... Sql Injection".
# Copies decoded as cp1252 show the original byte 0x96 as an en dash instead. Both, and other
# dash variants, become "-" so each label stays one class.
_DASH_VARIANTS = re.compile("[�–—\x96]")


def normalize_label(label) -> str:
    """'Web Attack \\ufffd Brute Force' -> 'Web Attack - Brute Force' (whitespace collapsed, stripped)."""
    return re.sub(r"\s+", " ", _DASH_VARIANTS.sub("-", str(label))).strip()


def _detect_encoding(path: Path) -> str:
    """'utf-8' if the whole file decodes as UTF-8 (true for the UNB MachineLearningCSV files),
    else 'cp1252' (copies that keep the original 0x96 dash byte)."""
    try:
        with open(path, encoding="utf-8") as f:
            while f.read(1 << 22):
                pass
        return "utf-8"
    except UnicodeDecodeError:
        print(f"  {path.name}: not valid UTF-8, reading as cp1252")
        return "cp1252"


def check_required_columns(columns_by_file: dict[str, list[str]]) -> None:
    """Raise MissingColumnsError naming every file and every missing column."""
    problems = {}
    for name, cols in columns_by_file.items():
        stripped = {str(c).strip() for c in cols}
        missing = [c for c in REQUIRED_COLUMNS if c not in stripped]
        if missing:
            problems[name] = missing
    if problems:
        detail = "\n".join(f"  {name}: missing {', '.join(cols)}" for name, cols in problems.items())
        raise MissingColumnsError(
            "Some CSV files lack required CIC-IDS 2017 columns (names are compared after "
            "stripping spaces):\n" + detail + "\nRequired columns: " + ", ".join(REQUIRED_COLUMNS)
            + "\nUse the original UNB CSVs (MachineLearningCVE), see docs/DECISIONS.md D1."
        )


def load_cicids(raw_dir: Path) -> tuple[pd.DataFrame, dict]:
    """Load every CSV in raw_dir (sorted by name), keeping only REQUIRED_COLUMNS.

    Checks all headers first and stops with a clear error if any column is missing.
    Returns (dataframe with a `source_file` column, dataset fingerprint for the manifest).
    """
    from .run_dir import file_sha256

    files = sorted(Path(raw_dir).glob("*.csv"))
    if not files:
        raise FileNotFoundError(
            f"No CSV files found in {raw_dir}. "
            "Download CIC-IDS 2017 from https://www.unb.ca/cic/datasets/ids-2017.html"
        )
    encodings = {f.name: _detect_encoding(f) for f in files}
    headers = {f.name: list(pd.read_csv(f, nrows=0, encoding=encodings[f.name]).columns) for f in files}
    check_required_columns(headers)

    frames, fingerprint = [], []
    for f in files:
        rename = {c: str(c).strip() for c in headers[f.name] if str(c).strip() in REQUIRED_COLUMNS}
        df = pd.read_csv(f, usecols=list(rename), encoding=encodings[f.name], low_memory=False)
        df = df.rename(columns=rename)
        df["Label"] = df["Label"].map(normalize_label)
        df["source_file"] = f.name
        df["source_row"] = range(len(df))   # 0-based data row in that file, for traceability
        print(f"Loaded {f.name}: {len(df):,} rows")
        frames.append(df)
        fingerprint.append({"name": f.name, "sha256": file_sha256(f), "bytes": f.stat().st_size, "rows": len(df),
                            "encoding": encodings[f.name]})
    combined = pd.concat(frames, ignore_index=True)
    print(f"Loaded {len(combined):,} rows total from {len(files)} file(s)")
    return combined, {"files": fingerprint, "total_rows": len(combined)}


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

"""
M1: stratified, attack-only alert sampling with asserted label hygiene.

Audit lesson 1: the old loader excluded only the label "BENIGN", so 337 of its 400
"attack" alerts were benign flows. Here benign flows are recognised by every
spelling in config.BENIGN_LABELS, every fine label must map to a known coarse
class (an unknown label stops the run), and the realized class distribution is
printed, saved and asserted.

Sampling (DECISIONS D2): per fine label, min(per_class_cap, available) rows,
drawn with the run seed. Each class is drawn independently, so adding or removing
rows of one class never changes which rows are drawn for another.
Benign control arm (D9): a separate seeded sample, written to its own file and
never mixed into the attack alerts.
"""

from __future__ import annotations

import re

import pandas as pd

from . import config
from .data_loader import build_evidence_string, extract_evidence_tokens


class LabelHygieneError(AssertionError):
    pass


# ── labels ────────────────────────────────────────────────────────────────

_DASHES = re.compile("[–—\x96�]")   # en/em dash, cp1252 0x96, replacement char


def normalize_label(label: str) -> str:
    """'Web Attack \\x96 Brute Force' (raw UNB bytes) -> 'Web Attack - Brute Force'."""
    return re.sub(r"\s+", " ", _DASHES.sub("-", str(label))).strip()


def is_benign(label: str) -> bool:
    return normalize_label(label).lower() in config.BENIGN_LABELS


def coarse_label(fine: str) -> str:
    """Fine CIC-IDS 2017 label -> coarse class (DECISIONS D1). Unknown labels raise."""
    f = normalize_label(fine).lower()
    if f in config.BENIGN_LABELS:
        return "Benign"
    if f == "ddos":
        return "DDoS"
    if f.startswith("dos "):
        return "DoS"
    if f == "portscan":
        return "Port Scanning"
    if f.endswith("-patator"):
        return "Brute Force"
    if f.startswith("web attack"):
        return "Web Attack"
    if f == "bot":
        return "Botnet"
    if f == "infiltration":
        return "Infiltration"
    if f == "heartbleed":
        return "Heartbleed"
    raise LabelHygieneError(f"Unknown CIC-IDS 2017 label {fine!r}: add it to sampling.coarse_label "
                            "(and docs/DECISIONS.md) before sampling")


# ── sampling ──────────────────────────────────────────────────────────────

def stratified_attack_sample(df: pd.DataFrame, per_class_cap: int, seed: int) -> pd.DataFrame:
    """Attack rows only: per fine label, min(per_class_cap, available) rows drawn with `seed`.
    Output order: by fine label (alphabetical), then by position in the source data."""
    attacks = df[~df["Label"].map(is_benign)]
    parts = []
    for label in sorted(attacks["Label"].unique()):
        group = attacks[attacks["Label"] == label]
        parts.append(group.sample(n=min(per_class_cap, len(group)), random_state=seed).sort_index())
    return pd.concat(parts) if parts else attacks.iloc[0:0]


def benign_control_sample(df: pd.DataFrame, n: int, seed: int) -> pd.DataFrame:
    benign = df[df["Label"].map(is_benign)]
    return benign.sample(n=min(n, len(benign)), random_state=seed).sort_index()


def make_alert(alert_id: str, row: pd.Series, run_id: str, arm: str) -> dict:
    evidence = build_evidence_string(row)
    return {
        "alert_id": alert_id,
        "arm": arm,
        "alert_type": row["Label"],
        "label_fine": row["Label"],
        "label_coarse": coarse_label(row["Label"]),
        "source_file": row.get("source_file"),
        "source_row": int(row["source_row"]) if "source_row" in row else None,
        "evidence": evidence,
        "evidence_tokens": extract_evidence_tokens(evidence),
        "run_id": run_id,
    }


# ── distribution: compute, assert, print ──────────────────────────────────

def class_distribution(df: pd.DataFrame, attack_alerts: list[dict], benign_alerts: list[dict],
                       per_class_cap: int, seed: int, benign_control_n: int) -> dict:
    available = df["Label"].value_counts()
    attack_available = {k: int(v) for k, v in sorted(available.items()) if not is_benign(k)}
    realized: dict[str, int] = {}
    for a in attack_alerts:
        realized[a["label_fine"]] = realized.get(a["label_fine"], 0) + 1
    coarse: dict[str, int] = {}
    for a in attack_alerts:
        coarse[a["label_coarse"]] = coarse.get(a["label_coarse"], 0) + 1
    evidences = [a["evidence"] for a in attack_alerts]
    return {
        "per_class_cap": per_class_cap,
        "seed": seed,
        "available_attack": attack_available,
        "available_benign": {k: int(v) for k, v in sorted(available.items()) if is_benign(k)},
        "realized_fine": dict(sorted(realized.items())),
        "realized_coarse": dict(sorted(coarse.items())),
        "total_attack_alerts": len(attack_alerts),
        "classes_below_cap": {k: v for k, v in attack_available.items() if v < per_class_cap},
        "fine_to_coarse": {k: coarse_label(k) for k in sorted(available.index)},
        "benign_control": {"requested": benign_control_n, "realized": len(benign_alerts)},
        "attack_alerts_with_duplicate_evidence": len(evidences) - len(set(evidences)),
        "attack_alerts_with_empty_evidence": sum(not e for e in evidences),
    }


def assert_distribution(dist: dict, attack_alerts: list[dict], benign_alerts: list[dict]) -> None:
    """Label hygiene checks. Raises LabelHygieneError on any violation."""
    problems = []
    leaked = sorted({a["label_fine"] for a in attack_alerts if is_benign(a["label_fine"])})
    if leaked:
        problems.append(f"benign label(s) in the attack set: {leaked}")
    not_benign = sorted({a["label_fine"] for a in benign_alerts if not is_benign(a["label_fine"])})
    if not_benign:
        problems.append(f"attack label(s) in the benign control set: {not_benign}")
    cap = dist["per_class_cap"]
    for label, avail in dist["available_attack"].items():
        want, got = min(cap, avail), dist["realized_fine"].get(label, 0)
        if want != got:
            problems.append(f"{label}: realized {got}, expected min(cap={cap}, available={avail}) = {want}")
    extra = set(dist["realized_fine"]) - set(dist["available_attack"])
    if extra:
        problems.append(f"realized classes not in the data: {sorted(extra)}")
    if dist["total_attack_alerts"] != sum(dist["realized_fine"].values()):
        problems.append("total does not equal the sum of per-class counts")
    ids = [a["alert_id"] for a in attack_alerts + benign_alerts]
    if len(ids) != len(set(ids)):
        problems.append("duplicate alert ids")
    if problems:
        raise LabelHygieneError("Class distribution check FAILED:\n  " + "\n  ".join(problems))


def format_distribution(dist: dict) -> str:
    lines = [f"Realized attack sample (cap {dist['per_class_cap']}, seed {dist['seed']}):",
             f"  {'fine label':<32}{'coarse':<16}{'available':>10}{'sampled':>9}"]
    for label, n in dist["realized_fine"].items():
        lines.append(f"  {label:<32}{dist['fine_to_coarse'][label]:<16}"
                     f"{dist['available_attack'][label]:>10,}{n:>9}")
    lines.append(f"  {'TOTAL':<48}{sum(dist['available_attack'].values()):>10,}{dist['total_attack_alerts']:>9}")
    lines.append(f"Benign rows excluded from the attack set: {dist['available_benign']}")
    lines.append(f"Benign control arm: {dist['benign_control']['realized']} of "
                 f"{dist['benign_control']['requested']} requested (separate file)")
    if dist["attack_alerts_with_duplicate_evidence"]:
        lines.append(f"Note: {dist['attack_alerts_with_duplicate_evidence']} attack alert(s) repeat another "
                     "alert's evidence exactly")
    return "\n".join(lines)


def build_samples(df: pd.DataFrame, per_class_cap: int, seed: int, benign_control_n: int,
                  run_id: str) -> tuple[list[dict], list[dict], dict]:
    """Returns (attack alerts, benign control alerts, asserted class distribution)."""
    df = df.copy()
    df["Label"] = df["Label"].map(normalize_label)
    for label in df["Label"].unique():
        coarse_label(label)   # fail fast on unknown labels, before any sampling
    attacks = stratified_attack_sample(df, per_class_cap, seed)
    benign = benign_control_sample(df, benign_control_n, seed)
    attack_alerts = [make_alert(f"A{i:04d}", row, run_id, "attack")
                     for i, (_, row) in enumerate(attacks.iterrows(), start=1)]
    benign_alerts = [make_alert(f"B{i:04d}", row, run_id, "benign_control")
                     for i, (_, row) in enumerate(benign.iterrows(), start=1)]
    dist = class_distribution(df, attack_alerts, benign_alerts, per_class_cap, seed, benign_control_n)
    assert_distribution(dist, attack_alerts, benign_alerts)
    print(format_distribution(dist))
    return attack_alerts, benign_alerts, dist

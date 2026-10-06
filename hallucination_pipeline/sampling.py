"""
M1: stratified, attack-only alert sampling with asserted label hygiene.

Audit lesson 1: the old loader excluded only the label "BENIGN", so 337 of its 400
"attack" alerts were benign flows. Here benign flows are recognised by every
spelling in config.BENIGN_LABELS, every fine label must map to a known coarse
class (an unknown label stops the run), and the realized class distribution is
printed, saved and asserted.

Eligibility, applied before sampling and reported per class:
  D12  only rows whose nine evidence fields are all present and finite, so every
       evidence string has the same nine lines (applies to the benign control too);
  D11  exact duplicates within an attack class (identical values in all nine
       evidence columns) are removed, keeping the first occurrence in file order.
The two filters commute: a group of identical rows is either entirely finite or
entirely not, so the eligible set is the same whichever runs first.

Sampling (D2): per fine label, min(per_class_cap, eligible) rows, drawn with the run
seed. Each class is drawn independently, so one class never changes another's draw.
Benign control arm (D9): a separate seeded sample of eligible benign rows, written to
its own file and never mixed into the attack alerts.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from . import config
from .data_loader import EVIDENCE_COLUMNS, build_evidence_string, extract_evidence_tokens, normalize_label


class LabelHygieneError(AssertionError):
    pass


# ── labels ────────────────────────────────────────────────────────────────

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


# ── eligibility (D11, D12) ────────────────────────────────────────────────

def finite_evidence_mask(df: pd.DataFrame) -> pd.Series:
    """True where all nine evidence fields are present and finite (D12)."""
    values = df[list(EVIDENCE_COLUMNS)].apply(pd.to_numeric, errors="coerce").to_numpy(dtype=float)
    return pd.Series(np.isfinite(values).all(axis=1), index=df.index)


def eligible_rows(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, dict]:
    """Returns (eligible attack rows, eligible benign rows, per-label filter report)."""
    finite = finite_evidence_mask(df)
    benign = df["Label"].map(is_benign)
    attack_finite = df[~benign & finite]
    dup = attack_finite.duplicated(subset=[*EVIDENCE_COLUMNS, "Label"], keep="first")
    attacks = attack_finite[~dup]
    report = {}
    for label, group in df.groupby("Label", sort=True):
        n_finite = int(finite[group.index].sum())
        dropped_dup = 0 if is_benign(label) else int(dup[attack_finite["Label"] == label].sum())
        report[label] = {"rows": len(group), "dropped_nonfinite": len(group) - n_finite,
                         "dropped_duplicate": dropped_dup, "eligible": n_finite - dropped_dup}
    return attacks, df[benign & finite], report


# ── sampling ──────────────────────────────────────────────────────────────

def stratified_attack_sample(attacks: pd.DataFrame, per_class_cap: int, seed: int) -> pd.DataFrame:
    """Per fine label, min(per_class_cap, available) rows drawn with `seed`.
    Output order: by fine label (alphabetical), then by position in the source data."""
    parts = []
    for label in sorted(attacks["Label"].unique()):
        group = attacks[attacks["Label"] == label]
        parts.append(group.sample(n=min(per_class_cap, len(group)), random_state=seed).sort_index())
    return pd.concat(parts) if parts else attacks.iloc[0:0]


def benign_control_sample(benign: pd.DataFrame, n: int, seed: int) -> pd.DataFrame:
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

def class_distribution(report: dict, attack_alerts: list[dict], benign_alerts: list[dict],
                       per_class_cap: int, seed: int, benign_control_n: int) -> dict:
    attack_report = {k: v for k, v in report.items() if not is_benign(k)}
    realized: dict[str, int] = {}
    coarse: dict[str, int] = {}
    for a in attack_alerts:
        realized[a["label_fine"]] = realized.get(a["label_fine"], 0) + 1
        coarse[a["label_coarse"]] = coarse.get(a["label_coarse"], 0) + 1
    eligible = {k: v["eligible"] for k, v in attack_report.items()}
    total = lambda key: sum(v[key] for v in attack_report.values())
    evidences = [a["evidence"] for a in attack_alerts]
    return {
        "per_class_cap": per_class_cap,
        "seed": seed,
        "filters": "D12 non-finite evidence dropped, then D11 exact duplicates within each attack class dropped",
        "attack_classes": {k: {**v, "coarse": coarse_label(k), "sampled": realized.get(k, 0)}
                           for k, v in attack_report.items()},
        "attack_totals": {"rows": total("rows"), "dropped_nonfinite": total("dropped_nonfinite"),
                          "dropped_duplicate": total("dropped_duplicate"), "eligible": total("eligible")},
        "eligible_attack": eligible,
        "benign": {k: v for k, v in report.items() if is_benign(k)},
        "realized_fine": dict(sorted(realized.items())),
        "realized_coarse": dict(sorted(coarse.items())),
        "total_attack_alerts": len(attack_alerts),
        "classes_below_cap": {k: v for k, v in eligible.items() if v < per_class_cap},
        "fine_to_coarse": {k: coarse_label(k) for k in sorted(report)},
        "benign_control": {"requested": benign_control_n, "realized": len(benign_alerts)},
        "attack_alerts_with_duplicate_evidence_string": len(evidences) - len(set(evidences)),
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
    for label, avail in dist["eligible_attack"].items():
        want, got = min(cap, avail), dist["realized_fine"].get(label, 0)
        if want != got:
            problems.append(f"{label}: realized {got}, expected min(cap={cap}, eligible={avail}) = {want}")
    extra = set(dist["realized_fine"]) - set(dist["eligible_attack"])
    if extra:
        problems.append(f"realized classes not in the data: {sorted(extra)}")
    if dist["total_attack_alerts"] != sum(dist["realized_fine"].values()):
        problems.append("total does not equal the sum of per-class counts")
    ids = [a["alert_id"] for a in attack_alerts + benign_alerts]
    if len(ids) != len(set(ids)):
        problems.append("duplicate alert ids")
    short = [a["alert_id"] for a in attack_alerts + benign_alerts
             if len(a["evidence"].splitlines()) != len(EVIDENCE_COLUMNS)]
    if short:
        problems.append(f"{len(short)} alert(s) without all {len(EVIDENCE_COLUMNS)} evidence lines: {short[:5]}")
    if problems:
        raise LabelHygieneError("Class distribution check FAILED:\n  " + "\n  ".join(problems))


def format_distribution(dist: dict) -> str:
    lines = [f"Realized attack sample (cap {dist['per_class_cap']}, seed {dist['seed']}):",
             f"  {'fine label':<28}{'coarse':<15}{'rows':>9}{'non-finite':>11}{'duplicate':>10}"
             f"{'eligible':>9}{'sampled':>8}"]
    for label, c in dist["attack_classes"].items():
        lines.append(f"  {label:<28}{c['coarse']:<15}{c['rows']:>9,}{c['dropped_nonfinite']:>11,}"
                     f"{c['dropped_duplicate']:>10,}{c['eligible']:>9,}{c['sampled']:>8}")
    t = dist["attack_totals"]
    lines.append(f"  {'TOTAL':<43}{t['rows']:>9,}{t['dropped_nonfinite']:>11,}{t['dropped_duplicate']:>10,}"
                 f"{t['eligible']:>9,}{dist['total_attack_alerts']:>8}")
    for label, b in dist["benign"].items():
        lines.append(f"Benign label {label!r}: {b['rows']:,} rows excluded from the attack set "
                     f"({b['dropped_nonfinite']:,} non-finite)")
    lines.append(f"Benign control arm: {dist['benign_control']['realized']} of "
                 f"{dist['benign_control']['requested']} requested (separate file)")
    if dist["attack_alerts_with_duplicate_evidence_string"]:
        lines.append(f"Note: {dist['attack_alerts_with_duplicate_evidence_string']} sampled attack alert(s) repeat "
                     "another alert's evidence string (values equal after rounding)")
    return "\n".join(lines)


def build_samples(df: pd.DataFrame, per_class_cap: int, seed: int, benign_control_n: int,
                  run_id: str) -> tuple[list[dict], list[dict], dict]:
    """Returns (attack alerts, benign control alerts, asserted class distribution)."""
    df = df.copy()
    df["Label"] = df["Label"].map(normalize_label)
    for label in df["Label"].unique():
        coarse_label(label)   # fail fast on unknown labels, before any sampling
    eligible_attacks, eligible_benign, report = eligible_rows(df)
    attacks = stratified_attack_sample(eligible_attacks, per_class_cap, seed)
    benign = benign_control_sample(eligible_benign, benign_control_n, seed)
    attack_alerts = [make_alert(f"A{i:04d}", row, run_id, "attack")
                     for i, (_, row) in enumerate(attacks.iterrows(), start=1)]
    benign_alerts = [make_alert(f"B{i:04d}", row, run_id, "benign_control")
                     for i, (_, row) in enumerate(benign.iterrows(), start=1)]
    dist = class_distribution(report, attack_alerts, benign_alerts, per_class_cap, seed, benign_control_n)
    assert_distribution(dist, attack_alerts, benign_alerts)
    print(format_distribution(dist))
    return attack_alerts, benign_alerts, dist

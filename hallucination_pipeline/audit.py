"""
D28 human audit of the existing corpus: 25 explanations (3 from each attack class present, 13
benign-flow), blind sheets (annotation.export_annotation), D23 import (annotation.import_sheet),
then rules-versus-human precision / recall / F1 under both policies, at sentence and explanation
level, with bootstrap CIs over explanations. One pass, one annotator: an audit with wide intervals,
not a gold-standard evaluation.
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import numpy as np

from .annotation import GoldLabel, export_annotation
from .corpus import GROUPS, N_BOOT, SEED, SOURCE, analyze, boot_index, group_of, usable, write_csv

AUDIT_PER_CLASS = {"DoS": 3, "DDoS": 3, "Port Scanning": 3, "Brute Force": 3}   # D28
AUDIT_BENIGN = 13


def sample_audit(alerts: list[dict], explanations: list[dict], *, seed: int = SEED,
                 per_class: dict = AUDIT_PER_CLASS, n_benign: int = AUDIT_BENIGN) -> dict:
    """Fixed-seed D28 sample, in the shape export_annotation expects (primary sheet only)."""
    cls = {a["alert_id"]: a["alert_type"] for a in alerts}
    ok = sorted(e["alert_id"] for e in explanations if usable(e))
    picked, per = [], {}
    for c, k in per_class.items():
        pool = [a for a in ok if cls[a] == c]
        if len(pool) < k:
            raise ValueError(f"class {c!r} has {len(pool)} usable explanations; the audit needs {k}")
        per[c] = sorted(random.Random(f"{seed}:audit:{c}").sample(pool, k))
        picked += per[c]
    benign_pool = [a for a in ok if group_of(cls[a]) == "benign-flow"]
    per["benign-flow"] = sorted(random.Random(f"{seed}:audit:benign").sample(benign_pool, n_benign))
    picked += per["benign-flow"]
    return {"seed": seed, "design": "D28", "primary": sorted(picked), "reliability": [], "retest": [],
            "per_class": {c: len(v) for c, v in per.items()}}


def export_audit(corpus: dict, out_dir: Path, *, seed: int = SEED, unfrozen_ok: bool = False,
                 repo: Path | None = None) -> Path:
    sample = sample_audit(corpus["alerts"], corpus["explanations"], seed=seed)
    return export_annotation(corpus["explanations"], corpus["alerts"], out_dir, run_id=corpus["corpus_id"],
                             seed=seed, unfrozen_ok=unfrozen_ok, repo=repo, sample=sample)


# ── rules versus human ────────────────────────────────────────────────────

def _prf(tp: np.ndarray, fp: np.ndarray, fn: np.ndarray):
    with np.errstate(invalid="ignore", divide="ignore"):
        p = tp / (tp + fp)
        r = tp / (tp + fn)
        f = 2 * p * r / (p + r)
    return p, r, f


def _ci(draws: np.ndarray):
    d = draws[~np.isnan(draws)]
    return [float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5))] if len(d) else None


def audit_metrics(gold: list[GoldLabel], corpus: dict, *, seed: int = SEED, n_boot: int = N_BOOT) -> dict:
    """Precision, recall, F1 of the rules against the human labels, per policy and level, overall and
    per group, with 95% bootstrap CIs (explanations resampled). Rules only: ambiguous = not flagged."""
    sentences, _, _ = analyze(corpus["alerts"], corpus["explanations"])
    pred = {(s["alert_id"], s["sentence_id"]): s for s in sentences}
    missing = [(g.alert_id, g.sentence_id) for g in gold if (g.alert_id, g.sentence_id) not in pred]
    if missing:
        raise ValueError(f"{len(missing)} labelled sentence(s) have no rule record, e.g. {missing[:3]}")
    expl_ids = sorted({g.alert_id for g in gold})
    group = {g.alert_id: pred[(g.alert_id, g.sentence_id)]["group"] for g in gold}
    rows, disagreements = [], []
    for policy in ("strict", "lenient"):
        per_expl = {a: {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "gold_any": False, "pred_any": False} for a in expl_ids}
        for g in gold:
            p = pred[(g.alert_id, g.sentence_id)]
            y, yhat = (g.strict if policy == "strict" else g.lenient), p[policy]
            c = per_expl[g.alert_id]
            c[("tp" if yhat else "fn") if y else ("fp" if yhat else "tn")] += 1
            c["gold_any"] |= y
            c["pred_any"] |= yhat
            if y != yhat:
                disagreements.append({"policy": policy, "kind": "missed by rules (FN)" if y else "rules only (FP)",
                                      "alert_id": g.alert_id, "sentence_id": g.sentence_id, "group": p["group"],
                                      "human_label": g.label, "human_subtype": g.subtype or "",
                                      "human_other_subtypes": ",".join(g.other_subtypes), "human_note": g.note,
                                      "human_unsure": g.unsure, "rule_subtypes": ",".join(p["subtypes"]),
                                      "rule_ambiguous": p[f"ambiguous_{policy}"], "sentence": p["sentence"]})
        for subset in ("all", *GROUPS):
            ids = [a for a in expl_ids if subset == "all" or group[a] == subset]
            idx = boot_index(len(ids), seed, n_boot)
            for level in ("sentence", "explanation"):
                if level == "sentence":
                    arr = {k: np.array([float(per_expl[a][k]) for a in ids]) for k in ("tp", "fp", "fn", "tn")}
                else:
                    gy = np.array([per_expl[a]["gold_any"] for a in ids])
                    py = np.array([per_expl[a]["pred_any"] for a in ids])
                    arr = {"tp": (gy & py).astype(float), "fp": (~gy & py).astype(float),
                           "fn": (gy & ~py).astype(float), "tn": (~gy & ~py).astype(float)}
                tot = {k: v.sum() for k, v in arr.items()}
                p, r, f = _prf(*(np.array([tot[k]]) for k in ("tp", "fp", "fn")))
                bp, br, bf = _prf(*(arr[k][idx].sum(axis=1) for k in ("tp", "fp", "fn")))
                val = lambda x: None if np.isnan(x[0]) else float(x[0])
                rows.append({"policy": policy, "level": level, "group": subset, "n_explanations": len(ids),
                             "n_units": int(sum(tot.values())), "human_positive": int(tot["tp"] + tot["fn"]),
                             "rule_positive": int(tot["tp"] + tot["fp"]), "tp": int(tot["tp"]), "fp": int(tot["fp"]),
                             "fn": int(tot["fn"]), "tn": int(tot["tn"]),
                             "precision": val(p), "precision_ci95": _ci(bp), "recall": val(r), "recall_ci95": _ci(br),
                             "f1": val(f), "f1_ci95": _ci(bf)})
    return {"source": SOURCE, "design": "D28 audit: one annotator, one pass, 25 explanations; wide intervals",
            "detector": "rules only; ambiguous (soft certainty only) = not flagged", "metrics": rows,
            "disagreements": disagreements, "n_sentences": len(gold), "n_explanations": len(expl_ids),
            "human_unsure": sum(g.unsure for g in gold), "human_catch_all": sum(g.subtype in ("other_fabrication",
                                                                                              "other_knowledge")
                                                                                for g in gold)}


def write_audit(result: dict, out_dir: Path) -> Path:
    out_dir = Path(out_dir)
    if out_dir.exists():
        raise FileExistsError(f"{out_dir} already exists; audit results are never overwritten")
    out_dir.mkdir(parents=True)
    write_csv(out_dir / "audit_metrics.csv", result["metrics"])
    write_csv(out_dir / "audit_disagreements.csv", result["disagreements"])
    (out_dir / "audit.json").write_text(json.dumps(result, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
                                        newline="\n")
    return out_dir


def format_audit(result: dict) -> str:
    f = lambda v, ci: "n/a" if v is None else f"{v:.2f} [{ci[0]:.2f}, {ci[1]:.2f}]" if ci else f"{v:.2f}"
    out = [SOURCE, result["design"], f"{result['n_sentences']} sentences in {result['n_explanations']} explanations; "
           f"human unsure: {result['human_unsure']}", "",
           f"{'policy':<8}{'level':<12}{'group':<12}{'n':>5}{'human+':>8}{'rules+':>8}  "
           f"{'precision':<20}{'recall':<20}{'F1':<20}"]
    for r in result["metrics"]:
        out.append(f"{r['policy']:<8}{r['level']:<12}{r['group']:<12}{r['n_units']:>5}{r['human_positive']:>8}"
                   f"{r['rule_positive']:>8}  {f(r['precision'], r['precision_ci95']):<20}"
                   f"{f(r['recall'], r['recall_ci95']):<20}{f(r['f1'], r['f1_ci95']):<20}")
    return "\n".join(out)

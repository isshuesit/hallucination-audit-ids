"""
Existing-corpus study (D25-D28): rule-based analysis of the earlier run's 400 explanations.

No LLM call anywhere (D27). Every explanation is split into sentences (as everywhere else in the
pipeline) and every sentence gets every rule layer plus the policy-layer checks (policy 1.2.0:
D17 hedging, D18 all subtypes, D19 unit_wrong, D20 stated durations). Rules only: a sentence that
the policy leaves "ambiguous" (soft certainty only) is NOT flagged, because no judge runs tonight;
the number of such sentences is reported.

Every file written carries SOURCE (D25). Results go to results/<corpus_id>/ and are never overwritten.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import random
import re
from collections import Counter
from pathlib import Path

import numpy as np

from .detection import split_sentences
from .detection.version import rules_stamp
from .manifest import environment_info, git_info, utc_now
from .policy import (SUBTYPES, TIER1, TIER2, classify_sentence_rules, counts_as_hallucination,
                     flow_duration_from_evidence, policy_stamp, sentence_policy_decision)
from .run_config import PROJECT_ROOT
from .sampling import is_benign

SOURCE = ("source: earlier run, API-default sampling, prompt v1, 63 attack-flow and 337 benign-flow explanations; "
          "not generated under freeze-1")
CORPUS_FILES = ("alerts.json", "llm_explanations.json", "corrected_explanations.json")
REWRITE_FILES = ("phase3_predictions.json", "hallucination_masks.json")   # needed to rebuild the old rewrite pairs
RESULTS_DIR = PROJECT_ROOT / "results"
GROUPS = ("attack-flow", "benign-flow")
N_BOOT, SEED = 2000, 42
RULE_SUBTYPES = [s for s, v in SUBTYPES.items() if v.label and not v.catch_all]   # what rules can produce
FAILED_MARK = "[GENERATION FAILED]"


class ResultsExistError(RuntimeError):
    pass


# ── loading ───────────────────────────────────────────────────────────────

def _sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def corpus_fingerprint(corpus_dir: Path) -> dict:
    """SHA-256 of every input file plus the rule and policy fingerprints; corpus_id = 'corpus-' + 8 hex."""
    files = {n: _sha256(Path(corpus_dir) / n) for n in (*CORPUS_FILES, *REWRITE_FILES) if (Path(corpus_dir) / n).exists()}
    missing = [n for n in CORPUS_FILES if n not in files]
    if missing:
        raise FileNotFoundError(f"{corpus_dir} lacks {missing} (put the earlier run's JSON files in old_run/)")
    blob = json.dumps({"files": files, "rules": rules_stamp(), "policy": policy_stamp()}, sort_keys=True)
    return {"corpus_id": "corpus-" + hashlib.sha256(blob.encode()).hexdigest()[:8], "files": files}


def load_corpus(corpus_dir: Path) -> dict:
    d = Path(corpus_dir)
    load = lambda n: json.loads((d / n).read_text(encoding="utf-8"))
    out = {"alerts": load("alerts.json"), "explanations": load("llm_explanations.json"),
           "corrected": load("corrected_explanations.json"), **corpus_fingerprint(d)}
    for n in REWRITE_FILES:
        out[n] = load(n) if (d / n).exists() else None
    return out


def group_of(alert_type: str) -> str:
    return "benign-flow" if is_benign(alert_type) else "attack-flow"


def usable(explanation: dict) -> bool:
    text = explanation.get("explanation") or ""
    return bool(text.strip()) and FAILED_MARK not in text


# ── per-sentence and per-explanation records ──────────────────────────────

def analyze_sentence(sentence: str, alert: dict, sentence_id: str, group: str) -> dict:
    tokens = {str(t).lower() for t in alert.get("evidence_tokens", [])}
    r = classify_sentence_rules(sentence, tokens, flow_duration_from_evidence(alert["evidence"]))
    rec = {"alert_id": alert["alert_id"], "sentence_id": sentence_id, "group": group,
           "alert_type": alert["alert_type"], "sentence": sentence,
           "hits": [{k: h.get(k) for k in ("subtype", "tier", "hedged", "unit_wrong", "matched", "rule")}
                    for h in r["hits"]],
           "subtypes": r["subtypes"], "hedged": r["hedged"],
           "tier1": any(h["tier"] == TIER1 for h in r["hits"]), "tier2": any(h["tier"] == TIER2 for h in r["hits"]),
           "unit_wrong": any(h.get("unit_wrong") for h in r["hits"]),
           "duration_claims": r["duration_claims"], "rule_engine_label": r["label"]}
    for policy in ("strict", "lenient"):
        d = sentence_policy_decision(r, sentence, policy)
        rec[policy] = d["label"] == "hallucinated"                 # rules only: ambiguous is not flagged
        rec[f"ambiguous_{policy}"] = d["label"] == "ambiguous"
        rec[f"primary_{policy}"] = ({"subtype": d["primary"]["subtype"], "tier": d["primary"]["tier"]}
                                    if d["primary"] else None)
    return rec


def analyze(alerts: list[dict], explanations: list[dict]) -> tuple[list[dict], list[dict], list[dict]]:
    """Returns (sentence records, explanation records, excluded explanations)."""
    by_id = {a["alert_id"]: a for a in alerts}
    sentences, expls, excluded = [], [], []
    for e in sorted(explanations, key=lambda e: e["alert_id"]):
        alert = by_id[e["alert_id"]]
        group = group_of(alert["alert_type"])
        if not usable(e):
            excluded.append({"alert_id": e["alert_id"], "group": group, "reason": "generation failed"})
            continue
        recs = [analyze_sentence(s, alert, f"S{j}", group) for j, s in enumerate(split_sentences(e["explanation"]), 1)]
        sentences += recs
        expls.append({
            "alert_id": e["alert_id"], "group": group, "alert_type": alert["alert_type"], "n_sentences": len(recs),
            "strict": any(r["strict"] for r in recs), "lenient": any(r["lenient"] for r in recs),
            "tier1": any(r["tier1"] for r in recs), "tier2": any(r["tier2"] for r in recs),
            "flagged_strict": sum(r["strict"] for r in recs), "flagged_lenient": sum(r["lenient"] for r in recs),
            "ambiguous_strict": sum(r["ambiguous_strict"] for r in recs),
            "subtypes": sorted({s for r in recs for s in r["subtypes"]}),
            "unit_wrong": any(r["unit_wrong"] for r in recs)})
    return sentences, expls, excluded


# ── bootstrap over explanations ───────────────────────────────────────────

def boot_index(n: int, seed: int = SEED, n_boot: int = N_BOOT) -> np.ndarray:
    return np.random.default_rng(seed).integers(0, n, size=(n_boot, n)) if n else np.zeros((n_boot, 0), int)


def ratio_ci(num: np.ndarray, den: np.ndarray, idx: np.ndarray) -> tuple[float | None, list | None]:
    """sum(num)/sum(den) and its 95% percentile CI, resampling clusters (rows of idx)."""
    if den.sum() == 0:
        return None, None
    with np.errstate(invalid="ignore", divide="ignore"):
        draws = num[idx].sum(axis=1) / den[idx].sum(axis=1)
    lo, hi = np.nanpercentile(draws, [2.5, 97.5])
    return float(num.sum() / den.sum()), [float(lo), float(hi)]


def diff_ci(a: tuple, b: tuple, ia: np.ndarray, ib: np.ndarray) -> tuple[float | None, list | None]:
    """Rate difference a - b with a 95% CI; each group resampled independently."""
    (na, da), (nb, db) = a, b
    if da.sum() == 0 or db.sum() == 0:
        return None, None
    with np.errstate(invalid="ignore", divide="ignore"):
        draws = na[ia].sum(1) / da[ia].sum(1) - nb[ib].sum(1) / db[ib].sum(1)
    lo, hi = np.nanpercentile(draws, [2.5, 97.5])
    return float(na.sum() / da.sum() - nb.sum() / db.sum()), [float(lo), float(hi)]


# ── tables ────────────────────────────────────────────────────────────────

def _categories() -> list[tuple[str, callable]]:
    cats = [("flag (strict)", lambda r: r["strict"]), ("flag (lenient)", lambda r: r["lenient"]),
            ("any Tier 1", lambda r: r["tier1"]), ("any Tier 2", lambda r: r["tier2"])]
    cats += [(f"subtype {s} (tier {SUBTYPES[s].tier}; counts under "
              f"{'both' if SUBTYPES[s].tier == TIER1 else 'strict only'})", lambda r, s=s: s in r["subtypes"])
             for s in RULE_SUBTYPES]
    return cats


def _arrays(expls: list[dict], sents_by_expl: dict, level: str, fn) -> tuple[np.ndarray, np.ndarray]:
    if level == "explanation":
        return np.array([float(fn(e)) for e in expls]), np.ones(len(expls))
    num = np.array([float(sum(bool(fn(s)) for s in sents_by_expl[e["alert_id"]])) for e in expls])
    return num, np.array([float(e["n_sentences"]) for e in expls])


def build_tables(sentences: list[dict], expls: list[dict], seed: int = SEED, n_boot: int = N_BOOT) -> dict:
    by_expl: dict[str, list] = {}
    for s in sentences:
        by_expl.setdefault(s["alert_id"], []).append(s)
    sel = {"all": expls, **{g: [e for e in expls if e["group"] == g] for g in GROUPS}}
    idx = {g: boot_index(len(v), seed, n_boot) for g, v in sel.items()}
    tables = {}

    rows = []
    for level in ("sentence", "explanation"):
        for name, fn in _categories():
            for g, ex in sel.items():
                num, den = _arrays(ex, by_expl, level, fn)
                rate, ci = ratio_ci(num, den, idx[g])
                rows.append({"level": level, "group": g, "category": name, "n_explanations": len(ex),
                             "n_units": int(den.sum()), "count": int(num.sum()), "rate": rate,
                             "ci95_low": ci[0] if ci else None, "ci95_high": ci[1] if ci else None})
    tables["prevalence"] = rows

    rows = []
    for level in ("sentence", "explanation"):
        for name, fn in _categories():
            a, b = (_arrays(sel[g], by_expl, level, fn) for g in GROUPS)
            d, ci = diff_ci(a, b, idx["attack-flow"], idx["benign-flow"])
            rows.append({"level": level, "category": name, "n_attack_expl": len(sel["attack-flow"]),
                         "n_attack_units": int(a[1].sum()), "rate_attack": float(a[0].sum() / a[1].sum()),
                         "n_benign_expl": len(sel["benign-flow"]), "n_benign_units": int(b[1].sum()),
                         "rate_benign": float(b[0].sum() / b[1].sum()), "difference": d,
                         "ci95_low": ci[0] if ci else None, "ci95_high": ci[1] if ci else None})
    tables["attack_vs_benign"] = rows

    rows = []
    for g, ex in sel.items():
        hits = [[h for s in by_expl[e["alert_id"]] for h in s["hits"] if h["subtype"] == "attack_technique"] for e in ex]
        num = np.array([float(sum(bool(h["hedged"]) for h in hs)) for hs in hits])
        den = np.array([float(len(hs)) for hs in hits])
        rate, ci = ratio_ci(num, den, idx[g])
        rows.append({"group": g, "n_explanations": len(ex), "attack_technique_hits": int(den.sum()),
                     "hedged": int(num.sum()), "unhedged": int(den.sum() - num.sum()), "share_hedged": rate,
                     "ci95_low": ci[0] if ci else None, "ci95_high": ci[1] if ci else None})
    tables["hedging_attack_technique"] = rows

    tables["durations"] = [{"alert_id": s["alert_id"], "sentence_id": s["sentence_id"], "group": s["group"],
                            "claim": c["text"], "value": c["value"], "unit": c["unit"],
                            "true_value_in_unit": c["true_value_in_unit"], "unit_wrong": c["consistent"] is False}
                           for s in sentences for c in s["duration_claims"]]
    rows = []
    for g, ex in sel.items():
        cl = [[c for s in by_expl[e["alert_id"]] for c in s["duration_claims"]] for e in ex]
        num = np.array([float(sum(c["consistent"] is False for c in cs)) for cs in cl])
        den = np.array([float(len(cs)) for cs in cl])
        rate, ci = ratio_ci(num, den, idx[g])
        rows.append({"group": g, "n_explanations": len(ex), "explanations_with_a_duration": int((den > 0).sum()),
                     "duration_claims": int(den.sum()), "unit_wrong": int(num.sum()), "share_unit_wrong": rate,
                     "ci95_low": ci[0] if ci else None, "ci95_high": ci[1] if ci else None})
    tables["durations_summary"] = rows

    rows = []
    for g, ex in sel.items():
        ss = [s for e in ex for s in by_expl[e["alert_id"]]]
        rows.append({"group": g, "n_explanations": len(ex), "n_sentences": len(ss),
                     "sentences_with_port_not_in_evidence": sum("port_not_in_evidence" in s["subtypes"] for s in ss),
                     "explanations_with_port_not_in_evidence": sum("port_not_in_evidence" in e["subtypes"] for e in ex)})
    tables["port_not_in_evidence"] = rows

    rows, hist = [], []
    for g, ex in sel.items():
        for policy in ("strict", "lenient"):
            k = np.array([float(e[f"flagged_{policy}"]) for e in ex])
            mean, ci = ratio_ci(k, np.ones(len(ex)), idx[g])
            rows.append({"group": g, "policy": policy, "n_explanations": len(ex), "mean_flagged_sentences": mean,
                         "ci95_low": ci[0] if ci else None, "ci95_high": ci[1] if ci else None,
                         "median": float(np.median(k)) if len(k) else None, "max": int(k.max()) if len(k) else None,
                         "mean_sentences_per_explanation": float(np.mean([e["n_sentences"] for e in ex])) if ex else None})
            for value, n in sorted(Counter(int(x) for x in k).items()):
                hist.append({"group": g, "policy": policy, "flagged_sentences": value, "n_explanations": n})
    tables["flagged_per_explanation"] = rows
    tables["flagged_per_explanation_histogram"] = hist
    return tables


# ── the old rewrites ──────────────────────────────────────────────────────

_NUM = re.compile(r"\d+(?:\.\d+)?")


def rewrite_pairs(corpus: dict) -> list[dict] | None:
    """The earlier run's QUALIFY rewrites (original sentence -> rewritten sentence), rebuilt exactly as
    tools/reproduce_frozen.py does. None if the files needed are not in the corpus directory."""
    if corpus.get("phase3_predictions.json") is None or corpus.get("hallucination_masks.json") is None:
        return None
    from .impact_analysis import analyze_alerts
    _, pairs, _ = analyze_alerts(corpus["alerts"], corpus["corrected"], corpus["phase3_predictions.json"],
                                 corpus["hallucination_masks.json"])
    return pairs


def check_rewrites(pairs: list[dict], groups: dict) -> list[dict]:
    """Numbers in each rewrite that are absent from the evidence (and, separately, also absent from the
    original sentence: figures the rewrite introduced). Same number pattern as the audit."""
    out = []
    for p in pairs:
        evidence_nums = set(_NUM.findall(p["evidence"])) | {str(t) for t in p["evidence_tokens"]}
        absent = sorted({n for n in _NUM.findall(p["corrected"]) if n not in evidence_nums})
        new = [n for n in absent if n not in set(_NUM.findall(p["original"]))]
        out.append({"alert_id": p["alert_id"], "group": groups.get(p["alert_id"]), "original": p["original"],
                    "rewrite": p["corrected"], "numbers_absent_from_evidence": absent,
                    "new_numbers_absent_from_evidence_and_original": new})
    return out


# ── writing the results pack ──────────────────────────────────────────────

def _fmt(v):
    if isinstance(v, float):
        return f"{v:.4f}"
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False)
    return "" if v is None else v


def write_csv(path: Path, rows: list[dict]) -> None:
    buf = io.StringIO()
    buf.write(f"# {SOURCE}\n")
    if rows:
        w = csv.DictWriter(buf, fieldnames=list(rows[0]), lineterminator="\n")
        w.writeheader()
        w.writerows({k: _fmt(v) for k, v in r.items()} for r in rows)
    path.write_text(buf.getvalue(), encoding="utf-8", newline="\n")


def _samples_md(title: str, rows: list[dict], alerts: dict) -> str:
    parts = [f"# {title}", "", f"_{SOURCE}_", ""]
    for i, s in enumerate(rows, 1):
        parts += [f"## {i}. {s['alert_id']} {s['sentence_id']} ({s['group']})", "", "```",
                  alerts[s["alert_id"]]["evidence"], "```", "", f"> {s['sentence']}", "",
                  f"Subtypes: {', '.join(s['subtypes'])}; hedged: {s['hedged']}", ""]
    return "\n".join(parts) + "\n"


def write_results(corpus: dict, out_root: Path | None = None, *, seed: int = SEED, n_boot: int = N_BOOT) -> Path:
    out = Path(out_root if out_root is not None else RESULTS_DIR) / corpus["corpus_id"]   # RESULTS_DIR read at call time
    if out.exists():
        raise ResultsExistError(f"{out} already exists; results are never overwritten")
    sentences, expls, excluded = analyze(corpus["alerts"], corpus["explanations"])
    tables = build_tables(sentences, expls, seed, n_boot)
    alerts = {a["alert_id"]: a for a in corpus["alerts"]}
    groups = {a["alert_id"]: group_of(a["alert_type"]) for a in corpus["alerts"]}
    pairs = rewrite_pairs(corpus)
    rewrites = check_rewrites(pairs, groups) if pairs is not None else None

    out.mkdir(parents=True)
    (out / "tables").mkdir()
    (out / "samples").mkdir()
    for name, rows in tables.items():
        write_csv(out / "tables" / f"{name}.csv", rows)
    port_examples = [{"alert_id": s["alert_id"], "sentence_id": s["sentence_id"], "group": s["group"],
                      "evidence_port": (re.search(r"Destination Port: (\d+)", alerts[s["alert_id"]]["evidence"])
                                        or [None, None])[1],
                      "matched": [m for h in s["hits"] if h["subtype"] == "port_not_in_evidence" for m in h["matched"]],
                      "sentence": s["sentence"]} for s in sentences if "port_not_in_evidence" in s["subtypes"]]
    write_csv(out / "tables" / "port_not_in_evidence_examples.csv", port_examples)
    rewrite_summary = None
    if rewrites is not None:
        write_csv(out / "tables" / "rewrites.csv", rewrites)
        rewrite_summary = {"n_rewrites": len(rewrites),
                           "with_numbers_absent_from_evidence": sum(bool(r["numbers_absent_from_evidence"])
                                                                    for r in rewrites),
                           "with_new_numbers_absent_from_evidence_and_original":
                               sum(bool(r["new_numbers_absent_from_evidence_and_original"]) for r in rewrites)}
        write_csv(out / "tables" / "rewrites_summary.csv", [rewrite_summary])

    rng = random.Random(f"{seed}:corpus-samples")
    t1 = [s for s in sentences if s["tier1"]]
    t2 = [s for s in sentences if s["tier2"] and not s["tier1"]]
    for name, pool, title in (("tier1", t1, "20 random sentences with a Tier 1 hit"),
                              ("tier2", t2, "20 random sentences with only Tier 2 hits")):
        pick = sorted(rng.sample(pool, min(20, len(pool))), key=lambda s: (s["alert_id"], s["sentence_id"]))
        (out / "samples" / f"flagged_{name}.md").write_text(_samples_md(title + f" (of {len(pool)})", pick, alerts),
                                                           encoding="utf-8", newline="\n")
    (out / "sentences.jsonl").write_text("".join(json.dumps({"source": SOURCE, **s}, ensure_ascii=False) + "\n"
                                                 for s in sentences), encoding="utf-8", newline="\n")
    (out / "explanations.json").write_text(json.dumps({"source": SOURCE, "excluded": excluded, "explanations": expls},
                                                      indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    counts = {g: {"explanations_in_corpus": sum(groups[e["alert_id"]] == g for e in corpus["explanations"]),
                  "analysed": sum(e["group"] == g for e in expls), "excluded": sum(x["group"] == g for x in excluded),
                  "sentences": sum(s["group"] == g for s in sentences),
                  "ambiguous_sentences_not_flagged_strict": sum(s["ambiguous_strict"] for s in sentences
                                                                if s["group"] == g)} for g in GROUPS}
    manifest = {"source": SOURCE, "corpus_id": corpus["corpus_id"], "created_at": utc_now(), "git": git_info(),
                "environment": environment_info(), "input_files_sha256": corpus["files"], "rules": rules_stamp(),
                "policy": policy_stamp(), "llm_calls": 0, "bootstrap": {"draws": n_boot, "seed": seed,
                                                                         "unit": "explanation", "ci": "percentile 95%"},
                "detector": "rules only, every layer, policy 1.2.0; ambiguous (soft certainty only) = not flagged",
                "counts": counts, "excluded": excluded, "rewrites": rewrite_summary}
    (out / "MANIFEST.json").write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
                                       newline="\n")
    (out / "REPORT.md").write_text(render_report(manifest, tables), encoding="utf-8", newline="\n")
    return out


def render_report(manifest: dict, tables: dict) -> str:
    pct = lambda v: "n/a" if v is None else f"{v:.1%}"
    ci = lambda r: "" if r.get("ci95_low") in (None, "") else f" [{pct(r['ci95_low'])}, {pct(r['ci95_high'])}]"
    c = manifest["counts"]
    lines = [f"# Existing-corpus study {manifest['corpus_id']}", "", f"**{SOURCE}**", "",
             "Rules only (no LLM call, D27); every rule layer plus policy 1.2.0 checks on every sentence. "
             "95% CIs: percentile bootstrap over explanations (2000 draws, seed 42).", "",
             "| group | explanations analysed | excluded (generation failed) | sentences |", "|---|---|---|---|"]
    lines += [f"| {g} | {c[g]['analysed']} | {c[g]['excluded']} | {c[g]['sentences']} |" for g in GROUPS]
    lines += ["", "## Headline prevalence (explanation level)", "", "| group | category | n | count | rate [95% CI] |",
              "|---|---|---|---|---|"]
    for r in tables["prevalence"]:
        if r["level"] == "explanation" and not r["category"].startswith("subtype"):
            lines.append(f"| {r['group']} | {r['category']} | {r['n_units']} | {r['count']} | {pct(r['rate'])}{ci(r)} |")
    lines += ["", "## Durations", "", "| group | claims | unit_wrong | share [95% CI] |", "|---|---|---|---|"]
    lines += [f"| {r['group']} | {r['duration_claims']} | {r['unit_wrong']} | {pct(r['share_unit_wrong'])}{ci(r)} |"
              for r in tables["durations_summary"]]
    lines += ["", "## Hedged attack_technique hits", "", "| group | hits | hedged | share [95% CI] |", "|---|---|---|---|"]
    lines += [f"| {r['group']} | {r['attack_technique_hits']} | {r['hedged']} | {pct(r['share_hedged'])}{ci(r)} |"
              for r in tables["hedging_attack_technique"]]
    if manifest["rewrites"]:
        rw = manifest["rewrites"]
        lines += ["", "## Old rewrites", "", f"{rw['n_rewrites']} rewrites; {rw['with_numbers_absent_from_evidence']} "
                  f"contain a number absent from the evidence; {rw['with_new_numbers_absent_from_evidence_and_original']}"
                  " contain a number absent from both the evidence and the original sentence."]
    lines += ["", "All tables (CSV, n in every row) are in `tables/`; sentence-level records in `sentences.jsonl`.",
              "Known rule gaps that lower these counts: `docs/KNOWN_RULE_GAPS.md`."]
    return "\n".join(lines) + "\n"

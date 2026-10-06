"""
Differential verification: does the rebuild behave like the original?

Runs the ORIGINAL scripts and this rebuild side by side, on identical
synthetic inputs, through the whole pipeline (generate -> detect -> localize
-> [simulated annotation] -> unlearn -> impact -> evaluate -> report), using
the same deterministic fake Gemini client for both, then compares every
output file.

The fake client is a pure function of the prompt (plus how many times that
exact prompt has been seen), so both runs see identical LLM behaviour. It
deliberately includes the awkward cases: 429 rate-limit errors with a
retryDelay body, generic errors, fenced and malformed JSON, rewrites that
return the sentence unchanged, and rewrites that fail every retry.

Usage:
    python tools/verify_against_original.py --original-dir /path/to/original/files

--original-dir must contain the original scripts (01_..py through 08_..py and
hallucination_utils.py). The original files contain several commented-out
duplicate copies of themselves; the live copy is the part starting at the
first uncommented line, which is what this tool extracts and runs.

Nothing from the original is copied into this repository.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import random
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# ── deterministic fake Gemini (lives in tests/fakes.py) ─────────────────────

sys.path.insert(0, str(REPO_ROOT / "tests"))
from fakes import FakeGemini, _h, install_stubs  # noqa: E402


# ── synthetic inputs and simulated annotation ─────────────────────────────

COARSE = ["DDoS", "DoS", "Port Scanning", "Brute Force", "Web Attack", "Infiltration", "Botnet", "Heartbleed"]


def make_alerts(n: int = 400) -> list[dict]:
    rng = random.Random(7)
    alerts = []
    for i in range(1, n + 1):
        port = rng.choice([22, 80, 443, 53, 3389, 445, 8080, 21])
        ev = "\n".join([
            f"Destination Port: {port}", f"Flow Duration: {rng.randint(100, 99999999)}",
            f"Forward Packets: {rng.randint(1, 900)}", f"Backward Packets: {rng.randint(0, 50)}",
            f"Flow Bytes/s: {rng.uniform(1, 9000):.2f}", f"Flow Packets/s: {rng.uniform(0.1, 90):.2f}",
            f"SYN Flag Count: {rng.randint(0, 800)}", f"ACK Flag Count: {rng.randint(0, 60)}",
            f"RST Flag Count: {rng.randint(0, 5)}",
        ])
        alerts.append({"alert_id": f"A{i:03d}", "alert_type": rng.choice(COARSE),
                       "evidence": ev, "evidence_tokens": list(set(re.findall(r"\d+", ev)))})
    return alerts


def simulate_annotation(datadir: Path) -> None:
    """Fill gold labels deterministically: mostly agree with the prediction,
    sometimes flip it, sometimes leave it unannotated."""
    det_p = datadir / "data/processed/phase2_detection.json"
    pred_p = datadir / "data/annotations/phase3_predictions.json"
    det = json.loads(det_p.read_text())
    for d in det:
        x = _h(d["alert_id"], "g") % 10
        if x < 8:
            d["gold_label"] = bool(d["contains_hallucination"]) if x > 1 else (not bool(d["contains_hallucination"]))
    det_p.write_text(json.dumps(det, indent=2))
    pred = json.loads(pred_p.read_text())
    for p in pred:
        x = _h(p["alert_id"], p["sentence_id"], "g") % 10
        pl = p["predicted_label"]
        if x < 6:
            p["gold_label"] = pl
        elif x < 8:
            p["gold_label"] = "grounded" if pl == "hallucinated" else "hallucinated"
        # else: leave None -> mask falls back to prediction
    pred_p.write_text(json.dumps(pred, indent=2))


# ── workers ───────────────────────────────────────────────────────────────

def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


def worker_original(datadir: Path, livedir: Path) -> None:
    os.chdir(datadir)
    os.environ["GEMINI_API_KEY"] = "fake"
    install_stubs()
    sys.path.insert(0, str(livedir))
    _load_module(livedir / "hallucination_utils.py", "hallucination_utils")
    mods = {n: _load_module(livedir / f"{n}.py", f"orig_{n}") for n in
            ["02_generate_explanations", "03_detect_hallucination", "04_localize_hallucinations",
             "05_apply_unlearning", "08_measure_unlearning_impact", "06_evaluate", "07_generate_report"]}
    mods["02_generate_explanations"].main()
    mods["03_detect_hallucination"].main()
    mods["04_localize_hallucinations"].main()
    simulate_annotation(datadir)
    mods["05_apply_unlearning"].main()
    mods["08_measure_unlearning_impact"].main()
    mods["06_evaluate"].main()
    mods["07_generate_report"].main()


def worker_mine(datadir: Path) -> None:
    os.environ["HALLUC_ROOT"] = str(datadir)
    os.environ["GEMINI_API_KEY"] = "fake"
    install_stubs()
    sys.path.insert(0, str(REPO_ROOT))
    from hallucination_pipeline import (detection_pipeline, evaluation, explanation_generator,
                                        impact_analysis, reporting, unlearning)
    from hallucination_pipeline.llm_client import get_client
    explanation_generator.run()
    detection_pipeline.run_explanation_detection()
    detection_pipeline.run_sentence_localization()
    simulate_annotation(datadir)
    unlearning.run(get_client())
    impact_analysis.run()
    evaluation.run()
    reporting.run()




# ── data loader (Phase 1) comparison ──────────────────────────────────────

def make_cic_csvs(dst: Path) -> None:
    """Messy CIC-IDS-2017-style CSVs: padded column names, NaN, inf, zeros."""
    import numpy as np
    import pandas as pd
    rng = np.random.default_rng(3)
    labels = ["BENIGN"] * 6 + COARSE
    for k in range(3):
        n = 700
        df = pd.DataFrame({
            " Destination Port": rng.choice([22, 80, 443, 53, 0, 8080], n),
            " Flow Duration": rng.integers(0, 10**8, n),
            " Total Fwd Packets": rng.integers(0, 900, n),
            " Total Backward Packets": rng.integers(0, 60, n),
            "Flow Bytes/s": rng.uniform(0, 9000, n),
            " Flow Packets/s": rng.uniform(0, 90, n),
            " SYN Flag Count": rng.integers(0, 800, n),
            " ACK Flag Count": rng.integers(0, 60, n),
            " RST Flag Count": rng.integers(0, 3, n),
            " Label": rng.choice(labels, n),
        })
        df.loc[rng.choice(n, 25, replace=False), "Flow Bytes/s"] = np.nan
        df.loc[rng.choice(n, 25, replace=False), " Flow Packets/s"] = np.inf
        df.to_csv(dst / f"day{k}.csv", index=False)


def worker_loader_original(datadir: Path, livedir: Path) -> None:
    os.chdir(datadir)
    _load_module(livedir / "01_load_cicids.py", "orig_01").main()


def worker_loader_mine(datadir: Path) -> None:
    os.environ["HALLUC_ROOT"] = str(datadir)
    sys.path.insert(0, str(REPO_ROOT))
    from hallucination_pipeline import data_loader
    data_loader.run()


def verify_loader(tmp: Path, live: Path) -> int:
    d1, d2 = tmp / "loader_orig", tmp / "loader_mine"
    for d in (d1, d2):
        (d / "data/raw").mkdir(parents=True, exist_ok=True)
        (d / "data/processed").mkdir(parents=True, exist_ok=True)
        make_cic_csvs(d / "data/raw")
    for mode, d in (("loader-orig", d1), ("loader-mine", d2)):
        r = subprocess.run([sys.executable, __file__, "--worker", mode, "--datadir", str(d), "--livedir", str(live)],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"loader worker {mode} FAILED:\n{r.stderr[-1200:]}")
            return 1
    a = json.loads((d1 / "data/processed/alerts.json").read_text())
    b = json.loads((d2 / "data/processed/alerts.json").read_text())
    for side in (a, b):
        for al in side:
            al["evidence_tokens"] = sorted(al["evidence_tokens"])   # original order is arbitrary
    diff = _first_diff(a, b)
    leaked = [al for al in b if re.search(r"attack|brute|flood|scan|inject|exploit|suspicious|malicious", al["evidence"], re.I)]
    print(f"  {'IDENTICAL' if not diff else 'DIFFERS  '}  evidence-pure alerts (Phase 1 loader)            ({len(b)} alerts)")
    if diff:
        print(f"             first difference -> {diff}")
    print(f"  {'OK       ' if not leaked else 'LEAK     '}  evidence purity: {len(leaked)} alerts contain interpretive words")
    return 1 if (diff or leaked) else 0

# ── orchestration and comparison ──────────────────────────────────────────

def extract_live(src: Path, dst: Path) -> None:
    """Copy each original file keeping only the live (uncommented) copy."""
    dst.mkdir(parents=True, exist_ok=True)
    for f in src.glob("*.py"):
        lines = f.read_text(encoding="utf-8").splitlines(keepends=True)
        start = next(i for i, l in enumerate(lines) if l.strip() and not l.lstrip().startswith("#"))
        (dst / f.name).write_text("".join(lines[start:]), encoding="utf-8")


FILES = [
    ("data/processed/llm_explanations.json", "explanations (Phase 2.2)"),
    ("data/processed/phase2_detection.json", "explanation-level detection (Phase 2.3)"),
    ("data/annotations/phase3_predictions.json", "sentence-level localization (Phase 3)"),
    ("data/processed/hallucination_masks.json", "masks (Phase 4)"),
    ("data/processed/corrected_explanations.json", "corrected explanations (Phase 4)"),
    ("data/processed/phase4_effect_analysis.json", "effect analysis (Phase 4)"),
    ("outputs/unlearning_impact.json", "impact analysis (Phase 5.8)"),
    ("outputs/end_to_end_metrics.json", "end-to-end metrics (Phase 5.6)"),
    ("outputs/comparison_analysis.json", "comparison (Phase 5.6)"),
    ("outputs/qualitative_examples.json", "qualitative examples (Phase 5.6)"),
]
MD_FILES = [("outputs/unlearning_impact_report.md", "impact report"), ("outputs/final_report.md", "final report")]


def _first_diff(a, b, path="$"):
    if type(a) != type(b):
        return f"{path}: type {type(a).__name__} vs {type(b).__name__}"
    if isinstance(a, dict):
        for k in sorted(set(a) | set(b)):
            if k not in a:
                return f"{path}.{k}: only in rebuild"
            if k not in b:
                return f"{path}.{k}: only in original"
            d = _first_diff(a[k], b[k], f"{path}.{k}")
            if d:
                return d
    elif isinstance(a, list):
        if len(a) != len(b):
            return f"{path}: length {len(a)} (original) vs {len(b)} (rebuild)"
        for i, (x, y) in enumerate(zip(a, b)):
            d = _first_diff(x, y, f"{path}[{i}]")
            if d:
                return d
    elif a != b:
        return f"{path}: {str(a)[:90]!r} (original) vs {str(b)[:90]!r} (rebuild)"
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--original-dir", type=Path)
    ap.add_argument("--worker", choices=["orig", "mine", "loader-orig", "loader-mine"])
    ap.add_argument("--datadir", type=Path)
    ap.add_argument("--livedir", type=Path)
    args = ap.parse_args()

    if args.worker == "orig":
        worker_original(args.datadir, args.livedir)
        return 0
    if args.worker == "mine":
        worker_mine(args.datadir)
        return 0
    if args.worker == "loader-orig":
        worker_loader_original(args.datadir, args.livedir)
        return 0
    if args.worker == "loader-mine":
        worker_loader_mine(args.datadir)
        return 0
    if not args.original_dir:
        ap.error("--original-dir is required")

    tmp = Path(tempfile.mkdtemp(prefix="verify_"))
    live, d_orig, d_mine = tmp / "live", tmp / "orig", tmp / "mine"
    extract_live(args.original_dir, live)
    alerts = make_alerts()
    for d in (d_orig, d_mine):
        for sub in ("data/processed", "data/annotations", "outputs"):
            (d / sub).mkdir(parents=True, exist_ok=True)
        (d / "data/processed/alerts.json").write_text(json.dumps(alerts, indent=2))

    print(f"Working in {tmp}\nRunning ORIGINAL pipeline on {len(alerts)} synthetic alerts...")
    r1 = subprocess.run([sys.executable, __file__, "--worker", "orig", "--datadir", str(d_orig), "--livedir", str(live)],
                        capture_output=True, text=True)
    print("Running REBUILD on the same alerts...")
    r2 = subprocess.run([sys.executable, __file__, "--worker", "mine", "--datadir", str(d_mine)],
                        capture_output=True, text=True)
    for name, r in (("original", r1), ("rebuild", r2)):
        if r.returncode != 0:
            print(f"\n{name} run FAILED:\n{r.stderr[-1500:]}")
            return 2

    print("\n" + "=" * 72 + "\nFILE-BY-FILE COMPARISON (rebuild vs original)\n" + "=" * 72)
    failures = verify_loader(tmp, live)
    deviations = []
    for rel, label in FILES:
        a = json.loads((d_orig / rel).read_text())
        b = json.loads((d_mine / rel).read_text())
        if rel.endswith("unlearning_impact.json"):
            # the original writes list(set(...)): order varies run to run. Compare as sorted.
            for side in (a, b):
                for pr in side["qualify_sentence_pairs"]:
                    pr["evidence_tokens"] = sorted(pr["evidence_tokens"])
        if rel.endswith("qualitative_examples.json"):
            # DELIBERATE DEVIATION: the original pairs a flagged sentence with the wrong
            # "corrected" sentence once an earlier sentence has been removed. Everything
            # except corrected_sentence must still match.
            moved = [(dict(x), dict(y)) for x, y in zip(a, b) if x["corrected_sentence"] != y["corrected_sentence"]]
            deviations.append((label, len(moved), len(a), moved))
            for side in (a, b):
                for ex in side:
                    ex.pop("corrected_sentence", None)
        diff = _first_diff(a, b)
        size = len(a) if isinstance(a, list) else len(a.keys())
        print(f"  {'IDENTICAL' if not diff else 'DIFFERS  '}  {label:<44} ({size} entries)")
        if diff:
            failures += 1
            print(f"             first difference -> {diff}")
    for rel, label in MD_FILES:
        def mask(t):
            t = re.sub(r"> Generated: .*", "> Generated: <ts>", t)
            if rel.endswith("final_report.md"):  # deliberate qualitative-example deviation, see above
                t = re.sub(r"(\*\*Corrected sentence:\*\*\n)> .*", r"\1> <corrected>", t)
            return t
        a, b = mask((d_orig / rel).read_text()), mask((d_mine / rel).read_text())
        same = a == b
        print(f"  {'IDENTICAL' if same else 'DIFFERS  '}  {label:<44} (markdown, timestamp masked)")
        if not same:
            failures += 1
            al, bl = a.splitlines(), b.splitlines()
            for i, (x, y) in enumerate(zip(al, bl)):
                if x != y:
                    print(f"             first differing line {i + 1}:\n               original: {x[:100]}\n               rebuild:  {y[:100]}")
                    break
            else:
                print(f"             line counts differ: {len(al)} (original) vs {len(bl)} (rebuild)")
    for label, n_diff, n_tot, moved in deviations:
        print(f"\n  DELIBERATE DEVIATION in {label}: 'corrected_sentence' differs in {n_diff} of {n_tot} examples")
        print("  (the original pairs a flagged sentence with the wrong 'corrected' sentence after an earlier removal)")
        for x, y in moved[:2]:
            print(f"    flagged : {x['original_sentence'][:80]}")
            print(f"    original builder showed : {x['corrected_sentence'][:80]}")
            print(f"    rebuild shows           : {y['corrected_sentence'][:80]}")
    print("\n" + ("ALL OUTPUTS IDENTICAL (apart from the deliberate deviation above)" if not failures else f"{failures} FILE(S) DIFFER"))
    print(f"(work dir kept for inspection: {tmp})")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

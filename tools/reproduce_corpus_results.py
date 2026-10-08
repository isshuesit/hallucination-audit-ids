"""
Re-run the existing-corpus study offline and check it reproduces the committed results exactly.

    python tools/reproduce_corpus_results.py [--corpus-dir old_run]

The committed outputs are never overwritten (the pipeline refuses to), so this script re-runs everything
into a temporary folder and compares file by file with what is in the repository:
  1. the rule analysis (`analyze_corpus`)           -> results/<corpus_id>/
  2. the final labels and the rules-vs-labels audit (`ai_finalize`, from the committed AI labels and the
     author's adjudication)                         -> annotation/<corpus_id>/ai/final_labels.csv,
                                                       final_summary.json, results/<corpus_id>/audit_ai/
  3. the evidence-completeness tables (D34)         -> results/<corpus_id>_extra/
MANIFEST.json files are compared without their time, git and environment fields. No API call; exit code 0
only if everything matches.
"""

from __future__ import annotations

import argparse
import filecmp
import json
import shutil
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "tools"))

import ai_labelling as AL  # noqa: E402
import evidence_completeness as EC  # noqa: E402
from hallucination_pipeline import corpus as CO  # noqa: E402

VOLATILE = ("created_at", "git", "environment")


def _same(a: Path, b: Path) -> bool:
    if a.name == "MANIFEST.json":
        strip = lambda p: {k: v for k, v in json.loads(p.read_text(encoding="utf-8")).items() if k not in VOLATILE}
        return strip(a) == strip(b)
    return filecmp.cmp(a, b, shallow=False)


def compare_trees(new: Path, published: Path, label: str, skip: tuple[str, ...] = ()) -> list[str]:
    """Files under `skip` (sub-folders checked on their own) are left out on both sides."""
    problems = []
    files = lambda root: {p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file()
                          and not p.relative_to(root).as_posix().startswith(skip)} if root.exists() else set()
    new_files, pub_files = files(new), files(published)
    problems += [f"{label}: only in the re-run: {f}" for f in sorted(new_files - pub_files)]
    problems += [f"{label}: only in the repository: {f}" for f in sorted(pub_files - new_files)]
    problems += [f"{label}: differs: {f}" for f in sorted(new_files & pub_files) if not _same(new / f, published / f)]
    return problems


def reproduce(corpus_dir: Path, annotation_root: Path, results_root: Path, work: Path) -> tuple[list[str], dict]:
    data = CO.load_corpus(corpus_dir)
    cid = data["corpus_id"]
    problems, checked = [], {}

    out = CO.write_results(data, work / "results")
    problems += compare_trees(out, results_root / cid, "analysis", skip=("audit_ai/",))
    checked["analysis files"] = sum(1 for p in out.rglob("*") if p.is_file())

    ai_pub = annotation_root / cid / "ai"
    summary = json.loads((ai_pub / "final_summary.json").read_text(encoding="utf-8"))
    a_name, b_name = list(summary["labellers"])
    ann_copy = work / "annotation"
    shutil.copytree(annotation_root / cid, ann_copy / cid)
    for f in ("final_labels.csv", "final_summary.json"):
        (ann_copy / cid / "ai" / f).unlink()
    r = AL.ai_finalize(ann_copy, cid, a_name, b_name, summary["author"], corpus_dir, results_dir=work / "results")
    for f in ("final_labels.csv", "final_summary.json"):
        if not _same(ann_copy / cid / "ai" / f, ai_pub / f):
            problems.append(f"labels: differs: {f}")
    problems += compare_trees(r["dest"], results_root / cid / "audit_ai", "audit_ai")
    checked["label and audit files"] = 2 + sum(1 for p in r["dest"].rglob("*") if p.is_file())

    alerts = json.loads((corpus_dir / "alerts.json").read_text(encoding="utf-8"))
    expl = json.loads((corpus_dir / "llm_explanations.json").read_text(encoding="utf-8"))
    extra = EC.write_outputs(EC.completeness(alerts, expl), work / "extra")
    problems += compare_trees(extra, results_root / f"{cid}_extra", "evidence completeness")
    checked["evidence-completeness files"] = sum(1 for p in extra.rglob("*") if p.is_file())
    return problems, {"corpus_id": cid, "labels": summary["labels"], **checked}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus-dir", default=str(REPO_ROOT / "old_run"))
    ap.add_argument("--annotation-root", default=str(REPO_ROOT / "annotation"))
    ap.add_argument("--results-root", default=str(REPO_ROOT / "results"))
    args = ap.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass
    with tempfile.TemporaryDirectory() as tmp:
        problems, info = reproduce(Path(args.corpus_dir), Path(args.annotation_root), Path(args.results_root), Path(tmp))
    print(f"Corpus {info['corpus_id']}; {CO.SOURCE}")
    print(info["labels"])
    for k, v in info.items():
        if k not in ("corpus_id", "labels"):
            print(f"  re-ran and compared {v} {k}")
    if problems:
        print("\nNOT REPRODUCED:\n  " + "\n  ".join(problems))
        return 1
    print("\nREPRODUCED: every re-run output matches the committed results (no LLM call).")
    return 0


if __name__ == "__main__":
    sys.exit(main())

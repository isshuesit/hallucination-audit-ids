"""
Package a pass-through for the paper side (docs/HANDOFF.md, "Outbox").

    python tools/make_outbox.py P1 <run_id>
    python tools/make_outbox.py P1b

Writes outbox/<pass>_<run_id or commit>.zip containing ONLY the files listed for that pass,
plus a fresh pytest summary. It works from an allow-list, so .env, API keys, raw
CIC-IDS CSVs and the LLM cache can never end up in the zip.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import zipfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from hallucination_pipeline.run_config import DEFAULT_CONFIG_PATH, load_run_config  # noqa: E402

# pass -> files from runs/<run_id>/ ; DECISIONS.md and test_summary.txt are always added
PASSES = {
    "P1": ["MANIFEST.json", "class_distribution.json", "anomalies.md"],
    "P1b": [],
}
# pass -> files from the repository (no run needed)
REPO_FILES = {
    "P1b": ["docs/RULE_TIERS.md"],
}
FORBIDDEN_SUFFIXES = (".csv", ".env", ".jsonl", ".sqlite")


def check_allowed(arcname: str) -> None:
    name = arcname.lower()
    if name.endswith(FORBIDDEN_SUFFIXES) or name.startswith(".env") or "cache" in name:
        raise ValueError(f"Refusing to package {arcname}: secrets, raw data and caches never leave the machine")


def make_outbox(pass_id: str, run_dir: Path | None, out_dir: Path, test_summary: str, label: str | None = None) -> Path:
    if PASSES[pass_id] and run_dir is None:
        raise ValueError(f"{pass_id} needs a run_id")
    missing = [f for f in PASSES[pass_id] if not (run_dir / f).exists()]
    if missing:
        raise FileNotFoundError(f"{run_dir} lacks {missing}; run the pipeline first")
    out_dir.mkdir(parents=True, exist_ok=True)
    zpath = out_dir / f"{pass_id}_{label or run_dir.name}.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as z:
        for f in PASSES[pass_id]:
            check_allowed(f)
            z.write(run_dir / f, f)
        for f in REPO_FILES.get(pass_id, []):
            check_allowed(f)
            z.write(REPO_ROOT / f, Path(f).name)
        z.write(REPO_ROOT / "docs" / "DECISIONS.md", "DECISIONS.md")
        z.writestr("test_summary.txt", test_summary)
    return zpath


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("pass_id", choices=sorted(PASSES))
    ap.add_argument("run_id", nargs="?")
    ap.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    args = ap.parse_args()
    cfg = load_run_config(args.config)
    tests = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-q"], cwd=REPO_ROOT,
                           capture_output=True, text=True)
    summary = tests.stdout[-4000:]
    print(summary.strip().splitlines()[-1])
    if tests.returncode != 0:
        print("Tests are failing; fix them before handing anything over.")
        return 1
    commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], cwd=REPO_ROOT, capture_output=True,
                            text=True).stdout.strip() or "nogit"
    run_dir = cfg.runs_dir / args.run_id if args.run_id else None
    zpath = make_outbox(args.pass_id, run_dir, REPO_ROOT / "outbox", summary, label=None if run_dir else commit)
    with zipfile.ZipFile(zpath) as z:
        print(f"Wrote {zpath}:\n  " + "\n  ".join(z.namelist()))
    return 0


if __name__ == "__main__":
    sys.exit(main())

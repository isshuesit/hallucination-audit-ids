"""
MANIFEST.json: everything needed to say exactly what produced a run.

git commit + dirty flag, Python and package versions, the config and its hash,
rule version + fingerprints, prompt hashes, dataset CSV hashes and row counts,
the model string the API actually returned, call counts and token usage.
"""

from __future__ import annotations

import platform
import subprocess
import sys
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

from .detection.version import rules_stamp
from .prompt_store import prompt_hashes
from .run_config import PROJECT_ROOT, RunConfig

MANIFEST_VERSION = 1
_PACKAGES = ("pandas", "numpy", "scikit-learn", "google-genai")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def git_info(repo: Path = PROJECT_ROOT) -> dict:
    def git(*args: str) -> str:
        return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True,
                              check=True).stdout.strip()
    try:
        return {
            "commit": git("rev-parse", "HEAD"),
            "dirty": bool(git("status", "--porcelain")),
            "describe": git("describe", "--tags", "--always", "--dirty"),
        }
    except (OSError, subprocess.CalledProcessError) as e:
        return {"commit": None, "dirty": None, "error": f"git unavailable: {e}"[:200]}


def environment_info() -> dict:
    versions = {}
    for pkg in _PACKAGES:
        try:
            versions[pkg] = metadata.version(pkg)
        except metadata.PackageNotFoundError:
            versions[pkg] = None
    return {"python": sys.version.split()[0], "platform": platform.platform(), "packages": versions}


def build_manifest(cfg: RunConfig, run_id: str, *, started_at: str, dataset: dict,
                   llm: dict, counts: dict, outputs: list[str], stages: list[str]) -> dict:
    return {
        "manifest_version": MANIFEST_VERSION,
        "run_id": run_id,
        "started_at": started_at,
        "finished_at": utc_now(),
        "stages": stages,
        "git": git_info(),
        "environment": environment_info(),
        "config": {"hash": cfg.config_hash, "settings": cfg.experiment_settings(), "paths": cfg.raw["paths"]},
        "rules": rules_stamp(),
        "prompts": prompt_hashes(),
        "dataset": dataset,
        "llm": {**llm, "generation_params": cfg.generation_params},
        "counts": counts,
        "outputs": outputs,
    }

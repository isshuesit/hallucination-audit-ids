"""
Run directories: runs/<run_id>/, written once, then frozen.

A run directory is frozen when it contains SHA256SUMS. Freezing (1) writes the
SHA-256 of every file, in `sha256sum` format so `sha256sum -c SHA256SUMS` can
check it outside Python, and (2) marks every file read-only. All writers in the
pipeline go through write_json/write_text here, which refuse to touch a frozen
run, so a finished run can never be overwritten; a re-run needs a new run_id.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path

SUMS_NAME = "SHA256SUMS"


class FrozenRunError(RuntimeError):
    pass


def is_frozen(run_dir: Path) -> bool:
    return (Path(run_dir) / SUMS_NAME).exists()


def ensure_writable(run_dir: Path) -> None:
    if is_frozen(run_dir):
        raise FrozenRunError(
            f"Run directory {run_dir} is frozen (it has {SUMS_NAME}) and is read-only. "
            "Re-run under a new run_id instead (cli run --run-id <new id>)."
        )


def write_text(run_dir: Path, name: str, text: str) -> Path:
    ensure_writable(run_dir)
    path = Path(run_dir) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return path


def write_json(run_dir: Path, name: str, obj) -> Path:
    return write_text(run_dir, name, json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _run_files(run_dir: Path) -> list[Path]:
    return sorted((p for p in Path(run_dir).rglob("*") if p.is_file() and p.name != SUMS_NAME),
                  key=lambda p: p.relative_to(run_dir).as_posix())


def freeze_run(run_dir: Path) -> Path:
    """Write SHA256SUMS and make every file in the run read-only."""
    run_dir = Path(run_dir)
    if not run_dir.is_dir():
        raise FileNotFoundError(f"No run directory at {run_dir}")
    ensure_writable(run_dir)
    files = _run_files(run_dir)
    lines = [f"{file_sha256(p)}  {p.relative_to(run_dir).as_posix()}" for p in files]
    sums = write_text(run_dir, SUMS_NAME, "\n".join(lines) + "\n")
    for p in [*files, sums]:
        os.chmod(p, stat.S_IREAD | stat.S_IRGRP | stat.S_IROTH)
    return sums


def verify_frozen(run_dir: Path) -> list[str]:
    """Compare a frozen run with its SHA256SUMS. Returns a list of problems (empty = intact)."""
    run_dir = Path(run_dir)
    if not is_frozen(run_dir):
        return [f"{run_dir} is not frozen"]
    expected = {}
    for line in (run_dir / SUMS_NAME).read_text(encoding="utf-8").splitlines():
        digest, rel = line.split("  ", 1)
        expected[rel] = digest
    actual = {p.relative_to(run_dir).as_posix(): p for p in _run_files(run_dir)}
    problems = [f"missing: {rel}" for rel in sorted(set(expected) - set(actual))]
    problems += [f"added after freeze: {rel}" for rel in sorted(set(actual) - set(expected))]
    problems += [f"changed: {rel}" for rel in sorted(set(expected) & set(actual))
                 if file_sha256(actual[rel]) != expected[rel]]
    return problems

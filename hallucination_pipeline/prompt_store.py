"""Loads the verbatim prompt texts from hallucination_pipeline/prompts/.

The prompts are part of the experimental protocol, not incidental strings:
changing a word changes what the LLM does, and therefore the results. They
live in plain-text files (extracted byte-for-byte from the original
experiment) so they can be diffed, versioned, and cited, and so no one has
to retype them.
"""

from __future__ import annotations

import hashlib
from functools import lru_cache

from . import config


@lru_cache(maxsize=None)
def load_prompt(name: str) -> str:
    return (config.PROMPTS_DIR / name).read_text(encoding="utf-8")


def prompt_sha256(name: str) -> str:
    """SHA-256 of a prompt file's exact bytes."""
    return hashlib.sha256((config.PROMPTS_DIR / name).read_bytes()).hexdigest()


def prompt_hashes() -> dict[str, str]:
    """Registry of every prompt file -> SHA-256. Written to each run manifest, so any
    edit to a prompt (which must be a new *_v2.txt file, never an in-place edit) shows up."""
    return {p.name: prompt_sha256(p.name) for p in sorted(config.PROMPTS_DIR.iterdir()) if p.is_file()}

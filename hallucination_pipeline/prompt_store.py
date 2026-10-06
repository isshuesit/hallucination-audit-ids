"""Loads the verbatim prompt texts from hallucination_pipeline/prompts/.

The prompts are part of the experimental protocol, not incidental strings:
changing a word changes what the LLM does, and therefore the results. They
live in plain-text files (extracted byte-for-byte from the original
experiment) so they can be diffed, versioned, and cited, and so no one has
to retype them.
"""

from __future__ import annotations

from functools import lru_cache

from . import config


@lru_cache(maxsize=None)
def load_prompt(name: str) -> str:
    return (config.PROMPTS_DIR / name).read_text(encoding="utf-8")

"""
Rule-engine version and fingerprints.

Every prediction record and every run manifest carries RULES_VERSION plus two
SHA-256 fingerprints, so a number can always be traced to the exact rule set
that produced it (the old paper mixed outputs from two rule versions).

RULE FOR CHANGING RULES: if you change any pattern in patterns.py or any logic
in rules.py, bump RULES_VERSION and add the new fingerprints to the pin table
in tests/test_run_infrastructure.py. That test fails until you do, so a rule
change can never slip through under an old version number.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from . import patterns as P

RULES_VERSION = "1.0.0"

_DETECTION_DIR = Path(__file__).resolve().parent


def _regex(r: re.Pattern) -> list:
    return [r.pattern, int(r.flags)]


def rule_patterns_canonical() -> dict:
    """Every pattern and lookup table the rule engine uses, as plain JSON data."""
    return {
        "factual": [[*_regex(p), t, d] for p, t, d in P.FACTUAL_PATTERNS],
        "reasoning": [[*_regex(p), t, d] for p, t, d in P.REASONING_PATTERNS],
        "certainty": [[*_regex(p), t, d] for p, t, d in P.CERTAINTY_PATTERNS],
        "soft_certainty": _regex(P.SOFT_CERTAINTY_RE),
        "external_knowledge": [[*_regex(p), d] for p, d in P.EXTERNAL_KNOWLEDGE_PATTERNS],
        "protocol_name": _regex(P.PROTOCOL_NAME_RE),
        "wellknown_port_protocols": P.WELLKNOWN_PORT_PROTOCOLS,
        "type_priority": P.TYPE_PRIORITY,
        "sentence_split": _regex(P._SENT_SPLIT_RE),
    }


def rules_patterns_sha256() -> str:
    """SHA-256 of all rule patterns (independent of comments and formatting)."""
    blob = json.dumps(rule_patterns_canonical(), sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def rules_source_sha256() -> str:
    """SHA-256 of patterns.py + rules.py source (catches inline regexes and logic changes)."""
    h = hashlib.sha256()
    for name in ("patterns.py", "rules.py"):
        text = (_DETECTION_DIR / name).read_bytes().replace(b"\r\n", b"\n")
        h.update(name.encode() + b"\0" + text + b"\0")
    return h.hexdigest()


def rules_stamp() -> dict:
    """The three fields written to every prediction record and the manifest."""
    return {
        "rules_version": RULES_VERSION,
        "rules_patterns_sha256": rules_patterns_sha256(),
        "rules_source_sha256": rules_source_sha256(),
    }

"""
Deterministic fake Gemini client, shared by the offline tests and
tools/verify_against_original.py.

The fake is a pure function of the prompt (plus how many times that exact
prompt has been seen), so two pipelines driven by it see identical LLM
behaviour. It deliberately includes the awkward cases: 429 rate-limit errors
with a retryDelay body, generic errors, fenced and malformed JSON, rewrites
that return the sentence unchanged, and rewrites that fail every retry.
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import sys
import types

# ── deterministic fake Gemini ─────────────────────────────────────────────

_CLEAN = [
    "The flow recorded {fwd} forward packets and {bwd} backward packets.",
    "The destination port value in the evidence is {port}.",
    "A SYN flag count of {syn} was recorded for this flow.",
    "The flow duration value is {dur} and the byte rate is {rate}.",
    "The ratio of forward to backward packets is notable in this record.",
    "Only the numeric flow features are available for this alert.",
]
_BAD = [
    "This flow exploits CVE-2017-0144 to gain access to the host.",
    "An attacker is targeting the database server through this connection.",
    "The server has been compromised by this traffic pattern.",
    "Port 443 is commonly used for HTTPS traffic on this network.",
    "The connection uses HTTPS encryption for this session.",
    "The flow lasted approximately 17 hours based on the duration value.",
    "This traffic pattern is definitely unusual for this network.",
    "This must be unusual activity given the packet counts observed.",
    "The pattern may indicate port scanning activity from a remote host.",
    "A brute-force attempt could result in unauthorized access to accounts.",
    "Nmap style tooling may have generated this traffic pattern here.",
    "ACK flags are expected in a fully established TCP connection here.",
    "Such behavior deviates significantly from typical web traffic patterns.",
    "Source 192.168.1.10 sent the packets to the destination host.",
    "The resource exhaustion of the server is likely under this load.",
    "The adversary intends to exfiltrate data over this connection.",
]
_FENCE = "```json\n{body}\n```"


def _h(*parts: str) -> int:
    return int(hashlib.md5("||".join(parts).encode()).hexdigest(), 16)


class _Usage:
    """Mimics google.genai's usage_metadata (word counts stand in for tokens)."""

    def __init__(self, prompt: str, text: str):
        self.prompt_token_count = len(prompt.split())
        self.candidates_token_count = len(text.split())
        self.thoughts_token_count = 0
        self.total_token_count = self.prompt_token_count + self.candidates_token_count


class _Resp:
    def __init__(self, text: str):
        self.text = text
        self.model_version = "fake-gemini-001"
        self.usage_metadata = None


class FakeGemini:
    """Deterministic stand-in for google.genai.Client()."""

    class _Models:
        def __init__(self, outer):
            self.outer = outer

        def generate_content(self, model=None, contents="", config=None):
            resp = self.outer._generate(contents, config)
            resp.usage_metadata = _Usage(contents, resp.text)
            return resp

    def __init__(self, *a, **kw):
        self.models = FakeGemini._Models(self)
        self.seen: dict[str, int] = {}

    def _generate(self, prompt: str, config):
        key = hashlib.md5(prompt.encode()).hexdigest()
        n = self.seen.get(key, 0)
        self.seen[key] = n + 1
        h = _h(prompt)

        # --- QUALIFY rewrites (editor prompts) ---
        if "cybersecurity explanation editor" in prompt:
            sentence = prompt.rsplit("\n", 1)[-1]
            mode = h % 20
            if mode == 0 and n == 0:
                raise RuntimeError('429 RESOURCE_EXHAUSTED {"error": {"details": [{"retryDelay": "3s"}]}}')
            if mode == 1 and n == 0:
                raise RuntimeError("503 service unavailable")
            if mode == 2:
                raise RuntimeError("500 always failing")          # exhausts retries -> fallback subs
            if mode == 3:
                return _Resp(sentence)                              # identical sentence
            words = sentence.split()
            return _Resp("Observed values only: " + " ".join(words[3:]) if len(words) > 6 else "The raw values were observed.")

        # --- re-check of a rewrite (impact analysis) ---
        if "Rewritten sentence to audit" in prompt:
            mode = h % 10
            if mode == 0:
                return _Resp("not json at all, the sentence is hallucinated")
            if mode == 1:
                return _Resp("not json at all, the sentence looks grounded")
            if mode == 2:
                return _Resp("complete gibberish")
            label = "grounded" if h % 3 else "hallucinated"
            return _Resp(json.dumps({"label": label, "confidence": "high", "reason": f"fake reason {h % 97}"}))

        # --- sentence-level judge ---
        if "sentence-level hallucination auditor" in prompt:
            mode = h % 12
            if mode == 0 and n == 0:
                raise RuntimeError('429 RESOURCE_EXHAUSTED {"error": {"details": [{"retryDelay": "2s"}]}}')
            body = json.dumps({
                "label": "hallucinated" if h % 2 else "grounded",
                "confidence": ["high", "medium", "low"][h % 3],
                "hallucination_type": ["reasoning", "certainty", "external_knowledge", "factual", None][h % 5],
                "reason": f"fake sentence reason {h % 89}",
            })
            if mode == 1:
                return _Resp(_FENCE.format(body=body))
            if mode == 2:
                return _Resp("totally malformed {{ output")
            return _Resp(body)

        # --- explanation-level judge ---
        if "RAW FLOW EVIDENCE" in prompt and "contains_hallucination" in prompt:
            mode = h % 10
            body = json.dumps({
                "contains_hallucination": bool(h % 2),
                "confidence": ["high", "medium", "low"][h % 3],
                "hallucination_type": ["reasoning", "certainty", "external_knowledge", None][h % 4],
                "reason": f"fake explanation reason {h % 83}",
            })
            if mode == 0:
                return _Resp(_FENCE.format(body=body))
            if mode == 1:
                return _Resp("malformed")
            return _Resp(body)

        # --- explanation generation ---
        rng = random.Random(h)
        nums = {k: (re.search(rf"{pat}: (\d+)", prompt) or [None, "0"])[1]
                for k, pat in [("fwd", "Forward Packets"), ("bwd", "Backward Packets"),
                               ("port", "Destination Port"), ("syn", "SYN Flag Count"),
                               ("dur", "Flow Duration")]}
        nums["rate"] = (re.search(r"Flow Bytes/s: ([\d.]+)", prompt) or [None, "0"])[1]
        sents = [rng.choice(_CLEAN).format(**nums) for _ in range(rng.randint(3, 6))]
        sents += [rng.choice(_BAD) for _ in range(rng.randint(0, 3))]
        rng.shuffle(sents)
        return _Resp("  " + " ".join(sents) + "  ")


def install_stubs() -> None:
    google = types.ModuleType("google")
    genai = types.ModuleType("google.genai")
    gtypes = types.ModuleType("google.genai.types")

    class _Cfg:
        def __init__(self, **kw):
            self.kw = kw

    gtypes.GenerateContentConfig = _Cfg
    gtypes.ThinkingConfig = _Cfg
    genai.types = gtypes
    genai.Client = FakeGemini
    google.genai = genai
    sys.modules.update({"google": google, "google.genai": genai, "google.genai.types": gtypes})
    import time
    time.sleep = lambda *_a, **_k: None  # no real waiting


# ── synthetic CIC-IDS 2017 CSVs ───────────────────────────────────────────

# Header exactly as in the original UNB CSVs: most names carry a leading space.
CIC_COLUMNS = {
    "Destination Port": " Destination Port", "Flow Duration": " Flow Duration",
    "Total Fwd Packets": " Total Fwd Packets", "Total Backward Packets": " Total Backward Packets",
    "Flow Bytes/s": "Flow Bytes/s", "Flow Packets/s": " Flow Packets/s",
    "SYN Flag Count": " SYN Flag Count", "ACK Flag Count": " ACK Flag Count",
    "RST Flag Count": " RST Flag Count", "Label": " Label",
}


def make_cicids_csv(path, label_counts: dict, seed: int = 0, drop_columns=(), extra_columns: bool = True) -> None:
    """Write a CIC-IDS-2017-style CSV with `label_counts[label]` rows per label.
    Includes the awkward bits of the real files: padded column names, NaN/inf values,
    an unrelated extra column, and rows shuffled across labels."""
    import numpy as np
    import pandas as pd

    rng = np.random.default_rng(seed)
    labels = [lab for lab, n in label_counts.items() for _ in range(n)]
    n = len(labels)
    df = pd.DataFrame({
        "Destination Port": rng.choice([21, 22, 80, 443, 8080, 444], n),
        "Flow Duration": rng.integers(1, 10**8, n),
        "Total Fwd Packets": rng.integers(1, 900, n),
        "Total Backward Packets": rng.integers(0, 60, n),
        "Flow Bytes/s": rng.uniform(1, 9000, n),
        "Flow Packets/s": rng.uniform(0.1, 90, n),
        "SYN Flag Count": rng.integers(0, 800, n),
        "ACK Flag Count": rng.integers(0, 60, n),
        "RST Flag Count": rng.integers(0, 3, n),
        "Label": labels,
    })
    if n >= 4:
        df.loc[0, "Flow Bytes/s"] = np.nan
        df.loc[1, "Flow Packets/s"] = np.inf
    if extra_columns:
        df.insert(1, "Fwd Header Length.1", rng.integers(0, 500, n))
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    df = df.drop(columns=list(drop_columns)).rename(columns=CIC_COLUMNS)
    df.to_csv(path, index=False)

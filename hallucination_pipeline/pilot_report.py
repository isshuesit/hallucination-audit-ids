"""
M3b pilot report (D24): is the plumbing sound before freeze-1?

Prints LLM calls per stage and in total, cache hits, tokens, wall time, rate-limit waits,
judge reply problems by kind, and the share of explanations each detection config flags under
each policy (per arm); writes 20 randomly chosen v2 judge replies to
runs/<run_id>/samples/pilot_judge_replies.md for reading by hand. Debugging only: pilot numbers
are never results and never used to tune rules.
"""

from __future__ import annotations

import json
import random
from collections import Counter, defaultdict
from pathlib import Path

from .run_dir import write_text

PROBLEM_KINDS = (  # (kind, substring of a reply_problems message), first match wins
    ("bad JSON", "bad JSON"),
    ("call failed", "call failed"),
    ("missing note", "needs a short free-text note"),
    ("unknown subtype", "unknown subtype"),
    ("tier mismatch", "reply says tier"),
    ("invalid tier", "tier is "),
    ("verdict/tier inconsistent", "without a tier"),
    ("verdict/tier inconsistent", "but a tier/subtype was given"),
    ("invalid verdict", "contains_hallucination is"),
    ("invalid verdict", "label is"),
)


def problem_kind(message: str) -> str:
    for kind, needle in PROBLEM_KINDS:
        if needle in message:
            return kind
    return "other"


def _load(run_dir: Path, name: str) -> list[dict]:
    path = run_dir / name
    return json.loads(path.read_text(encoding="utf-8")) if path.exists() else []


def build_report(run_dir: Path, *, seed: int = 42, n_samples: int = 20) -> dict:
    run_dir = Path(run_dir)
    manifest = json.loads((run_dir / "MANIFEST.json").read_text(encoding="utf-8"))
    llm = manifest["llm"]
    data = {arm: {"detect": _load(run_dir, f"{p}detection.json"), "sentences": _load(run_dir, f"{p}sentences.json"),
                  "alerts": _load(run_dir, f"{p}alerts.json"), "explanations": _load(run_dir, f"{p}explanations.json")}
            for arm, p in (("attack", ""), ("benign_control", "benign_control/"))}

    problems = Counter()
    judged = Counter()
    for arm in data.values():
        for level in ("detect", "sentences"):
            for r in arm[level]:
                if r.get("judge"):
                    judged[level] += 1
                    for m in r["judge"]["reply_problems"]:
                        problems[f"{level}: {problem_kind(m)}"] += 1

    flagged = {}
    for arm, d in data.items():
        cells = defaultdict(lambda: Counter())
        for r in d["detect"]:
            c = cells[(r["config"], r["policy"])]
            c["n"] += 1
            c[{True: "flagged", False: "clean", None: "undecided"}[r["contains_hallucination"]]] += 1
            c["judge_called"] += r["detection_method"] != "rule"
        flagged[arm] = {f"{k[0]}/{k[1]}": dict(v) for k, v in sorted(cells.items())}

    v2 = [(arm, r) for arm, d in data.items() for level in ("detect", "sentences") for r in d[level]
          if r.get("judge") and r["judge"]["prompt"].startswith("v2")]
    rng = random.Random(f"{seed}:pilot-samples")
    samples = rng.sample(v2, min(n_samples, len(v2)))
    return {"run_id": manifest["run_id"], "status": llm.get("status"), "llm": llm, "judged": dict(judged),
            "reply_problems": dict(sorted(problems.items())), "flagged": flagged, "samples": samples,
            "data": data}


def format_report(rep: dict) -> str:
    llm = rep["llm"]
    out = [f"PILOT REPORT {rep['run_id']}  (status: {rep['status']})", "",
           "LLM calls          API calls  cache hits  errors  rate-limit waits  tokens  wall s"]
    for stage in ("generate", "detect", "sentences"):
        s = llm.get("per_stage", {}).get(stage)
        if s:
            out.append(f"  {stage:<16}{s.get('api_calls', 0):>10}{s.get('cache_hits', 0):>12}{s.get('api_errors', 0):>8}"
                       f"{s.get('rate_limit_errors', 0):>18}{s.get('tokens', {}).get('total_token_count', 0):>8}"
                       f"{s.get('wall_seconds', 0):>8.1f}")
    tok = llm.get("tokens", {})
    out += [f"  {'TOTAL':<16}{llm.get('api_calls', 0):>10}{llm.get('cache_hits', 0):>12}{llm.get('api_errors', 0):>8}"
            f"{llm.get('rate_limit_errors', 0):>18}{tok.get('total_token_count', 0):>8}"
            f"{sum(llm.get('wall_seconds', {}).values()):>8.1f}",
            f"  tokens: prompt {tok.get('prompt_token_count', 0)}, output {tok.get('candidates_token_count', 0)}, "
            f"thinking {tok.get('thoughts_token_count', 0)}; model versions {llm.get('model_versions_returned')}", "",
            f"Judge calls recorded: {rep['judged']}. Reply problems by kind:"]
    out += [f"  {k:<40}{v:>5}" for k, v in rep["reply_problems"].items()] or ["  none"]
    for arm, cells in rep["flagged"].items():
        out += ["", f"Explanations flagged ({arm}): config/policy  flagged  undecided  of n  (judge called)"]
        for cell, c in cells.items():
            n = c.get("n", 0)
            share = c.get("flagged", 0) / n if n else 0
            out.append(f"  {cell:<14}{share:>8.0%}{c.get('undecided', 0):>11}{n:>6}   ({c.get('judge_called', 0)})")
    return "\n".join(out)


def write_samples(run_dir: Path, rep: dict) -> Path:
    alerts = {a["alert_id"]: a for d in rep["data"].values() for a in d["alerts"]}
    expl = {e["alert_id"]: e for d in rep["data"].values() for e in d["explanations"]}
    parts = [f"# Pilot: {len(rep['samples'])} randomly chosen v2 judge replies (run {rep['run_id']})", "",
             "Debugging only (D24). Check each reply is well-formed and consistent with the guide; do not tune rules.",
             ""]
    for i, (arm, r) in enumerate(rep["samples"], start=1):
        level = "sentence" if "sentence_id" in r else "explanation"
        text = r["sentence_text"] if level == "sentence" else expl[r["alert_id"]]["explanation"]
        j = r["judge"]
        parts += [f"## {i}. {r['alert_id']} ({arm}), {level} level, judge {j['prompt']}", "",
                  "Evidence:", "```", alerts[r["alert_id"]]["evidence"], "```", "", f"Text: {text}", "",
                  "Reply:", "```json", json.dumps(j["reply"], indent=2, ensure_ascii=False) if j["reply"] is not None
                  else f"(unparseable) {j.get('raw_text')!r}", "```",
                  f"Problems: {', '.join(j['reply_problems']) or 'none'}", ""]
    return write_text(run_dir, "samples/pilot_judge_replies.md", "\n".join(parts) + "\n")

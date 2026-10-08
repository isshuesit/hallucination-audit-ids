"""
Read-only check: how complete is the evidence in the earlier run's corpus?

    python tools/evidence_completeness.py [--corpus-dir old_run] [--json]

For the explanations the corpus analysis uses (corpus.usable: generation did not fail), counts how many alerts
have 9, 8, 7, ... evidence lines, which of the nine evidence fields are missing and how often, split by
attack-flow and normal-flow (benign-flow), and how many alerts have Flow Duration (needed by the D19 unit_wrong
check). Uses the frozen corpus code read-only; no API call; writes nothing.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from hallucination_pipeline import corpus as CO  # noqa: E402  (frozen, read-only)

# The nine fields as they are written in evidence strings (data_loader.build_evidence_string)
FIELDS = ("Destination Port", "Flow Duration", "Forward Packets", "Backward Packets", "Flow Bytes/s",
          "Flow Packets/s", "SYN Flag Count", "ACK Flag Count", "RST Flag Count")
GROUP_LABEL = {"attack-flow": "attack-flow", "benign-flow": "normal-flow"}


def present_fields(evidence: str) -> set[str]:
    names = {line.split(":", 1)[0].strip() for line in evidence.splitlines() if ":" in line}
    return {f for f in FIELDS if f in names}


def completeness(alerts: list[dict], explanations: list[dict]) -> dict:
    by_id = {a["alert_id"]: a for a in alerts}
    used = [by_id[e["alert_id"]] for e in explanations if CO.usable(e)]
    out = {"explanations_used": len(used), "groups": {}}
    for key, sel in (("all", used), *((g, [a for a in used if CO.group_of(a["alert_type"]) == g]) for g in CO.GROUPS)):
        present = [present_fields(a["evidence"]) for a in sel]
        out["groups"][GROUP_LABEL.get(key, key)] = {
            "alerts": len(sel),
            "by_number_of_lines": dict(sorted(Counter(len(p) for p in present).items(), reverse=True)),
            "missing_field_counts": {f: sum(f not in p for p in present) for f in FIELDS},
            "flow_duration_present": sum("Flow Duration" in p for p in present),
            "unrecognised_lines": sum(len([l for l in a["evidence"].splitlines() if l.strip()]) - len(p)
                                      for a, p in zip(sel, present)),
        }
    return out


def format_report(r: dict) -> str:
    groups = list(r["groups"])
    w = 22
    lines = [f"Evidence completeness: {r['explanations_used']} explanations used by the corpus analysis", "",
             f"{'':<{w}}" + "".join(f"{g:>14}" for g in groups),
             f"{'alerts':<{w}}" + "".join(f"{r['groups'][g]['alerts']:>14}" for g in groups), "",
             "Alerts by number of evidence lines (of 9):"]
    counts = sorted({n for g in groups for n in r["groups"][g]["by_number_of_lines"]}, reverse=True)
    for n in counts:
        lines.append(f"  {n} lines{'':<{w - 10}}" + "".join(f"{r['groups'][g]['by_number_of_lines'].get(n, 0):>14}"
                                                       for g in groups))
    lines += ["", "Alerts where the field is MISSING:"]
    for f in FIELDS:
        lines.append(f"  {f:<{w - 2}}" + "".join(f"{r['groups'][g]['missing_field_counts'][f]:>14}" for g in groups))
    lines += ["", f"{'Flow Duration present':<{w}}" + "".join(f"{r['groups'][g]['flow_duration_present']:>14}"
                                                            for g in groups)]
    if any(r["groups"][g]["unrecognised_lines"] for g in groups):
        lines.append(f"{'unrecognised lines':<{w}}" + "".join(f"{r['groups'][g]['unrecognised_lines']:>14}"
                                                             for g in groups))
    return "\n".join(lines)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--corpus-dir", default=str(REPO_ROOT / "old_run"))
    ap.add_argument("--json", action="store_true", help="print the counts as JSON")
    args = ap.parse_args(argv)
    d = Path(args.corpus_dir)
    load = lambda n: json.loads((d / n).read_text(encoding="utf-8"))
    r = completeness(load("alerts.json"), load("llm_explanations.json"))
    print(json.dumps(r, indent=2) if args.json else format_report(r))
    return 0


if __name__ == "__main__":
    sys.exit(main())

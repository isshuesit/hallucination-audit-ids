"""
AI-annotator audit labels (DECISIONS D30, D31), built on the frozen annotation code (used read-only).

    python tools/ai_labelling.py ai_export
    python tools/ai_labelling.py ai_import --labeller gemini
    python tools/ai_labelling.py ai_import --labeller gpt
    python tools/ai_labelling.py ai_compare --labellers gemini gpt
    python tools/ai_labelling.py ai_finalize --labellers gemini gpt --author IS

Files live in annotation/<corpus_id>/ai/:
  chunks/chunk_NN.txt          what you paste to each AI (after docs/AI_LABELLER_PROMPT.md)
  replies/<name>_chunk_NN.txt  what each AI answered (you save these)
  labelling_manifest.json      D31: model, version, date, interface, tools, customisation (you fill it)
  labels_<name>.csv / .json    one AI's labels, D23-valid
  adjudication.csv             YOUR blind sheet: all AI disagreements + a random 20% of agreements, shuffled,
                               without either AI's answer
  hidden/                      do NOT open before finishing adjudication: which items were disagreements,
                               both AIs' answers, agreement details
  final_labels.csv             D23 labels: your decisions on adjudicated items, AI consensus elsewhere
The detector-versus-label results go to results/<corpus_id>/audit_ai/. No API call anywhere.
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import random
import re
import sys
import tempfile
from collections import defaultdict
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from hallucination_pipeline import annotation as AN  # noqa: E402  (frozen, used read-only)
from hallucination_pipeline import audit as AU  # noqa: E402
from hallucination_pipeline import corpus as CO  # noqa: E402
from hallucination_pipeline.policy import SUBTYPES  # noqa: E402  (frozen vocabulary = docs/SUBTYPES.md order)

EXPLANATIONS_PER_CHUNK = 5
SPOT_CHECK_SHARE = 0.20
SEED = 42
FIELDS = ("item_id", "label", "subtype", "hedged", "other_subtypes", "note", "unsure")
EMPTY_WORDS = {"", "-", "—", "none", "null", "n/a", "na", "empty"}
MANIFEST_FIELDS = ("model_name", "model_version", "date", "interface", "tools", "customisation")
FILL = "FILL IN"


class LabellingError(RuntimeError):
    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__(f"{len(problems)} problem(s):\n  " + "\n  ".join(problems))


# ── paths ─────────────────────────────────────────────────────────────────

def ai_dir(annotation_dir: Path, corpus_id: str) -> Path:
    return Path(annotation_dir) / corpus_id / "ai"


def _read_sheet(annotation_dir: Path, corpus_id: str) -> list[dict]:
    path = Path(annotation_dir) / corpus_id / "sheets" / "primary.csv"
    if not path.exists():
        raise FileNotFoundError(f"{path} not found: run `python -m hallucination_pipeline.cli audit_export` first")
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def _read_key(annotation_dir: Path, corpus_id: str) -> dict:
    return json.loads((Path(annotation_dir) / corpus_id / "key.json").read_text(encoding="utf-8"))


# ── 1. export chunks ──────────────────────────────────────────────────────

def chunk_texts(sheet: list[dict], per_chunk: int = EXPLANATIONS_PER_CHUNK) -> list[str]:
    """Only sheet fields are used: explanation id, evidence lines, item codes and sentences."""
    by_expl: dict[str, list] = {}
    for r in sheet:
        by_expl.setdefault(r["explanation_id"], []).append(r)
    ids = list(by_expl)
    chunks = []
    for start in range(0, len(ids), per_chunk):
        parts = []
        for eid in ids[start:start + per_chunk]:
            rows = by_expl[eid]
            parts += [f"EXPLANATION {eid}", "Evidence:", *rows[0]["evidence"].splitlines(), "Sentences to label:"]
            parts += [f"[{r['item_id']}] {r['sentence']}" for r in rows]
            parts.append("")
        chunks.append("\n".join(parts).rstrip() + "\n")
    return chunks


def manifest_template(labellers=("gemini", "gpt")) -> dict:
    return {"decision": "D31", "note": "Fill every field. customisation: 'none', or the docs/ file holding the "
                                       "custom instructions you copied there.",
            "labellers": {name: {f: FILL for f in MANIFEST_FIELDS} for name in labellers}}


def ai_export(annotation_dir: Path, corpus_id: str) -> Path:
    out = ai_dir(annotation_dir, corpus_id)
    chunks = chunk_texts(_read_sheet(annotation_dir, corpus_id))
    (out / "chunks").mkdir(parents=True, exist_ok=True)
    (out / "replies").mkdir(exist_ok=True)
    for i, text in enumerate(chunks, start=1):
        path = out / "chunks" / f"chunk_{i:02d}.txt"
        if path.exists() and path.read_text(encoding="utf-8") != text:
            raise LabellingError([f"{path} exists with different content; chunks are never overwritten"])
        path.write_text(text, encoding="utf-8", newline="\n")
    man = out / "labelling_manifest.json"
    if not man.exists():
        man.write_text(json.dumps(manifest_template(), indent=2) + "\n", encoding="utf-8", newline="\n")
    return out


# ── 2. import one labeller's replies ──────────────────────────────────────

_BULLET = re.compile(r"^\s*(?:[-*\u2022+]|\d+[.)])\s+")
_SEPARATOR = re.compile(r"^[\s|:\-]+$")
_CODE_BEFORE_BAR = re.compile(r"[\[`*_]*\b([A-Z]\d{3}-\d{2})\b[\]`*_]*\s*\|")
_FENCE_ONLY = re.compile(r"^```[\w-]*$")
_DANGLING_BULLET = re.compile(r"\s+(?:[-*•+]|\d+[.)])$")
_ODD_SPACES = re.compile("[\u00a0\u2007\u202f\u2009\u200b\ufeff]")


def _clean_code(s: str) -> str:
    return s.strip().strip("[]`*_ ").strip()


def normalise_text(text: str) -> str:
    """D32(a): line breaks that are only \r (or \r\n) become \n; non-breaking and other odd spaces become spaces."""
    return _ODD_SPACES.sub(" ", text.replace("\r\n", "\n").replace("\r", "\n"))


def split_collapsed(line: str) -> list[str]:
    """D32(a): a line holding several item codes (each directly before a '|') is split into one record per code.
    Text before the first code (e.g. a code fence) is dropped. A line with 0 or 1 code is returned unchanged."""
    starts = [m.start() for m in _CODE_BEFORE_BAR.finditer(line)]
    if len(starts) < 2:
        return [line]
    parts = [line[a:b].strip() for a, b in zip(starts, starts[1:] + [len(line)])]
    # a bullet or number that introduced the NEXT record ("... | 2. E001-02 | ...") is not part of this one
    return [_DANGLING_BULLET.sub("", p) for p in parts[:-1]] + parts[-1:]


def parse_reply_lines(text: str, source: str, known: set[str]) -> tuple[list[tuple], list[str], int, list[dict]]:
    """(items as (code, fields, where), problems, ignored non-item lines, repairs). Tolerates code fences, bullets,
    numbering, extra spaces, a leading/trailing '|', markdown table rows, header and separator rows, and (D32a)
    whole replies collapsed onto one line, bare \r line breaks and non-breaking spaces."""
    items, problems, ignored, repairs = [], [], 0, []
    for n, raw in enumerate(normalise_text(text).splitlines(), start=1):
        records = split_collapsed(raw.strip())
        if len(records) > 1:
            repairs.append({"repair": "split_collapsed_line", "where": f"{source}:{n}", "records": len(records)})
        for k, rec in enumerate(records, start=1):
            where = f"{source}:{n}" + (f" record {k}" if len(records) > 1 else "")
            line = rec.strip()
            if not line or _FENCE_ONLY.match(line) or _SEPARATOR.match(line):
                continue
            line = _BULLET.sub("", line.strip("`").strip()).strip()     # a fence glued to a record is not content
            if line.startswith("|"):
                line = line[1:]
            line = line.rstrip()
            if line.endswith("|") and line.count("|") > 6:
                line = line[:-1]
            fields = [f.strip() for f in line.split("|")]
            code = _clean_code(fields[0])
            if code.upper() == "ITEM_CODE":
                continue
            if code not in known:
                if re.fullmatch(r"[A-Z]\d{3}-\d{2}", code):
                    problems.append(f"{code} ({where}): unknown item code")
                elif any(c in line for c in known):
                    problems.append(f"{where}: could not read this line: {rec.strip()[:80]!r}")
                else:
                    ignored += 1
                continue
            if len(fields) > len(FIELDS):
                problems.append(f"{code} ({where}): {len(fields)} fields, expected {len(FIELDS)} (is there a | in the note?)")
                continue
            fields += [""] * (len(FIELDS) - len(fields))
            items.append((code, fields, where))
    return items, problems, ignored, repairs


SUBTYPE_ORDER = {name: i for i, name in enumerate(k for k, v in SUBTYPES.items() if v.label)}


def repair_multi_subtype(code: str, answer: dict) -> tuple[dict, dict | None, str | None]:
    """D32(b): a subtype field holding several names keeps ONE primary (Tier 1 beats Tier 2; within a tier the name
    listed first in docs/SUBTYPES.md) and moves the rest to other_subtypes. Never changes the label, the hedged
    value, or the tier beyond that rule. Returns (answer, repair record or None, problem or None)."""
    names = [s.strip() for s in answer["subtype"].split(",") if s.strip()]
    if len(names) < 2:
        return answer, None, None
    if answer["label"] != "hallucinated":
        return answer, None, (f"{code}: several subtypes ({len(names)}) on a line whose label is not 'hallucinated'; "
                              "not repaired (a repair never changes a label)")
    unknown = [s for s in names if s not in SUBTYPE_ORDER]
    if unknown:
        return answer, None, f"{code}: unknown subtype {', '.join(map(repr, unknown))} in a multi-subtype field"
    primary = min(names, key=lambda s: (SUBTYPES[s].tier, SUBTYPE_ORDER[s]))
    others = [s for s in names if s != primary]
    others += [s for s in answer["other_subtypes"].split(",") if s and s not in others and s != primary]
    repaired = {**answer, "subtype": primary, "other_subtypes": ",".join(others)}
    return repaired, {"repair": "multi_subtype_field", "item": code, "field": answer["subtype"], "primary": primary,
                      "moved_to_other_subtypes": [s for s in names if s != primary]}, None


def _norm(fields: list[str]) -> dict:
    code, label, subtype, hedged, others, note, unsure = fields
    empty = lambda v: "" if v.strip().lower().strip("`*_") in EMPTY_WORDS else v.strip()
    subtype = empty(subtype).strip("`*_").lower()
    others = ",".join(o.strip().strip("`*_").lower() for o in empty(others).split(",") if o.strip())
    return {"label": empty(label).strip("`*_").lower(), "subtype": subtype, "hedged": empty(hedged).lower(),
            "other_subtypes": others, "note": empty(note), "unsure": empty(unsure).lower()}


def ai_import(annotation_dir: Path, corpus_id: str, labeller: str) -> dict:
    """Parse replies/<labeller>_chunk_*.txt, validate with D23 (annotation.import_sheet), write labels_<name>.*."""
    out = ai_dir(annotation_dir, corpus_id)
    if (out / "adjudication.csv").exists():
        raise LabellingError(["adjudication.csv exists: AI labels can no longer be re-imported"])
    files = sorted((out / "replies").glob(f"{labeller}_chunk_*.txt"))
    if not files:
        raise FileNotFoundError(f"no files named {labeller}_chunk_*.txt in {out / 'replies'}")
    sheet = _read_sheet(annotation_dir, corpus_id)
    key = _read_key(annotation_dir, corpus_id)
    known = set(key["sheets"]["primary"]["items"])
    seen: dict[str, str] = {}
    answers: dict[str, dict] = {}
    problems, ignored, repairs = [], 0, []
    for f in files:
        items, probs, ign, reps = parse_reply_lines(f.read_text(encoding="utf-8-sig"), f.name, known)
        problems += probs
        ignored += ign
        repairs += reps
        for code, fields, where in items:
            if code in seen:
                problems.append(f"{code} ({where}): duplicate (first at {seen[code]})")
                continue
            seen[code] = where
            ans, repair, problem = repair_multi_subtype(code, _norm(fields))
            if repair:
                repairs.append(repair)
            if problem:
                problems.append(problem)
            answers[code] = ans
    counts = repair_counts(repairs)
    missing = [r["item_id"] for r in sheet if r["item_id"] not in answers]
    duplicates = sorted({p.split(" ")[0] for p in problems if "duplicate" in p})
    if not missing:   # the D23 rules, applied by the frozen importer
        rows = [{**r, **answers[r["item_id"]]} for r in sheet]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "labels.csv"
            _write_sheet_csv(path, rows)
            try:
                labels = AN.import_sheet(path, key, "primary", labeller)["labels"]
            except AN.AnnotationImportError as e:
                problems += [re.sub(r"^line \d+ \((.*?)\)", r"\1", p) for p in e.problems]
    else:
        problems.append(f"missing item codes ({len(missing)}): {', '.join(missing)}")
    if problems:
        raise LabellingError(problems + ([f"duplicate item codes: {', '.join(duplicates)}"] if duplicates else [])
                             + [f"format repairs that were applied before these checks (D32): {counts}"])
    _write_sheet_csv(out / f"labels_{labeller}.csv", rows)
    (out / f"labels_{labeller}.json").write_text(json.dumps(AN.labels_to_json(labels), indent=2, ensure_ascii=False)
                                                 + "\n", encoding="utf-8", newline="\n")
    record_repairs(out, labeller, counts, repairs)
    return {"labeller": labeller, "files": [f.name for f in files], "items": len(labels),
            "hallucinated": sum(g.label == "hallucinated" for g in labels), "ignored_lines": ignored,
            "repairs": counts}


def repair_counts(repairs: list[dict]) -> dict:
    return {"collapsed_lines_split": sum(r["repair"] == "split_collapsed_line" for r in repairs),
            "records_recovered_from_split_lines": sum(r.get("records", 0) for r in repairs
                                                      if r["repair"] == "split_collapsed_line"),
            "multi_subtype_fields_repaired": sum(r["repair"] == "multi_subtype_field" for r in repairs)}


def record_repairs(out: Path, labeller: str, counts: dict, repairs: list[dict]) -> None:
    """D32: counts go into labelling_manifest.json (format_repairs.<labeller>); the per-item details, which would
    show what the AI answered, go to hidden/format_repairs_<labeller>.json (not to be opened before adjudication)."""
    man_path = out / "labelling_manifest.json"
    try:
        man = json.loads(man_path.read_text(encoding="utf-8")) if man_path.exists() else manifest_template()
    except json.JSONDecodeError as e:
        raise LabellingError([f"{man_path} is not valid JSON ({e}); fix it (save it in VS Code) and import again"])
    man.setdefault("format_repairs", {})[labeller] = {**counts, "decision": "D32"}
    man_path.write_text(json.dumps(man, indent=2, ensure_ascii=False) + "\n", encoding="utf-8", newline="\n")
    (out / "hidden").mkdir(exist_ok=True)
    (out / "hidden" / f"format_repairs_{labeller}.json").write_text(
        json.dumps({"labeller": labeller, "counts": counts, "repairs": repairs}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8", newline="\n")


def _write_sheet_csv(path: Path, rows: list[dict], comments: list[str] = ()) -> None:
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        for c in comments:
            f.write(f"# {c}\n")
        w = csv.DictWriter(f, fieldnames=AN.SHEET_COLUMNS, extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def _load_labels(out: Path, name: str) -> list:
    path = out / f"labels_{name}.json"
    if not path.exists():
        raise FileNotFoundError(f"{path} not found: run ai_import --labeller {name} first")
    return AN.labels_from_json(json.loads(path.read_text(encoding="utf-8")))


# ── 3. compare and build the blind adjudication sheet ─────────────────────

def answer(g) -> tuple:
    """What two labellers must share to agree on an item: label, subtype and hedged."""
    return (g.label, g.subtype, g.hedged)


def ai_compare(annotation_dir: Path, corpus_id: str, a_name: str, b_name: str, *, seed: int = SEED) -> dict:
    out = ai_dir(annotation_dir, corpus_id)
    if (out / "adjudication.csv").exists():
        raise LabellingError([f"{out / 'adjudication.csv'} already exists; it is never rebuilt"])
    a, b = _load_labels(out, a_name), _load_labels(out, b_name)
    ka, kb = {g.item_id: g for g in a}, {g.item_id: g for g in b}
    sheet = _read_sheet(annotation_dir, corpus_id)
    disagree = [r["item_id"] for r in sheet if answer(ka[r["item_id"]]) != answer(kb[r["item_id"]])]
    agree = [r["item_id"] for r in sheet if r["item_id"] not in set(disagree)]
    n_spot = round(SPOT_CHECK_SHARE * len(agree))
    spot = sorted(random.Random(f"{seed}:spot-check").sample(agree, n_spot))
    chosen = disagree + spot
    random.Random(f"{seed}:adjudication-order").shuffle(chosen)
    by_id = {r["item_id"]: r for r in sheet}
    rows = [{**by_id[i], **{c: "" for c in AN.ANNOTATION_COLUMNS}} for i in chosen]     # no AI answer, ever
    agreement = AN.agreement(a, b, seed=seed)
    both_h = [i for i in ka if ka[i].label == kb[i].label == "hallucinated"]
    hedged_k = AN.cohen_kappa([ka[i].hedged for i in both_h], [kb[i].hedged for i in both_h]) if both_h else None

    (out / "hidden").mkdir(exist_ok=True)
    _write_sheet_csv(out / "adjudication.csv", rows)
    (out / "hidden" / "adjudication_key.json").write_text(json.dumps({
        "labellers": [a_name, b_name], "seed": seed, "spot_check_share": SPOT_CHECK_SHARE,
        "n_disagreements": len(disagree), "n_agreements": len(agree), "n_spot_check": n_spot,
        "items": {i: ("disagreement" if i in set(disagree) else "spot_check") for i in chosen}}, indent=2) + "\n",
        encoding="utf-8", newline="\n")
    (out / "hidden" / "ai_agreement.json").write_text(json.dumps(
        {**agreement, "hedged_kappa_where_both_hallucinated": hedged_k, "n_both_hallucinated": len(both_h)},
        indent=2) + "\n", encoding="utf-8", newline="\n")
    with open(out / "hidden" / "ai_disagreements.csv", "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["item_id", "sentence", f"{a_name}_label", f"{a_name}_subtype", f"{a_name}_hedged",
                    f"{b_name}_label", f"{b_name}_subtype", f"{b_name}_hedged"])
        for i in disagree:
            w.writerow([i, by_id[i]["sentence"], *answer(ka[i]), *answer(kb[i])])
    return {"items": len(sheet), "disagreements": len(disagree), "agreements": len(agree), "spot_check": n_spot,
            "to_adjudicate": len(chosen), "kappa_label": agreement["kappa"]["label"]["kappa"],
            "kappa_tier": agreement["kappa"]["tier"]["kappa"]}


# ── 4. finalize ───────────────────────────────────────────────────────────

def check_manifest(out: Path, names: list[str]) -> dict:
    path = out / "labelling_manifest.json"
    if not path.exists():
        raise LabellingError([f"{path} is missing (D31)"])
    man = json.loads(path.read_text(encoding="utf-8"))
    problems = []
    for n in names:
        entry = man.get("labellers", {}).get(n)
        if entry is None:
            problems.append(f"labelling_manifest.json has no entry for {n!r}")
            continue
        problems += [f"labelling_manifest.json: {n}.{f} is not filled in" for f in MANIFEST_FIELDS
                     if not str(entry.get(f, "")).strip() or FILL in str(entry.get(f, ""))]
    if problems:
        raise LabellingError(problems)
    return man


def consensus_row(row: dict, ga, gb) -> dict:
    """AI consensus for an item both labellers answered alike (label, subtype, hedged)."""
    others = sorted((set(ga.other_subtypes) | set(gb.other_subtypes)) - {ga.subtype})
    note = ga.note if ga.note == gb.note else "; ".join(n for n in (ga.note, gb.note) if n)
    return {**row, "label": ga.label, "subtype": ga.subtype or "",
            "hedged": "" if ga.hedged is None else ("yes" if ga.hedged else "no"),
            "other_subtypes": ",".join(others), "note": note, "unsure": "yes" if ga.unsure or gb.unsure else ""}


def ai_finalize(annotation_dir: Path, corpus_id: str, a_name: str, b_name: str, author: str, corpus_dir: Path,
                *, results_dir: Path | None = None, adjudicated: Path | None = None, seed: int = SEED) -> dict:
    out = ai_dir(annotation_dir, corpus_id)
    man = check_manifest(out, [a_name, b_name])
    results = Path(results_dir if results_dir is not None else CO.RESULTS_DIR) / corpus_id
    if not (results / "MANIFEST.json").exists():
        raise FileNotFoundError(f"run `python -m hallucination_pipeline.cli analyze_corpus` first ({results})")
    if (results / "audit_ai").exists() or (out / "final_labels.csv").exists():
        raise LabellingError(["final labels / audit_ai results already exist; they are never overwritten"])
    hidden = json.loads((out / "hidden" / "adjudication_key.json").read_text(encoding="utf-8"))
    key = _read_key(annotation_dir, corpus_id)
    adj_items = {i: key["sheets"]["primary"]["items"][i] for i in hidden["items"]}
    adj_key = {"sheets": {"adjudication": {"items": adj_items}}}
    adjudicated = Path(adjudicated) if adjudicated else out / "adjudication_filled.csv"
    if not adjudicated.exists():
        raise FileNotFoundError(f"{adjudicated} not found: save your filled adjudication sheet there")
    try:
        author_labels = AN.import_sheet(adjudicated, adj_key, "adjudication", author)["labels"]
    except AN.AnnotationImportError as e:
        raise LabellingError(e.problems)
    mine = {g.item_id: g for g in author_labels}
    ka = {g.item_id: g for g in _load_labels(out, a_name)}
    kb = {g.item_id: g for g in _load_labels(out, b_name)}
    sheet = _read_sheet(annotation_dir, corpus_id)

    spot = [i for i, kind in hidden["items"].items() if kind == "spot_check"]
    dis = [i for i, kind in hidden["items"].items() if kind == "disagreement"]
    same = lambda g, h: (g.label, g.subtype) == (h.label, h.subtype)
    overruled = [i for i in spot if not same(mine[i], ka[i])]
    rate = len(overruled) / len(spot) if spot else None
    sided = {"with_" + a_name: sum(same(mine[i], ka[i]) and not same(mine[i], kb[i]) for i in dis),
             "with_" + b_name: sum(same(mine[i], kb[i]) and not same(mine[i], ka[i]) for i in dis),
             "with_both (they differed only in hedged)": sum(same(mine[i], ka[i]) and same(mine[i], kb[i]) for i in dis),
             "with_neither": sum(not same(mine[i], ka[i]) and not same(mine[i], kb[i]) for i in dis)}
    model = lambda n: f"{n}: {man['labellers'][n]['model_name']} {man['labellers'][n]['model_version']}"
    statement = (f"labels: two AI annotators ({model(a_name)}; {model(b_name)}), author-adjudicated; "
                 f"{len(dis)} disagreements; 20% blind spot-check ({len(spot)} items); overrule rate "
                 + (f"{rate:.0%} ({len(overruled)}/{len(spot)})" if rate is not None else "n/a (no spot-check items)"))

    rows = []
    for r in sheet:
        i = r["item_id"]
        if i in mine:
            g = mine[i]
            rows.append({**r, "label": g.label, "subtype": g.subtype or "",
                         "hedged": "" if g.hedged is None else ("yes" if g.hedged else "no"),
                         "other_subtypes": ",".join(g.other_subtypes), "note": g.note, "unsure": "yes" if g.unsure else ""})
        else:
            rows.append(consensus_row(r, ka[i], kb[i]))
    _write_sheet_csv(out / "final_labels.csv", rows, comments=[CO.SOURCE, statement])
    final = AN.import_sheet(out / "final_labels.csv", key, "primary", f"AI({a_name},{b_name})+{author}")["labels"]

    result = AU.audit_metrics(final, CO.load_corpus(corpus_dir), seed=seed)
    result.update({"labels": statement, "design": "D30 audit: two AI annotators, author-adjudicated; " + result["design"]})
    dest = results / "audit_ai"
    dest.mkdir(parents=True)
    for name, data in (("audit_metrics.csv", result["metrics"]), ("audit_disagreements.csv", result["disagreements"])):
        _write_table(dest / name, data, [CO.SOURCE, statement])
    summary = {"labels": statement, "source": CO.SOURCE, "labellers": {n: man["labellers"][n] for n in (a_name, b_name)},
               "author": author, "items": len(rows), "adjudicated": len(mine), "disagreements": len(dis),
               "spot_check": len(spot), "spot_check_overruled": len(overruled), "overrule_rate": rate,
               "overruled_items": sorted(overruled), "disagreements_resolved": sided}
    (dest / "audit.json").write_text(json.dumps({**result, "labelling": summary}, indent=2, ensure_ascii=False) + "\n",
                                     encoding="utf-8", newline="\n")
    (out / "final_summary.json").write_text(json.dumps(summary, indent=2, ensure_ascii=False) + "\n",
                                            encoding="utf-8", newline="\n")
    return {"summary": summary, "result": result, "dest": dest}


def _write_table(path: Path, rows: list[dict], comments: list[str]) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        for c in comments:
            f.write(f"# {c}\n")
        if rows:
            w = csv.DictWriter(f, fieldnames=list(rows[0]), lineterminator="\n")
            w.writeheader()
            w.writerows({k: json.dumps(v) if isinstance(v, (list, dict)) else v for k, v in r.items()} for r in rows)


# ── command line ──────────────────────────────────────────────────────────

def main(argv=None) -> int:
    from hallucination_pipeline.run_config import DEFAULT_CONFIG_PATH, load_run_config
    ap = argparse.ArgumentParser(prog="ai_labelling")
    ap.add_argument("command", choices=["ai_export", "ai_import", "ai_compare", "ai_finalize"])
    ap.add_argument("--labeller")
    ap.add_argument("--labellers", nargs=2)
    ap.add_argument("--author")
    ap.add_argument("--adjudicated", help="your filled adjudication sheet (default ai/adjudication_filled.csv)")
    ap.add_argument("--corpus-dir", default=str(REPO_ROOT / "old_run"))
    ap.add_argument("--config", default=str(DEFAULT_CONFIG_PATH))
    ap.add_argument("--results-dir", default=None)
    args = ap.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass
    ann = load_run_config(args.config).annotation_dir
    cid = CO.corpus_fingerprint(Path(args.corpus_dir))["corpus_id"]
    try:
        if args.command == "ai_export":
            out = ai_export(ann, cid)
            n = len(list((out / "chunks").glob("chunk_*.txt")))
            print(f"Wrote {n} chunk files to {out / 'chunks'} and a labelling_manifest.json to fill in.")
        elif args.command == "ai_import":
            if not args.labeller:
                ap.error("ai_import needs --labeller NAME")
            r = ai_import(ann, cid, args.labeller)
            print(f"{args.labeller}: {r['items']} items read and valid from {len(r['files'])} file(s); "
                  f"{r['ignored_lines']} other line(s) ignored. Wrote labels_{args.labeller}.csv")
            print(f"  format repairs (D32): {r['repairs']['collapsed_lines_split']} collapsed line(s) split into "
                  f"{r['repairs']['records_recovered_from_split_lines']} records; "
                  f"{r['repairs']['multi_subtype_fields_repaired']} multi-subtype field(s) repaired. "
                  "Counts saved in labelling_manifest.json.")
        elif args.command == "ai_compare":
            if not args.labellers:
                ap.error("ai_compare needs --labellers NAME_A NAME_B")
            r = ai_compare(ann, cid, *args.labellers)
            k = lambda v: "undefined" if v is None else f"{v:.2f}"
            print(f"{r['items']} items: {r['disagreements']} disagreements, {r['agreements']} agreements "
                  f"(kappa label {k(r['kappa_label'])}, tier {k(r['kappa_tier'])}).")
            print(f"Your blind adjudication sheet has {r['to_adjudicate']} items "
                  f"({r['disagreements']} disagreements + {r['spot_check']} spot-checks, shuffled): "
                  f"{ai_dir(ann, cid) / 'adjudication.csv'}")
            print("Do NOT open the hidden/ folder or the labels_*.csv files until you have finished adjudicating.")
        else:
            if not args.labellers or not args.author:
                ap.error("ai_finalize needs --labellers NAME_A NAME_B --author INITIALS")
            r = ai_finalize(ann, cid, *args.labellers, args.author, Path(args.corpus_dir),
                            results_dir=args.results_dir, adjudicated=args.adjudicated)
            print(r["summary"]["labels"])
            print(f"Disagreements resolved: {r['summary']['disagreements_resolved']}")
            print(AU.format_audit(r["result"]))
            print(f"\nWrote {ai_dir(ann, cid) / 'final_labels.csv'} and {r['dest']}")
    except (LabellingError, FileNotFoundError) as e:
        print(f"\nERROR: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

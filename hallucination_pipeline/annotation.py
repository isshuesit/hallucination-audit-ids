"""
M3: annotation tooling - sample, blind export, import with validation (D23), agreement.

Audit lesson 3: gold labels must be human, blind and measured. So:
  * the sheets contain only evidence, the sentence and its explanation - no pipeline field, no
    class, no alert id (alert ids are assigned in class order and would leak the class); items get
    shuffled, opaque ids, and the mapping back lives in key.json, which the annotator never opens;
  * every sentence of every sampled explanation is on the sheet, whatever the pipeline flagged
    (unconditional recall, D5);
  * import rejects anything outside D23 and lists every problem at once;
  * agreement is Cohen's kappa with a cluster-bootstrap CI (explanations resampled, D7).

Sheets (D5, D6): `primary` (100 explanations), `reliability` (25 of them, for a second annotator,
same item ids) and `retest` (25 of them, for the primary annotator >= 7 days later; fresh ids and a
new order so answers cannot be looked up).
"""

from __future__ import annotations

import csv
import html
import io
import json
import random
import subprocess
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path

from .detection import split_sentences
from .policy import SUBTYPES, TIER1, TIER2, is_catch_all

ANNOTATION_COLUMNS = ("label", "subtype", "hedged", "other_subtypes", "note", "unsure")
SHEET_COLUMNS = ("item_id", "explanation_id", "sentence_no", "evidence", "sentence", "explanation") + ANNOTATION_COLUMNS
LABEL_SUBTYPES = tuple(k for k, v in SUBTYPES.items() if v.label)   # soft_certainty is rule-internal
SHEETS = ("primary", "reliability", "retest")


class AnnotationExportError(RuntimeError):
    pass


class AnnotationImportError(ValueError):
    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__(f"{len(problems)} problem(s) in the annotation file:\n  " + "\n  ".join(problems))


# ── sampling ──────────────────────────────────────────────────────────────

def _allocate(available: dict[str, int], n: int, rng: random.Random) -> dict[str, int]:
    """Spread n over classes as evenly as possible (floor(n/k) each, the remainder to classes in a
    seeded random order), never above what a class has; a shortfall goes to classes with room."""
    classes = sorted(available)
    order = classes[:]
    rng.shuffle(order)
    alloc = {c: 0 for c in classes}
    remaining = min(n, sum(available.values()))
    while remaining:
        open_ = [c for c in order if alloc[c] < available[c]]
        share = max(1, remaining // len(open_))
        for c in open_:
            take = min(share, available[c] - alloc[c], remaining)
            alloc[c] += take
            remaining -= take
            if not remaining:
                break
    return alloc


def _stratified(ids_by_class: dict[str, list[str]], n: int, rng: random.Random) -> list[str]:
    alloc = _allocate({c: len(v) for c, v in ids_by_class.items()}, n, rng)
    picked = []
    for c in sorted(ids_by_class):
        picked += rng.sample(sorted(ids_by_class[c]), alloc[c])
    return sorted(picked)


def sample_explanations(explanations: list[dict], alerts: list[dict], *, seed: int, n: int = 100,
                        n_reliability: int = 25, n_retest: int = 25) -> dict:
    """Stratified by fine class: `n` explanations, and the reliability / retest subsets drawn
    from them (each also stratified, each with its own seeded stream, so they may overlap).
    Only successfully generated explanations of the attack arm are eligible."""
    cls = {a["alert_id"]: a.get("label_fine", a.get("alert_type")) for a in alerts}
    eligible = [e["alert_id"] for e in explanations
                if e.get("status", "ok") == "ok" and e.get("arm", "attack") == "attack" and e.get("explanation")]
    by_class = defaultdict(list)
    for aid in eligible:
        by_class[cls[aid]].append(aid)
    primary = _stratified(by_class, n, random.Random(f"{seed}:primary"))
    in_primary = defaultdict(list)
    for aid in primary:
        in_primary[cls[aid]].append(aid)
    subsets = {name: _stratified(in_primary, k, random.Random(f"{seed}:{name}"))
               for name, k in (("reliability", n_reliability), ("retest", n_retest))}
    return {
        "seed": seed,
        "primary": primary, **subsets,
        "per_class": {name: dict(sorted(Counter(cls[a] for a in ids).items()))
                      for name, ids in (("primary", primary), *subsets.items())},
        "eligible_per_class": dict(sorted((c, len(v)) for c, v in by_class.items())),
    }


# ── blind export ──────────────────────────────────────────────────────────

def _sheet_rows(alert_ids: list[str], prefix: str, rng: random.Random, expl: dict, evid: dict) -> tuple[list, dict]:
    order = alert_ids[:]
    rng.shuffle(order)
    rows, items = [], {}
    for i, aid in enumerate(order, start=1):
        eid = f"{prefix}{i:03d}"
        for j, sentence in enumerate(split_sentences(expl[aid]), start=1):
            item_id = f"{eid}-{j:02d}"
            rows.append({"item_id": item_id, "explanation_id": eid, "sentence_no": j, "evidence": evid[aid],
                         "sentence": sentence, "explanation": expl[aid], **{c: "" for c in ANNOTATION_COLUMNS}})
            # sentence_id matches the pipeline's Phase 3 ids (S1, S2, ... over split_sentences)
            items[item_id] = {"alert_id": aid, "sentence_id": f"S{j}", "explanation_id": eid}
    return rows, items


def _write_csv(path: Path, rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=SHEET_COLUMNS)
        w.writeheader()
        w.writerows(rows)


def _write_html(path: Path, rows: list[dict], title: str) -> None:
    """A read-only view of the sheet: evidence beside each sentence, explanation for context."""
    out = [f"<!doctype html><meta charset='utf-8'><title>{html.escape(title)}</title>",
           "<style>body{font-family:sans-serif;max-width:60em;margin:1em auto;padding:0 1em}"
           "section{border-top:2px solid #888;margin-top:2em}pre{background:#f3f3f3;padding:.5em}"
           "td{vertical-align:top;padding:.3em .6em;border-bottom:1px solid #ddd}</style>",
           f"<h1>{html.escape(title)}</h1><p>Read-only view. Enter labels in the CSV file of the same name.</p>"]
    by_expl = defaultdict(list)
    for r in rows:
        by_expl[r["explanation_id"]].append(r)
    for eid, rs in by_expl.items():
        out.append(f"<section><h2>{html.escape(eid)}</h2><h3>Evidence</h3><pre>{html.escape(rs[0]['evidence'])}</pre>"
                   f"<h3>Explanation</h3><p>{html.escape(rs[0]['explanation'])}</p><table>")
        out += [f"<tr><td>{html.escape(r['item_id'])}</td><td>{html.escape(r['sentence'])}</td></tr>" for r in rs]
        out.append("</table></section>")
    path.write_text("\n".join(out) + "\n", encoding="utf-8", newline="\n")


def freeze_tag_ok(repo: Path, tag: str = "freeze-1") -> tuple[bool, str]:
    """True if `tag` exists, is an ancestor of HEAD, and no tracked file has uncommitted changes
    (untracked outputs such as results/ or annotation/ do not count)."""
    def git(*args):
        return subprocess.run(["git", *args], cwd=repo, capture_output=True, text=True)
    if git("rev-parse", "-q", "--verify", f"refs/tags/{tag}").returncode != 0:
        return False, f"git tag {tag} does not exist yet (D8: freeze before exporting real sheets)"
    if git("merge-base", "--is-ancestor", tag, "HEAD").returncode != 0:
        return False, f"HEAD does not contain {tag}"
    if git("status", "--porcelain", "--untracked-files=no").stdout.strip():
        return False, "tracked files have uncommitted changes"
    return True, "ok"


README_TEXT = """Annotation package for run {run_id}

GIVE TO THE ANNOTATOR (one sheet at a time):
{sheet_lines}
  docs/ANNOTATION_GUIDE_v2.md                          how to label

NEVER GIVE TO THE ANNOTATOR, and do not open it yourself while labelling:
  key.json      maps item ids back to alerts and classes

Fill in only: label, subtype, hedged, other_subtypes, note, unsure. Save as "CSV UTF-8".
Do not reorder, add or delete rows.
"""


def export_annotation(explanations: list[dict], alerts: list[dict], out_dir: Path, *, run_id: str, seed: int,
                      n: int = 100, n_reliability: int = 25, n_retest: int = 25, unfrozen_ok: bool = False,
                      repo: Path | None = None, sample: dict | None = None) -> Path:
    """Write sheets/{primary,reliability,retest}.csv + .html, key.json and README.txt into out_dir.

    Refuses to overwrite an existing export (labels must never be re-sampled after the fact), and,
    unless unfrozen_ok, refuses to run before `git tag freeze-1` (D8). `sample` replaces the default
    sampler ({"seed", "primary": [...], "reliability": [...], "retest": [...]}); a sheet whose list is
    empty is not written (e.g. the D28 audit has a primary sheet only)."""
    out_dir = Path(out_dir)
    if out_dir.exists():
        raise AnnotationExportError(f"{out_dir} already exists; an export is never overwritten")
    if not unfrozen_ok:
        ok, why = freeze_tag_ok(repo or Path(__file__).resolve().parent.parent)
        if not ok:
            raise AnnotationExportError(f"Refusing to export real annotation sheets: {why}")
    if sample is None:
        sample = sample_explanations(explanations, alerts, seed=seed, n=n, n_reliability=n_reliability,
                                     n_retest=n_retest)
    expl = {e["alert_id"]: e["explanation"] for e in explanations}
    evid = {a["alert_id"]: a["evidence"] for a in alerts}
    cls = {a["alert_id"]: a.get("label_fine", a.get("alert_type")) for a in alerts}

    (out_dir / "sheets").mkdir(parents=True)
    key = {"run_id": run_id, "seed": seed, "unfrozen_export": unfrozen_ok, "sample": sample, "sheets": {}}
    primary_rows, primary_items = _sheet_rows(sample["primary"], "E", random.Random(f"{seed}:order:primary"),
                                              expl, evid)
    sheets = {"primary": (primary_rows, primary_items)}
    rel_ids = {it["explanation_id"] for it in primary_items.values() if it["alert_id"] in set(sample["reliability"])}
    sheets["reliability"] = ([r for r in primary_rows if r["explanation_id"] in rel_ids],   # same ids, 2nd person
                             {k: v for k, v in primary_items.items() if v["explanation_id"] in rel_ids})
    sheets["retest"] = _sheet_rows(sample["retest"], "T", random.Random(f"{seed}:order:retest"), expl, evid)
    for name, (rows, items) in sheets.items():
        if not rows:
            continue
        _write_csv(out_dir / "sheets" / f"{name}.csv", rows)
        _write_html(out_dir / "sheets" / f"{name}.html", rows, f"Annotation sheet: {name}")
        key["sheets"][name] = {"items": items, "n_explanations": len({r["explanation_id"] for r in rows}),
                               "n_sentences": len(rows)}
    key["classes"] = {aid: cls[aid] for aid in sorted(set(sample["primary"]))}
    (out_dir / "key.json").write_text(json.dumps(key, indent=2, ensure_ascii=False) + "\n", encoding="utf-8",
                                      newline="\n")
    what = {"primary": "first pass", "retest": "primary annotator again, at least 7 days after finishing primary",
            "reliability": "a second annotator, if available (D6)"}
    sheet_lines = "\n".join(f"  sheets/{name}.csv + sheets/{name}.html   {what[name]}, "
                            f"{key['sheets'][name]['n_explanations']} explanations"
                            for name in ("primary", "retest", "reliability") if name in key["sheets"])
    (out_dir / "README.txt").write_text(README_TEXT.format(run_id=run_id, sheet_lines=sheet_lines),
                                        encoding="utf-8", newline="\n")
    return out_dir


# ── import with D23 validation ────────────────────────────────────────────

@dataclass(frozen=True)
class GoldLabel:
    item_id: str
    alert_id: str
    sentence_id: str
    explanation_id: str
    label: str                    # grounded | hallucinated
    subtype: str | None
    tier: int | None              # derived from the subtype, never typed (D23)
    hedged: bool | None
    other_subtypes: tuple[str, ...]
    note: str
    unsure: bool
    annotator: str
    sheet: str

    @property
    def strict(self) -> bool:
        return self.label == "hallucinated"

    @property
    def lenient(self) -> bool:
        """Hallucinated under the lenient policy: any Tier 1 subtype, primary or other."""
        return self.label == "hallucinated" and any(
            SUBTYPES[s].tier == TIER1 for s in (self.subtype, *self.other_subtypes) if s)


def _read_text(path: Path) -> str:
    raw = Path(path).read_bytes()
    try:
        return raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        return raw.decode("cp1252")      # Excel "CSV" (not "CSV UTF-8")


def import_sheet(path: Path, key: dict, sheet: str, annotator: str) -> dict:
    """Validate a filled sheet against D23 and the key. Returns {"labels": [GoldLabel], "file_notes": [...]}.
    Raises AnnotationImportError listing every problem (with CSV line numbers).
    Lines starting with '#' before the header are kept as file notes (the guide asks annotators to note
    any integrity incident at the top of the file)."""
    if sheet not in key["sheets"]:
        raise AnnotationImportError([f"unknown sheet {sheet!r}; expected one of {sorted(key['sheets'])}"])
    lines = _read_text(path).splitlines(keepends=True)
    notes, start = [], 0
    while start < len(lines) and lines[start].lstrip().startswith("#"):
        notes.append(lines[start].strip().lstrip("#").strip())
        start += 1
    reader = csv.DictReader(io.StringIO("".join(lines[start:])))
    missing_cols = [c for c in ("item_id", *ANNOTATION_COLUMNS) if c not in (reader.fieldnames or [])]
    if missing_cols:
        raise AnnotationImportError([f"missing column(s): {', '.join(missing_cols)}"])

    items = key["sheets"][sheet]["items"]
    problems, labels, seen = [], [], set()
    for line_no, row in enumerate(reader, start=start + 2):
        get = lambda c: (row.get(c) or "").strip()
        item = get("item_id")
        where = f"line {line_no} ({item or 'no item_id'})"
        if item not in items:
            problems.append(f"{where}: item_id not in this sheet")
            continue
        if item in seen:
            problems.append(f"{where}: duplicate row for this item")
            continue
        seen.add(item)
        label, subtype, hedged = get("label").lower(), get("subtype"), get("hedged").lower()
        others = tuple(s.strip() for s in get("other_subtypes").split(",") if s.strip())
        note, unsure = get("note"), get("unsure").lower()
        errs = []
        if not label:
            errs.append("label is blank")
        elif label not in ("grounded", "hallucinated"):
            errs.append(f"label {get('label')!r} must be grounded or hallucinated")
        for s in (subtype, *others):
            if s and s not in LABEL_SUBTYPES:
                errs.append(f"unknown subtype {s!r} (see docs/SUBTYPES.md)")
        if label == "hallucinated":
            if not subtype:
                errs.append("hallucinated without a subtype")
            if hedged not in ("yes", "no"):
                errs.append(f"hedged must be yes or no for a hallucinated sentence, not {get('hedged')!r}")
            if subtype and subtype in others:
                errs.append("other_subtypes repeats the subtype")
        elif label == "grounded":
            if subtype:
                errs.append("grounded with a subtype")
            if hedged:
                errs.append("hedged must be empty when grounded")
            if others:
                errs.append("other_subtypes must be empty when grounded")
        if any(is_catch_all(s) for s in (subtype, *others)) and not note:
            errs.append("other_fabrication / other_knowledge need a note")
        if unsure not in ("", "yes"):
            errs.append(f"unsure must be yes or empty, not {get('unsure')!r}")
        if errs:
            problems += [f"{where}: {e}" for e in errs]
            continue
        k = items[item]
        labels.append(GoldLabel(
            item_id=item, alert_id=k["alert_id"], sentence_id=k["sentence_id"], explanation_id=k["explanation_id"],
            label=label, subtype=subtype or None, tier=SUBTYPES[subtype].tier if subtype else None,
            hedged=(hedged == "yes") if label == "hallucinated" else None, other_subtypes=others, note=note,
            unsure=unsure == "yes", annotator=annotator, sheet=sheet))
    for item in sorted(set(items) - seen):
        problems.append(f"{item}: row missing (every sentence must be labelled)")
    if problems:
        raise AnnotationImportError(problems)
    return {"labels": labels, "file_notes": notes}


def labels_from_json(rows: list[dict]) -> list[GoldLabel]:
    fields = GoldLabel.__dataclass_fields__
    return [GoldLabel(**{k: (tuple(v) if k == "other_subtypes" else v) for k, v in r.items() if k in fields})
            for r in rows]


def labels_to_json(labels: list[GoldLabel]) -> list[dict]:
    return [{**asdict(g), "other_subtypes": list(g.other_subtypes), "gold_strict": g.strict,
             "gold_lenient": g.lenient} for g in labels]


# ── agreement ─────────────────────────────────────────────────────────────

def cohen_kappa(a: list, b: list) -> float | None:
    """Cohen's kappa for two equally long label lists. None when undefined (chance agreement = 1,
    e.g. both annotators used a single category)."""
    if len(a) != len(b) or not a:
        raise ValueError("need two non-empty lists of equal length")
    n = len(a)
    po = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    pe = sum(ca[c] * cb[c] for c in set(ca) | set(cb)) / (n * n)
    return None if pe == 1 else (po - pe) / (1 - pe)


def _views(g: GoldLabel) -> dict:
    return {
        "label": g.label,
        "lenient": g.lenient,
        "tier": g.tier or 0,                       # 0 = grounded, 1, 2: Tier 1 versus Tier 2
        "tier1": g.tier == TIER1,
        "tier2": g.tier == TIER2,
    }


def restrict_to(labels: list[GoldLabel], other: list[GoldLabel]) -> list[GoldLabel]:
    """The labels in `labels` for the sentences `other` covers (e.g. primary pass -> retest subset)."""
    keep = {(g.alert_id, g.sentence_id) for g in other}
    return [g for g in labels if (g.alert_id, g.sentence_id) in keep]


def agreement(a: list[GoldLabel], b: list[GoldLabel], *, seed: int = 0, n_boot: int = 2000) -> dict:
    """Kappa between two annotation passes over the same sentences: overall (label), lenient,
    tier (grounded / Tier 1 / Tier 2), Tier 1 and Tier 2 each as present/absent, and per subtype
    (primary subtype is X or not). 95% CI by cluster bootstrap over explanations (D7)."""
    ka = {(g.alert_id, g.sentence_id): g for g in a}
    kb = {(g.alert_id, g.sentence_id): g for g in b}
    if set(ka) != set(kb):
        only_a, only_b = sorted(set(ka) - set(kb)), sorted(set(kb) - set(ka))
        raise ValueError(f"the passes cover different sentences: {len(only_a)} only in A, {len(only_b)} only in B")
    keys = sorted(ka)
    clusters = defaultdict(list)
    for k in keys:
        clusters[k[0]].append(k)
    cluster_ids = sorted(clusters)

    va, vb = {k: _views(ka[k]) for k in keys}, {k: _views(kb[k]) for k in keys}
    subtypes = sorted({g.subtype for g in (*a, *b) if g.subtype})
    metrics = {name: (lambda k, name=name, v=va: v[k][name], lambda k, name=name, v=vb: v[k][name])
               for name in ("label", "lenient", "tier", "tier1", "tier2")}
    for s in subtypes:
        metrics[f"subtype:{s}"] = (lambda k, s=s: ka[k].subtype == s, lambda k, s=s: kb[k].subtype == s)

    rng = random.Random(f"{seed}:kappa-bootstrap")
    draws = [[k for c in (rng.choice(cluster_ids) for _ in cluster_ids) for k in clusters[c]] for _ in range(n_boot)]
    out = {"n_sentences": len(keys), "n_explanations": len(cluster_ids), "bootstrap": {"draws": n_boot, "seed": seed,
                                                                                        "unit": "explanation"},
           "kappa": {}}
    for name, (fa, fb) in metrics.items():
        xa, xb = [fa(k) for k in keys], [fb(k) for k in keys]
        kappa = cohen_kappa(xa, xb)
        boot = sorted(v for v in (cohen_kappa([fa(k) for k in d], [fb(k) for k in d]) for d in draws) if v is not None)
        ci = [boot[int(0.025 * (len(boot) - 1))], boot[int(0.975 * (len(boot) - 1))]] if boot else None
        entry = {"kappa": kappa, "ci95": ci, "valid_draws": len(boot),
                 "observed_agreement": sum(x == y for x, y in zip(xa, xb)) / len(keys)}
        if name.startswith("subtype:") or name in ("tier1", "tier2", "lenient"):
            entry["positives"] = [sum(map(bool, xa)), sum(map(bool, xb))]
        out["kappa"][name] = entry
    out["catch_all_counts"] = {"a": sum(is_catch_all(g.subtype) for g in a),
                               "b": sum(is_catch_all(g.subtype) for g in b)}      # D21: reported separately
    out["unsure_counts"] = {"a": sum(g.unsure for g in a), "b": sum(g.unsure for g in b)}
    return out


def disagreements(a: list[GoldLabel], b: list[GoldLabel], sentences: dict | None = None) -> list[dict]:
    """Sentences where label or subtype differ, as rows for an adjudication sheet (adjudicated_*
    columns left empty). `sentences` optionally maps (alert_id, sentence_id) -> sentence text."""
    kb = {(g.alert_id, g.sentence_id): g for g in b}
    rows = []
    for g in sorted(a, key=lambda g: (g.alert_id, g.sentence_id)):
        h = kb[(g.alert_id, g.sentence_id)]
        if (g.label, g.subtype) != (h.label, h.subtype):
            rows.append({"alert_id": g.alert_id, "sentence_id": g.sentence_id,
                         "sentence": (sentences or {}).get((g.alert_id, g.sentence_id), ""),
                         "a_annotator": g.annotator, "a_label": g.label, "a_subtype": g.subtype or "",
                         "a_note": g.note, "b_annotator": h.annotator, "b_label": h.label,
                         "b_subtype": h.subtype or "", "b_note": h.note,
                         "adjudicated_label": "", "adjudicated_subtype": "", "adjudication_note": ""})
    return rows


def write_disagreements(path: Path, rows: list[dict]) -> None:
    cols = ["alert_id", "sentence_id", "sentence", "a_annotator", "a_label", "a_subtype", "a_note", "b_annotator",
            "b_label", "b_subtype", "b_note", "adjudicated_label", "adjudicated_subtype", "adjudication_note"]
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)

"""M3: annotation sampling, blind export, D23 import validation, agreement (synthetic data only)."""

import csv
import json
import os
import random
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import fakes
from hallucination_pipeline import annotation as AN
from hallucination_pipeline.detection import split_sentences

# 14 classes like the real sample: 12 x 30, one with 20, one with 11 (D2)
CLASSES = {f"SentinelClass{i:02d}": 30 for i in range(12)} | {"SentinelClassSmall20": 20, "SentinelClassTiny11": 11}
PIPELINE_SENTINELS = ["SENTINEL_REASON", "SENTINEL_TYPE", "SENTINEL_METHOD", "SENTINEL_TIER", "SENTINEL_RULE",
                      "SentinelClass", "SENTINEL_COARSE"]


def synthetic_run(seed=1):
    """Alerts + explanations shaped like a run's files, with every pipeline field set to a sentinel."""
    rng = random.Random(seed)
    alerts, explanations, i = [], [], 0
    for cls, n in CLASSES.items():
        for _ in range(n):
            i += 1
            aid = f"A{i:04d}"
            port = rng.choice([22, 80, 443])
            evidence = f"Destination Port: {port}\nFlow Duration: {rng.randint(1, 10**7)}\nForward Packets: 4"
            alerts.append({"alert_id": aid, "arm": "attack", "alert_type": cls, "label_fine": cls,
                           "label_coarse": "SENTINEL_COARSE", "evidence": evidence, "evidence_tokens": [str(port)]})
            sents = [rng.choice(fakes._CLEAN).format(fwd=4, bwd=1, port=port, syn=2, dur=5, rate=1.5)
                     for _ in range(rng.randint(3, 6))] + rng.sample(fakes._BAD, rng.randint(0, 2))
            explanations.append({
                "alert_id": aid, "arm": "attack", "alert_type": cls, "status": "ok", "explanation": " ".join(sents),
                "reason": "SENTINEL_REASON", "hallucination_type": "SENTINEL_TYPE", "detection_method": "SENTINEL_METHOD",
                "tier": "SENTINEL_TIER", "rule_hits": [{"rule": "SENTINEL_RULE"}], "predicted_label": "hallucinated"})
    explanations[0] = {**explanations[0], "status": "failed", "explanation": None}     # never sampled
    return alerts, explanations


@pytest.fixture
def export(tmp_path):
    alerts, explanations = synthetic_run()
    out = AN.export_annotation(explanations, alerts, tmp_path / "annotation", run_id="test-run", seed=42,
                               unfrozen_ok=True)
    key = json.loads((out / "key.json").read_text(encoding="utf-8"))
    return out, key, alerts, explanations


def read_sheet(path):
    with open(path, encoding="utf-8-sig", newline="") as f:
        return list(csv.DictReader(f))


def write_sheet(path, rows, notes=(), encoding="utf-8-sig"):
    with open(path, "w", encoding=encoding, newline="") as f:
        for n in notes:
            f.write(f"# {n}\n")
        w = csv.DictWriter(f, fieldnames=AN.SHEET_COLUMNS)
        w.writeheader()
        w.writerows(rows)


def fill(rows, rule):
    """Fill every row with rule(row) -> dict of annotation columns."""
    return [{**r, **{c: "" for c in AN.ANNOTATION_COLUMNS}, **rule(r)} for r in rows]


GROUNDED = lambda r: {"label": "grounded"}


# ── sampling ──────────────────────────────────────────────────────────────

def test_sample_is_stratified_by_class_and_deterministic():
    alerts, explanations = synthetic_run()
    s = AN.sample_explanations(explanations, alerts, seed=42)
    assert len(s["primary"]) == 100 and len(set(s["primary"])) == 100
    counts = s["per_class"]["primary"]
    assert len(counts) == 14 and set(counts.values()) <= {7, 8} and sum(counts.values()) == 100
    assert s == AN.sample_explanations(explanations, alerts, seed=42)
    assert s["primary"] != AN.sample_explanations(explanations, alerts, seed=7)["primary"]
    assert "A0001" not in s["primary"]                                   # failed generation is never sampled
    for name in ("reliability", "retest"):
        assert len(s[name]) == 25 and set(s[name]) <= set(s["primary"])
        assert max(s["per_class"][name].values()) <= 2                   # spread over classes


def test_allocation_moves_a_shortfall_to_classes_with_room():
    alloc = AN._allocate({"a": 2, "b": 50, "c": 50}, 30, random.Random(0))
    assert alloc["a"] == 2 and alloc["b"] + alloc["c"] == 28 and abs(alloc["b"] - alloc["c"]) <= 1
    assert sum(AN._allocate({"a": 3, "b": 4}, 100, random.Random(0)).values()) == 7


# ── blind export ──────────────────────────────────────────────────────────

def test_export_contains_every_sentence_of_every_sampled_explanation(export):
    out, key, alerts, explanations = export
    expl = {e["alert_id"]: e["explanation"] for e in explanations}
    rows = read_sheet(out / "sheets" / "primary.csv")
    assert tuple(rows[0]) == AN.SHEET_COLUMNS
    assert len(rows) == sum(len(split_sentences(expl[a])) for a in key["sample"]["primary"])
    assert all(r[c] == "" for r in rows for c in AN.ANNOTATION_COLUMNS)
    for r in rows:                                      # the key maps each row back to its sentence
        k = key["sheets"]["primary"]["items"][r["item_id"]]
        assert split_sentences(expl[k["alert_id"]])[int(k["sentence_id"][1:]) - 1] == r["sentence"]


def test_export_is_blind(export):
    """No pipeline field, class name or alert id reaches anything the annotator receives."""
    out, key, alerts, _ = export
    alert_ids = {a["alert_id"] for a in alerts}
    for path in [*(out / "sheets").iterdir(), out / "README.txt"]:
        text = path.read_text(encoding="utf-8-sig")
        for sentinel in PIPELINE_SENTINELS:
            assert sentinel not in text, f"{sentinel} leaked into {path.name}"
        assert not {w for w in text.replace(",", " ").replace("<", " ").replace(">", " ").split()} & alert_ids
    for name in ("primary", "reliability", "retest"):
        assert set(read_sheet(out / "sheets" / f"{name}.csv")[0]) == set(AN.SHEET_COLUMNS)


def test_explanation_order_does_not_follow_class_order(export):
    out, key, _, _ = export
    items = key["sheets"]["primary"]["items"]
    first_alert_per_expl = {}
    for it in items.values():
        first_alert_per_expl.setdefault(it["explanation_id"], it["alert_id"])
    in_sheet_order = [first_alert_per_expl[e] for e in sorted(first_alert_per_expl)]
    assert in_sheet_order != sorted(in_sheet_order)


def test_reliability_and_retest_sheets(export):
    out, key, _, _ = export
    primary = {r["item_id"]: r for r in read_sheet(out / "sheets" / "primary.csv")}
    rel = read_sheet(out / "sheets" / "reliability.csv")
    assert {r["item_id"] for r in rel} <= set(primary)                    # same ids for the second annotator
    assert key["sheets"]["reliability"]["n_explanations"] == 25
    retest = read_sheet(out / "sheets" / "retest.csv")
    assert all(r["item_id"].startswith("T") for r in retest)              # fresh ids: no lookup of old answers
    assert key["sheets"]["retest"]["n_explanations"] == 25
    retest_alerts = {it["alert_id"] for it in key["sheets"]["retest"]["items"].values()}
    assert retest_alerts == set(key["sample"]["retest"])


def test_export_never_overwrites(export, tmp_path):
    out, _, alerts, explanations = export
    with pytest.raises(AN.AnnotationExportError, match="never overwritten"):
        AN.export_annotation(explanations, alerts, out, run_id="x", seed=42, unfrozen_ok=True)


def test_real_export_requires_freeze_1(tmp_path):
    alerts, explanations = synthetic_run()
    repo = tmp_path / "repo"
    repo.mkdir()
    git = lambda *a: subprocess.run(["git", *a], cwd=repo, capture_output=True, text=True, check=True)
    git("init", "-q")
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "x")
    with pytest.raises(AN.AnnotationExportError, match="freeze-1 does not exist"):
        AN.export_annotation(explanations, alerts, tmp_path / "a1", run_id="x", seed=1, repo=repo)
    git("tag", "freeze-1")
    assert AN.freeze_tag_ok(repo) == (True, "ok")
    (repo / "dirty.txt").write_text("x")
    assert AN.freeze_tag_ok(repo)[0] is False


# ── import (D23) ──────────────────────────────────────────────────────────

def test_valid_sheet_imports_with_derived_tiers(export, tmp_path):
    out, key, _, _ = export
    rows = read_sheet(out / "sheets" / "primary.csv")

    def rule(r):
        n = int(r["sentence_no"])
        if n == 1:
            return {"label": "hallucinated", "subtype": "attack_technique", "hedged": "yes"}
        if n == 2:
            return {"label": "hallucinated", "subtype": "unit", "hedged": "no", "other_subtypes": "threat_actor",
                    "unsure": "yes"}
        if n == 3:
            return {"label": "hallucinated", "subtype": "other_knowledge", "hedged": "no", "note": "backup schedule"}
        return {"label": "grounded"}

    path = tmp_path / "filled.csv"
    write_sheet(path, fill(rows, rule), notes=["no incidents"])
    res = AN.import_sheet(path, key, "primary", "ann1")
    labels = {g.item_id: g for g in res["labels"]}
    assert len(labels) == len(rows) and res["file_notes"] == ["no incidents"]
    g1 = next(g for g in labels.values() if g.item_id.endswith("-01"))
    assert (g1.tier, g1.hedged, g1.strict, g1.lenient) == (1, True, True, True)
    g2 = next(g for g in labels.values() if g.item_id.endswith("-02"))
    assert (g2.tier, g2.other_subtypes, g2.unsure, g2.lenient) == (2, ("threat_actor",), True, True)  # T1 other
    g3 = next(g for g in labels.values() if g.item_id.endswith("-03"))
    assert (g3.tier, g3.lenient, g3.note) == (2, False, "backup schedule")
    assert all(g.tier is None and g.hedged is None for g in labels.values() if g.label == "grounded")
    assert AN.labels_to_json(res["labels"])[0]["gold_strict"] in (True, False)


@pytest.mark.parametrize("bad,message", [
    ({"label": "hallucinated", "subtype": "port_scan", "hedged": "no"}, "unknown subtype 'port_scan'"),
    ({"label": "hallucinated", "hedged": "no"}, "hallucinated without a subtype"),
    ({"label": "grounded", "subtype": "cve"}, "grounded with a subtype"),
    ({"label": "hallucinated", "subtype": "other_fabrication", "hedged": "no"}, "need a note"),
    ({"label": "hallucinated", "subtype": "cve", "hedged": "no", "other_subtypes": "other_knowledge"}, "need a note"),
    ({"label": ""}, "label is blank"),
    ({"label": "maybe"}, "must be grounded or hallucinated"),
    ({"label": "hallucinated", "subtype": "cve", "hedged": "sort of"}, "hedged must be yes or no"),
    ({"label": "hallucinated", "subtype": "cve"}, "hedged must be yes or no"),
    ({"label": "grounded", "hedged": "no"}, "hedged must be empty"),
    ({"label": "hallucinated", "subtype": "cve", "hedged": "no", "other_subtypes": "cve"}, "repeats the subtype"),
    ({"label": "hallucinated", "subtype": "soft_certainty", "hedged": "no"}, "unknown subtype"),
    ({"label": "grounded", "unsure": "no"}, "unsure must be yes or empty"),
])
def test_d23_rejections(export, tmp_path, bad, message):
    out, key, _, _ = export
    rows = fill(read_sheet(out / "sheets" / "primary.csv"), GROUNDED)
    rows[5] = {**rows[5], **bad}
    write_sheet(tmp_path / "f.csv", rows)
    with pytest.raises(AN.AnnotationImportError) as err:
        AN.import_sheet(tmp_path / "f.csv", key, "primary", "ann1")
    assert any(message in p for p in err.value.problems) and rows[5]["item_id"] in str(err.value)


def test_every_problem_is_reported_at_once(export, tmp_path):
    out, key, _, _ = export
    rows = fill(read_sheet(out / "sheets" / "primary.csv"), GROUNDED)
    rows[1]["label"] = ""
    rows[2] = {**rows[2], "label": "hallucinated", "subtype": "made_up", "hedged": "no"}
    dup, missing = dict(rows[3]), rows.pop(4)
    rows.append(dup)
    rows.append({**rows[0], "item_id": "Z999-01"})
    write_sheet(tmp_path / "f.csv", rows)
    with pytest.raises(AN.AnnotationImportError) as err:
        AN.import_sheet(tmp_path / "f.csv", key, "primary", "ann1")
    text = "\n".join(err.value.problems)
    for expected in ("label is blank", "unknown subtype 'made_up'", "duplicate row", "item_id not in this sheet",
                     f"{missing['item_id']}: row missing"):
        assert expected in text


def test_import_accepts_excel_cp1252_and_rejects_a_missing_column(export, tmp_path):
    out, key, _, _ = export
    rows = fill(read_sheet(out / "sheets" / "retest.csv"), GROUNDED)
    write_sheet(tmp_path / "f.csv", rows, encoding="cp1252")
    assert len(AN.import_sheet(tmp_path / "f.csv", key, "retest", "ann1")["labels"]) == len(rows)
    with open(tmp_path / "g.csv", "w", encoding="utf-8", newline="") as f:
        f.write("item_id,label\nT001-01,grounded\n")
    with pytest.raises(AN.AnnotationImportError, match="missing column"):
        AN.import_sheet(tmp_path / "g.csv", key, "retest", "ann1")


# ── agreement ─────────────────────────────────────────────────────────────

def test_kappa_matches_a_hand_computed_example():
    # 10 items; agree on 8 (po = 0.8); each rater says "yes" 5 times (pe = 0.5) -> kappa = 0.6
    a = [1, 1, 1, 1, 1, 0, 0, 0, 0, 0]
    b = [1, 1, 1, 1, 0, 0, 0, 0, 0, 1]
    assert AN.cohen_kappa(a, b) == pytest.approx(0.6)
    # three categories: agree on 5 of 6 (po = 5/6); pe = (2*2 + 2*1 + 2*3)/36 = 1/3 -> kappa = (5/6-1/3)/(2/3) = 0.75
    assert AN.cohen_kappa([0, 0, 1, 1, 2, 2], [0, 0, 1, 2, 2, 2]) == pytest.approx(0.75)
    assert AN.cohen_kappa([1, 1, 1], [1, 1, 1]) is None                  # undefined, not 1 or 0


def test_kappa_matches_sklearn():
    from sklearn.metrics import cohen_kappa_score
    rng = random.Random(3)
    for _ in range(20):
        a = [rng.choice("xyz") for _ in range(50)]
        b = [x if rng.random() < 0.7 else rng.choice("xyz") for x in a]
        assert AN.cohen_kappa(a, b) == pytest.approx(cohen_kappa_score(a, b))


def labelled(export, tmp_path, name, rule, sheet="primary", annotator="ann1"):
    out, key, _, _ = export
    rows = fill(read_sheet(out / "sheets" / f"{sheet}.csv"), rule)
    write_sheet(tmp_path / f"{name}.csv", rows)
    return AN.import_sheet(tmp_path / f"{name}.csv", key, sheet, annotator)["labels"]


def rule_from(seed, flip=0.0):
    def rule(r):
        rng = random.Random(f"{r['item_id'][-2:]}:{r['sentence']}")          # same sentence -> same base answer
        x = rng.random()
        if random.Random(f"{seed}:{r['item_id']}:{r['sentence']}").random() < flip:
            x = 1 - x
        if x < 0.5:
            return {"label": "grounded"}
        sub = "attack_technique" if x < 0.75 else ("baseline" if x < 0.9 else "cve")
        return {"label": "hallucinated", "subtype": sub, "hedged": "no"}
    return rule


def test_agreement_identical_passes(export, tmp_path):
    a = labelled(export, tmp_path, "a", rule_from(0))
    b = labelled(export, tmp_path, "b", rule_from(0), annotator="ann2")
    res = AN.agreement(a, b, seed=1, n_boot=200)
    assert res["n_explanations"] == 100
    for name in ("label", "lenient", "tier", "tier1", "tier2", "subtype:attack_technique", "subtype:baseline",
                 "subtype:cve"):
        assert res["kappa"][name]["kappa"] == pytest.approx(1.0) and res["kappa"][name]["ci95"] == [1.0, 1.0]


def test_agreement_with_disagreements(export, tmp_path):
    a = labelled(export, tmp_path, "a", rule_from(0))
    b = labelled(export, tmp_path, "b", rule_from(1, flip=0.2), annotator="ann2")
    res = AN.agreement(a, b, seed=1, n_boot=300)
    k = res["kappa"]["label"]
    assert k["kappa"] == pytest.approx(AN.cohen_kappa([g.label for g in sorted(a, key=lambda g: (g.alert_id, g.sentence_id))],
                                                      [g.label for g in sorted(b, key=lambda g: (g.alert_id, g.sentence_id))]))
    assert 0 < k["kappa"] < 1 and k["ci95"][0] <= k["kappa"] <= k["ci95"][1]
    assert res == AN.agreement(a, b, seed=1, n_boot=300)                  # deterministic
    assert set(res["kappa"]) >= {"tier", "tier1", "tier2", "subtype:cve"}
    rows = AN.disagreements(a, b)
    assert rows and all((r["a_label"], r["a_subtype"]) != (r["b_label"], r["b_subtype"]) for r in rows)
    AN.write_disagreements(tmp_path / "adjudicate.csv", rows)
    assert len(read_sheet(tmp_path / "adjudicate.csv")) == len(rows)


def test_retest_agreement_on_the_subset(export, tmp_path):
    primary = labelled(export, tmp_path, "p", rule_from(0))
    retest = labelled(export, tmp_path, "t", rule_from(0), sheet="retest")
    with pytest.raises(ValueError, match="different sentences"):
        AN.agreement(primary, retest)
    res = AN.agreement(AN.restrict_to(primary, retest), retest, n_boot=100)
    assert res["n_explanations"] == 25 and res["kappa"]["label"]["kappa"] == pytest.approx(1.0)


# ── command line, end to end on a synthetic run ───────────────────────────

def test_cli_export_import_agreement(tmp_path, capsys):
    from hallucination_pipeline import cli
    from test_run_infrastructure import BASE, _to_toml
    alerts, explanations = synthetic_run()
    run_dir = tmp_path / "runs" / "syn-run"
    run_dir.mkdir(parents=True)
    (run_dir / "alerts.json").write_text(json.dumps(alerts), encoding="utf-8")
    (run_dir / "explanations.json").write_text(json.dumps(explanations), encoding="utf-8")
    toml = tmp_path / "cfg.toml"
    toml.write_text(_to_toml(BASE, tmp_path), encoding="utf-8")
    c = ["--config", str(toml)]

    assert cli.main(["annotation_export", "syn-run", *c]) == 1                # no freeze-1 tag here -> refused
    assert cli.main(["annotation_export", "syn-run", "--unfrozen", *c]) == 0
    ann = tmp_path / "annotation" / "syn-run"
    key = json.loads((ann / "key.json").read_text(encoding="utf-8"))
    assert key["unfrozen_export"] is True
    for sheet, name in (("primary", "p"), ("retest", "t")):
        rows = fill(read_sheet(ann / "sheets" / f"{sheet}.csv"), rule_from(0))
        write_sheet(tmp_path / f"{name}.csv", rows)
        assert cli.main(["annotation_import", "syn-run", str(tmp_path / f"{name}.csv"), "--sheet", sheet,
                         "--annotator", "ann1", *c]) == 0
    assert cli.main(["annotation_import", "syn-run", str(tmp_path / "p.csv"), "--sheet", "primary",
                     "--annotator", "ann1", *c]) == 1                         # never overwritten
    imported = ann / "imported"
    assert cli.main(["annotation_agreement", "syn-run", str(imported / "primary_ann1.json"),
                     str(imported / "retest_ann1.json"), *c]) == 0
    res = json.loads((ann / "agreement_primary-ann1_vs_retest-ann1.json").read_text(encoding="utf-8"))
    assert res["n_explanations"] == 25 and res["kappa"]["label"]["kappa"] == pytest.approx(1.0)
    assert "kappa" in capsys.readouterr().out

"""D30/D31 AI-annotator audit labels (tools/ai_labelling.py). Offline: synthetic corpus, fake replies, no API."""

import csv
import json
import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

import ai_labelling as AL
from hallucination_pipeline import annotation as AN
from hallucination_pipeline import audit as AU
from hallucination_pipeline import corpus as CO
from test_corpus import AGREE, make_corpus


@pytest.fixture
def setup(tmp_path):
    corpus_dir = make_corpus(tmp_path / "old_run")
    corpus = CO.load_corpus(corpus_dir)
    ann = tmp_path / "annotation"
    AU.export_audit(corpus, ann / corpus["corpus_id"], unfrozen_ok=True)
    AL.ai_export(ann, corpus["corpus_id"])
    return {"ann": ann, "cid": corpus["corpus_id"], "corpus": corpus, "corpus_dir": corpus_dir, "tmp": tmp_path,
            "out": AL.ai_dir(ann, corpus["corpus_id"]), "sheet": AL._read_sheet(ann, corpus["corpus_id"])}


def truthful(row):
    """A labeller that answers like the rules' ground truth in test_corpus."""
    if row["sentence"] in AGREE:
        sub, hedged = AGREE[row["sentence"]]
        return ["hallucinated", sub, hedged, "", "", ""]
    return ["grounded", "", "", "", "", ""]


def write_replies(s, name, answer, style="plain", per_file=None):
    """One reply file per chunk, in the chunk's item order."""
    chunks = sorted((s["out"] / "chunks").glob("chunk_*.txt"))
    by_id = {r["item_id"]: r for r in s["sheet"]}
    for ch in chunks:
        codes = [line[1:line.index("]")] for line in ch.read_text(encoding="utf-8").splitlines() if line.startswith("[")]
        lines = []
        if style == "messy":
            lines += ["Here are my labels:", "```", "| ITEM_CODE | label | subtype | hedged | other_subtypes | note | unsure |",
                      "|---|---|---|---|---|---|---|"]
        for k, code in enumerate(codes):
            fields = answer(by_id[code])
            if style == "messy":
                lines.append(["- ", "* ", "1. ", "| ", "  "][k % 5] + f"{code}  |  " + " | ".join(fields)
                             + (" |" if k % 5 == 3 else ""))
            else:
                lines.append(f"{code} | " + " | ".join(fields))
        if style == "messy":
            lines.append("```")
        (s["out"] / "replies" / f"{name}_{ch.stem}.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


# ── export ────────────────────────────────────────────────────────────────

def test_chunks_contain_every_item_once_and_leak_nothing(setup):
    chunks = sorted((setup["out"] / "chunks").glob("chunk_*.txt"))
    assert [c.name for c in chunks] == [f"chunk_{i:02d}.txt" for i in range(1, 6)]          # 25 explanations / 5
    text = "".join(c.read_text(encoding="utf-8") for c in chunks)
    codes = [line[1:line.index("]")] for line in text.splitlines() if line.startswith("[")]
    assert sorted(codes) == sorted(r["item_id"] for r in setup["sheet"]) and len(codes) == len(set(codes))
    assert text.count("EXPLANATION E") == 25 and text.count("Evidence:") == 25
    assert all(c.read_text(encoding="utf-8").count("EXPLANATION E") == 5 for c in chunks)
    for leak in ("Normal Traffic", "DoS", "DDoS", "Brute Force", "Port Scanning", "benign", "attack-flow", "A0",
                 "alert", "label_", "rule", "tier", "subtype"):
        assert leak not in text, leak
    man = json.loads((setup["out"] / "labelling_manifest.json").read_text(encoding="utf-8"))
    assert set(man["labellers"]) == {"gemini", "gpt"}
    AL.ai_export(setup["ann"], setup["cid"])          # re-export with identical content is harmless


# ── import ────────────────────────────────────────────────────────────────

def test_import_tolerates_formatting_and_validates(setup):
    write_replies(setup, "gemini", truthful, style="messy")
    write_replies(setup, "gpt", truthful)
    r = AL.ai_import(setup["ann"], setup["cid"], "gemini")
    assert (r["valid"], r["invalid_or_missing"]) == (75, 0) and r["other_lines_ignored"] >= 5   # prose ignored
    assert AL.ai_import(setup["ann"], setup["cid"], "gpt")["valid"] == 75
    a = AL._load_labels(setup["out"], "gemini")
    b = AL._load_labels(setup["out"], "gpt")
    assert [AL.answer(g) for g in a] == [AL.answer(g) for g in b]
    assert (setup["out"] / "labels_gemini.csv").exists()


def test_d33_invalid_items_are_recorded_not_fatal(setup, capsys):
    s = setup
    rows = s["sheet"]
    bad = {rows[0]["item_id"]: ["hallucinated", "port_scan", "no", "", "", ""],          # unknown subtype
           rows[1]["item_id"]: ["hallucinated", "", "no", "", "", ""],                   # subtype missing
           rows[2]["item_id"]: ["hallucinated", "other_fabrication", "no", "", "", ""],  # catch-all, no note
           rows[3]["item_id"]: ["", "", "", "", "", ""],                                 # blank label
           rows[4]["item_id"]: ["maybe", "", "", "", "", ""]}                            # invalid label
    write_replies(s, "gemini", lambda r: bad.get(r["item_id"], truthful(r)))
    f = sorted((s["out"] / "replies").glob("gemini_*.txt"))[1]
    lines = f.read_text(encoding="utf-8").splitlines()
    missing_code, dup_code = lines[0].split(" | ")[0], lines[1].split(" | ")[0]
    f.write_text("\n".join(lines[1:] + [lines[1], "Z999-01 | grounded | | | | |"]) + "\n", encoding="utf-8")
    r = AL.ai_import(s["ann"], s["cid"], "gemini")
    assert (r["valid"], r["invalid_or_missing"], r["missing"]) == (75 - 7, 7, 1)
    assert r["invalid_by_reason"] == {"catch_all_without_note": 1, "duplicate": 1, "invalid_label": 1,
                                      "label_blank": 1, "missing": 1, "subtype_missing": 1, "unknown_subtype": 1}
    assert r["unknown_item_codes_ignored"] == 1
    hidden = json.loads((s["out"] / "hidden" / "invalid_gemini.json").read_text(encoding="utf-8"))["invalid"]
    assert hidden[missing_code] == ["missing"] and hidden[dup_code] == ["duplicate"]
    assert hidden[rows[0]["item_id"]] == ["unknown_subtype"] and hidden[rows[2]["item_id"]] == ["catch_all_without_note"]
    valid_ids = {g.item_id for g in AL._load_labels(s["out"], "gemini")}
    assert len(valid_ids) == 68 and not valid_ids & set(hidden)
    man = json.loads((s["out"] / "labelling_manifest.json").read_text(encoding="utf-8"))
    assert man["import"]["gemini"]["invalid_by_reason"] == r["invalid_by_reason"]
    assert man["import"]["gemini"]["valid"] == 68 and "invalid" not in json.dumps(man["import"]).replace("invalid_", "")
    for code in hidden:                                   # the manifest holds counts, never item codes
        assert code not in json.dumps(man)

    # the terminal shows counts only, never an item code
    write_replies(s, "gpt", truthful)
    from test_run_infrastructure import BASE, _to_toml
    toml = s["tmp"] / "cfg.toml"
    toml.write_text(_to_toml(BASE, s["tmp"]), encoding="utf-8")
    assert AL.main(["ai_import", "--labeller", "gemini", "--config", str(toml), "--corpus-dir", str(s["corpus_dir"])]) == 0
    out = capsys.readouterr().out
    assert "68 valid, 7 invalid or missing" in out and not re.search(r"E\d{3}-\d{2}", out)


def test_d33_whole_import_problems_still_stop(setup):
    s = setup
    with pytest.raises(FileNotFoundError):
        AL.ai_import(s["ann"], s["cid"], "nobody")                                   # no reply files
    (s["out"] / "replies" / "x_chunk_01.txt").write_text("I cannot help with that.\n", encoding="utf-8")
    with pytest.raises(AL.LabellingError, match="no item code found"):
        AL.ai_import(s["ann"], s["cid"], "x")
    (s["out"] / "replies" / "y_chunk_01.txt").write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(AL.LabellingError, match="not readable"):
        AL.ai_import(s["ann"], s["cid"], "y")


# ── compare ───────────────────────────────────────────────────────────────

def disagreeing(row):
    """Labeller B: calls every hedged attack_technique 'baseline' and every T2 port 'grounded'."""
    a = truthful(row)
    if a[1] == "attack_technique":
        return ["hallucinated", "baseline", "yes", "", "", ""]
    if a[1] == "port":
        return ["grounded", "", "", "", "", ""]
    return a


@pytest.fixture
def compared(setup):
    write_replies(setup, "gemini", truthful)
    write_replies(setup, "gpt", disagreeing)
    AL.ai_import(setup["ann"], setup["cid"], "gemini")
    AL.ai_import(setup["ann"], setup["cid"], "gpt")
    setup["cmp"] = AL.ai_compare(setup["ann"], setup["cid"], "gemini", "gpt")
    return setup


def test_compare_builds_a_blind_shuffled_adjudication_sheet(compared):
    s, r = compared, compared["cmp"]
    a = {g.item_id: g for g in AL._load_labels(s["out"], "gemini")}
    b = {g.item_id: g for g in AL._load_labels(s["out"], "gpt")}
    dis = {i for i in a if AL.answer(a[i]) != AL.answer(b[i])}
    assert r["disagreements"] == len(dis) > 0 and r["agreements"] == 75 - len(dis)
    assert r["spot_check"] == round(0.2 * r["agreements"]) and r["to_adjudicate"] == len(dis) + r["spot_check"]
    with open(s["out"] / "adjudication.csv", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    assert tuple(rows[0]) == AN.SHEET_COLUMNS
    assert all(row[c] == "" for row in rows for c in AN.ANNOTATION_COLUMNS)         # no AI answer anywhere
    assert dis <= {row["item_id"] for row in rows} and len(rows) == r["to_adjudicate"]
    order = [row["item_id"] for row in rows]
    assert order != sorted(order)
    text = (s["out"] / "adjudication.csv").read_text(encoding="utf-8-sig")
    for leak in ("gemini", "gpt", "disagreement", "spot", "baseline", "attack_technique"):
        assert leak not in text, leak
    key = json.loads((s["out"] / "hidden" / "adjudication_key.json").read_text(encoding="utf-8"))
    assert {i for i, k in key["items"].items() if "disagreement" in k} == dis
    assert (s["out"] / "hidden" / "ai_disagreements.csv").exists()
    assert json.loads((s["out"] / "hidden" / "ai_agreement.json").read_text(encoding="utf-8"))["agreement"]["kappa"]["label"]
    with pytest.raises(AL.LabellingError):
        AL.ai_compare(s["ann"], s["cid"], "gemini", "gpt")                       # never rebuilt
    with pytest.raises(AL.LabellingError):
        AL.ai_import(s["ann"], s["cid"], "gemini")                               # labels frozen once adjudicating


# ── finalize ──────────────────────────────────────────────────────────────

def fill_manifest(s):
    man = json.loads((s["out"] / "labelling_manifest.json").read_text(encoding="utf-8"))
    for name, model in (("gemini", "Gemini"), ("gpt", "GPT")):
        man["labellers"][name] = {"model_name": model, "model_version": "x.y", "date": "2026-10-08",
                                  "interface": "chat", "tools": "off", "customisation": "none"}
    (s["out"] / "labelling_manifest.json").write_text(json.dumps(man), encoding="utf-8")


def adjudicate(s, decide):
    with open(s["out"] / "adjudication.csv", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    by_id = {r["item_id"]: r for r in s["sheet"]}
    filled = [{**r, **dict(zip(AN.ANNOTATION_COLUMNS, decide(by_id[r["item_id"]])))} for r in rows]
    AL._write_sheet_csv(s["out"] / "adjudication_filled.csv", filled)
    return rows


def test_finalize_merges_and_reports_the_overrule_rate(compared):
    s = compared
    key = json.loads((s["out"] / "hidden" / "adjudication_key.json").read_text(encoding="utf-8"))
    spot = sorted(i for i, k in key["items"].items() if k == ["spot-check"])
    overrule = spot[0]

    def author(row):                         # truthful, except one spot-check item is overruled
        if row["item_id"] == overrule:
            return ["hallucinated", "other_knowledge", "no", "", "author note", ""] if truthful(row)[0] == "grounded" \
                else ["grounded", "", "", "", "", ""]
        return truthful(row)

    with pytest.raises(AL.LabellingError, match="not filled in"):
        AL.ai_finalize(s["ann"], s["cid"], "gemini", "gpt", "IS", s["corpus_dir"], results_dir=s["tmp"] / "results")
    fill_manifest(s)
    with pytest.raises(FileNotFoundError, match="analyze_corpus"):
        AL.ai_finalize(s["ann"], s["cid"], "gemini", "gpt", "IS", s["corpus_dir"], results_dir=s["tmp"] / "results")
    CO.write_results(s["corpus"], s["tmp"] / "results", n_boot=200)
    adjudicate(s, author)
    r = AL.ai_finalize(s["ann"], s["cid"], "gemini", "gpt", "IS", s["corpus_dir"], results_dir=s["tmp"] / "results")
    summ = r["summary"]
    assert summ["spot_check_overruled"] == 1 and summ["overrule_rate"] == pytest.approx(1 / len(spot))
    assert summ["disagreements"] == s["cmp"]["disagreements"]
    assert summ["disagreements_resolved"]["with_gemini"] == s["cmp"]["disagreements"]
    expected = (f"labels: two AI annotators (gemini: Gemini x.y; gpt: GPT x.y), author-adjudicated; "
                f"{summ['disagreements']} disagreements; 0 items invalid or missing for at least one labeller were "
                f"adjudicated by the author; 20% blind spot-check ({len(spot)} items); overrule rate "
                f"{1 / len(spot):.0%} (1/{len(spot)})")
    assert summ["labels"] == expected

    final_text = (s["out"] / "final_labels.csv").read_text(encoding="utf-8-sig")
    assert final_text.splitlines()[:2] == [f"# {CO.SOURCE}", f"# {expected}"]
    final = AN.import_sheet(s["out"] / "final_labels.csv", AL._read_key(s["ann"], s["cid"]), "primary", "x")
    labels = {g.item_id: g for g in final["labels"]}
    assert len(labels) == 75 and labels[overrule].label != truthful(next(r for r in s["sheet"]
                                                                          if r["item_id"] == overrule))[0]
    for name in ("audit_metrics.csv", "audit_disagreements.csv"):
        lines = (r["dest"] / name).read_text(encoding="utf-8").splitlines()
        assert lines[:2] == [f"# {CO.SOURCE}", f"# {expected}"]
    assert json.loads((r["dest"] / "audit.json").read_text(encoding="utf-8"))["labels"] == expected
    with pytest.raises(AL.LabellingError, match="never overwritten"):
        AL.ai_finalize(s["ann"], s["cid"], "gemini", "gpt", "IS", s["corpus_dir"], results_dir=s["tmp"] / "results")


def test_cli_end_to_end(setup, capsys):
    from test_run_infrastructure import BASE, _to_toml
    s = setup
    toml = s["tmp"] / "cfg.toml"
    toml.write_text(_to_toml(BASE, s["tmp"]), encoding="utf-8")
    c = ["--config", str(toml), "--corpus-dir", str(s["corpus_dir"]), "--results-dir", str(s["tmp"] / "results")]
    assert AL.main(["ai_export", *c]) == 0
    write_replies(s, "gemini", truthful)
    write_replies(s, "gpt", disagreeing)
    assert AL.main(["ai_import", "--labeller", "gemini", *c]) == 0
    assert AL.main(["ai_import", "--labeller", "gpt", *c]) == 0
    assert AL.main(["ai_compare", "--labellers", "gemini", "gpt", *c]) == 0
    assert "Do NOT open the hidden/" in capsys.readouterr().out
    fill_manifest(s)
    CO.write_results(s["corpus"], s["tmp"] / "results", n_boot=200)
    adjudicate(s, truthful)
    assert AL.main(["ai_finalize", "--labellers", "gemini", "gpt", "--author", "IS", *c]) == 0
    out = capsys.readouterr().out
    assert "author-adjudicated" in out and "overrule rate 0%" in out and "precision" in out


# ── D32 deterministic format repairs ──────────────────────────────────────

def collapsed_line(codes, fields=("grounded", "", "", "", "", "")):
    return " ".join(f"{c} | " + " | ".join(fields) for c in codes)


def test_d32a_a_collapsed_line_of_11_items_is_split():
    codes = [f"E001-{i:02d}" for i in range(1, 12)]
    for text in (collapsed_line(codes),
                 "```" + collapsed_line(codes) + "```",
                 "\u00a0" + collapsed_line(codes).replace(" | ", "\u00a0|\u00a0"),
                 " ".join(f"{k}. {c} | grounded | | | | |" for k, c in enumerate(codes, 1))):
        items, problems, ignored, repairs = AL.parse_reply_lines(text, "r.txt", set(codes))
        assert [c for c, _, _ in items] == codes and problems == [], text[:40]
        assert all(f[1] == "grounded" and f[2:] == ["", "", "", "", ""] for _, f, _ in items)
        assert repairs == [{"repair": "split_collapsed_line", "where": "r.txt:1", "records": 11}]


def test_d32a_bare_carriage_returns_are_line_breaks():
    codes = ["E001-01", "E001-02", "E001-03"]
    text = "\r".join(f"{c} | grounded | | | | |" for c in codes)
    items, problems, _, repairs = AL.parse_reply_lines(text, "r.txt", set(codes))
    assert [c for c, _, _ in items] == codes and problems == [] and repairs == []


def ans(subtype, label="hallucinated", hedged="no", others=""):
    return {"label": label, "subtype": subtype, "hedged": hedged, "other_subtypes": others, "note": "", "unsure": ""}


@pytest.mark.parametrize("field,primary,moved", [
    ("baseline, protocol", "protocol", ["baseline"]),          # both Tier 2: protocol is listed first
    ("port, encryption", "port", ["encryption"]),
    ("baseline, attack_technique", "attack_technique", ["baseline"]),   # Tier 1 beats Tier 2
    ("unit, threat_actor, port", "threat_actor", ["unit", "port"]),
    ("threat_actor, cve", "cve", ["threat_actor"]),             # within Tier 1: cve is listed first
])
def test_d32b_primary_subtype_rule(field, primary, moved):
    out, repair, problem = AL.repair_multi_subtype("E001-01", ans(field, hedged="yes", others="unit"))
    assert problem is None and out["subtype"] == primary
    assert out["other_subtypes"].split(",") == moved + (["unit"] if "unit" not in moved and primary != "unit" else [])
    assert (out["label"], out["hedged"]) == ("hallucinated", "yes")            # never changed
    assert repair["moved_to_other_subtypes"] == moved


def test_d32b_refuses_a_repair_that_would_need_a_label_change():
    for label in ("grounded", ""):
        out, repair, problem = AL.repair_multi_subtype("E001-02", ans("baseline, protocol", label=label, hedged=""))
        assert repair is None and out["label"] == label and "not repaired" in problem and "E001-02" in problem
    out, repair, problem = AL.repair_multi_subtype("E001-03", ans("baseline, port_scan"))
    assert repair is None and "unknown subtype 'port_scan'" in problem
    assert AL.repair_multi_subtype("E001-04", ans("baseline")) == (ans("baseline"), None, None)


def test_d32_import_repairs_are_counted_logged_and_never_change_labels(setup):
    s = setup
    multi = {}

    def gemini(row):                       # truthful, but Tier 2 port answers come as 'port, encryption'
        a = truthful(row)
        if a[1] == "port":
            multi[row["item_id"]] = True
            return ["hallucinated", "port, encryption", "no", "", "", ""]
        return a
    write_replies(s, "gemini", gemini)
    write_replies(s, "gpt", truthful)
    for f in (s["out"] / "replies").glob("gpt_*.txt"):                 # collapse each reply onto one line
        f.write_text(f.read_text(encoding="utf-8").replace("\n", " ").strip() + "\n", encoding="utf-8")
    rg = AL.ai_import(s["ann"], s["cid"], "gemini")
    rp = AL.ai_import(s["ann"], s["cid"], "gpt")
    assert rg["repairs_d32"] == {"collapsed_lines_split": 0, "records_recovered_from_split_lines": 0,
                             "multi_subtype_fields_repaired": len(multi)} and multi
    assert rp["repairs_d32"] == {"collapsed_lines_split": 5, "records_recovered_from_split_lines": 75,
                             "multi_subtype_fields_repaired": 0}
    man = json.loads((s["out"] / "labelling_manifest.json").read_text(encoding="utf-8"))
    assert man["format_repairs"]["gpt"]["collapsed_lines_split"] == 5 and man["format_repairs"]["gemini"]["decision"] == "D32"
    hidden = json.loads((s["out"] / "hidden" / "format_repairs_gemini.json").read_text(encoding="utf-8"))
    assert sorted(r["item"] for r in hidden["repairs"]) == sorted(multi)
    a = {g.item_id: g for g in AL._load_labels(s["out"], "gemini")}
    b = {g.item_id: g for g in AL._load_labels(s["out"], "gpt")}
    for i in a:
        assert (a[i].label, a[i].hedged) == (b[i].label, b[i].hedged)            # labels and hedged untouched
        if i in multi:
            assert (a[i].subtype, a[i].other_subtypes) == ("port", ("encryption",))
        else:
            assert AL.answer(a[i]) == AL.answer(b[i])


def test_d32_a_refused_repair_makes_the_item_invalid(setup):
    s = setup
    target = s["sheet"][0]["item_id"]
    write_replies(s, "gemini", lambda r: ["grounded", "baseline, protocol", "", "", "", ""] if r["item_id"] == target
                  else truthful(r))
    r = AL.ai_import(s["ann"], s["cid"], "gemini")
    assert r["invalid_by_reason"] == {"multi_subtype_not_repairable": 1} and r["repairs_d32"]["multi_subtype_fields_repaired"] == 0
    hidden = json.loads((s["out"] / "hidden" / "invalid_gemini.json").read_text(encoding="utf-8"))["invalid"]
    assert hidden == {target: ["multi_subtype_not_repairable"]}
    assert target not in {g.item_id for g in AL._load_labels(s["out"], "gemini")}


def test_d33_invalid_items_go_to_adjudication_and_out_of_kappa(setup):
    s = setup
    rows = s["sheet"]
    inv_gemini, inv_gpt = rows[0]["item_id"], rows[1]["item_id"]
    write_replies(s, "gemini", lambda r: ["hallucinated", "port_scan", "no", "", "", ""] if r["item_id"] == inv_gemini
                  else truthful(r))
    write_replies(s, "gpt", lambda r: ["hallucinated", "other_knowledge", "no", "", "", ""] if r["item_id"] == inv_gpt
                  else truthful(r))
    AL.ai_import(s["ann"], s["cid"], "gemini")
    AL.ai_import(s["ann"], s["cid"], "gpt")
    r = AL.ai_compare(s["ann"], s["cid"], "gemini", "gpt")
    assert (r["valid_for_both"], r["excluded_from_kappa"]) == (73, 2)
    assert (r["invalid_or_missing_gemini"], r["invalid_or_missing_gpt"]) == (1, 1)
    assert (r["disagreements"], r["agreements"]) == (0, 73) and r["kappa_label"] == pytest.approx(1.0)
    assert r["to_adjudicate"] == 2 + round(0.2 * 73)
    key = json.loads((s["out"] / "hidden" / "adjudication_key.json").read_text(encoding="utf-8"))
    assert key["items"][inv_gemini] == ["invalid-gemini"] and key["items"][inv_gpt] == ["invalid-gpt"]
    assert key["n_invalid_or_missing_for_either"] == 2
    agreement = json.loads((s["out"] / "hidden" / "ai_agreement.json").read_text(encoding="utf-8"))
    assert agreement["n_items"] == 73 and agreement["excluded"] == 2
    with open(s["out"] / "adjudication.csv", encoding="utf-8-sig") as f:
        sheet_rows = list(csv.DictReader(f))
    assert {inv_gemini, inv_gpt} <= {x["item_id"] for x in sheet_rows}
    assert tuple(sheet_rows[0]) == AN.SHEET_COLUMNS
    assert all(x[c] == "" for x in sheet_rows for c in AN.ANNOTATION_COLUMNS)
    text = (s["out"] / "adjudication.csv").read_text(encoding="utf-8-sig")
    for leak in ("invalid", "gemini", "gpt", "spot", "disagree", "port_scan", "other_knowledge", "reason"):
        assert leak not in text, leak

    def author(row):
        return truthful(row)
    fill_manifest(s)
    CO.write_results(s["corpus"], s["tmp"] / "results", n_boot=200)
    adjudicate(s, author)
    res = AL.ai_finalize(s["ann"], s["cid"], "gemini", "gpt", "IS", s["corpus_dir"], results_dir=s["tmp"] / "results")
    assert res["summary"]["invalid_or_missing_adjudicated"] == 2
    assert "2 items invalid or missing for at least one labeller were adjudicated by the author" in res["summary"]["labels"]
    final = (s["out"] / "final_labels.csv").read_text(encoding="utf-8-sig")
    assert "2 items invalid or missing for at least one labeller were adjudicated by the author" in final.splitlines()[1]


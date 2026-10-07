"""D25-D28 existing-corpus study: analysis, results pack, audit sample, rules-versus-human metrics.
Synthetic corpora only (plus one optional check against old_run/ when it is present). No API key, no LLM."""

import csv
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hallucination_pipeline import annotation as AN
from hallucination_pipeline import audit as AU
from hallucination_pipeline import cli
from hallucination_pipeline import corpus as CO

T1_HEDGED = "This may indicate port scanning activity against the host."            # attack_technique, hedged
T1_PLAIN = "An attacker is targeting this host with the traffic."                    # threat_actor
UNIT_WRONG = "The flow lasted 92 seconds in total for this record."                  # 92190 us -> unit_wrong
PORT_WRONG = "Traffic was also sent to port 3389 during the flow."                   # port_not_in_evidence
T2_PORT = "Port 80 is commonly used for web traffic on most networks."               # Tier 2 port
CLEAN = "The flow recorded 4 forward packets in this record."                        # grounded
SOFT = "This is definitely unusual for a flow of this size."                         # ambiguous: not flagged


def evidence(port=80, duration=92190):
    return f"Destination Port: {port}\nFlow Duration: {duration}\nForward Packets: 4\nACK Flag Count: 0"


def make_corpus(d: Path, n_per_class=4, n_benign=16) -> Path:
    d.mkdir(parents=True, exist_ok=True)
    alerts, expls, i = [], [], 0
    plan = [(c, [T1_HEDGED, UNIT_WRONG, CLEAN]) for c in ("DoS", "DDoS", "Port Scanning", "Brute Force")
            for _ in range(n_per_class)]
    plan += [("Normal Traffic", [T2_PORT, CLEAN, SOFT] if k % 2 else [T1_PLAIN, PORT_WRONG, CLEAN])
             for k in range(n_benign)]
    for cls, sents in plan:
        i += 1
        aid = f"A{i:03d}"
        alerts.append({"alert_id": aid, "alert_type": cls, "evidence": evidence(),
                       "evidence_tokens": ["80", "92190", "4", "0"]})
        expls.append({"alert_id": aid, "alert_type": cls, "prompt": "p", "explanation": " ".join(sents),
                      "model": "m", "input_tokens": 0, "output_tokens": 0})
    alerts.append({"alert_id": "A999", "alert_type": "Normal Traffic", "evidence": evidence(), "evidence_tokens": []})
    expls.append({"alert_id": "A999", "alert_type": "Normal Traffic", "explanation": "[GENERATION FAILED]"})
    (d / "alerts.json").write_text(json.dumps(alerts), encoding="utf-8")
    (d / "llm_explanations.json").write_text(json.dumps(expls), encoding="utf-8")
    (d / "corrected_explanations.json").write_text("[]", encoding="utf-8")
    return d


@pytest.fixture
def corpus(tmp_path):
    return CO.load_corpus(make_corpus(tmp_path / "old_run"))


def read_csv(path):
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    assert lines[0] == f"# {CO.SOURCE}", f"{path} lacks the source line"
    return list(csv.DictReader(lines[1:]))


# ── loading and per-sentence analysis ─────────────────────────────────────

def test_fingerprint_is_stable_and_tracks_the_files(tmp_path):
    d = make_corpus(tmp_path / "c")
    a = CO.corpus_fingerprint(d)
    assert a == CO.corpus_fingerprint(d) and a["corpus_id"].startswith("corpus-")
    (d / "corrected_explanations.json").write_text("[ ]", encoding="utf-8")
    assert CO.corpus_fingerprint(d)["corpus_id"] != a["corpus_id"]
    (d / "alerts.json").unlink()
    with pytest.raises(FileNotFoundError, match="alerts.json"):
        CO.corpus_fingerprint(d)


def test_groups_and_exclusions(corpus):
    sentences, expls, excluded = CO.analyze(corpus["alerts"], corpus["explanations"])
    assert excluded == [{"alert_id": "A999", "group": "benign-flow", "reason": "generation failed"}]
    assert sum(e["group"] == "attack-flow" for e in expls) == 16 and sum(e["group"] == "benign-flow" for e in expls) == 16
    assert len(sentences) == 32 * 3


@pytest.mark.parametrize("sentence,strict,lenient,subtypes,extra", [
    (T1_HEDGED, True, True, ["attack_technique"], {"hedged": True}),
    (T1_PLAIN, True, True, ["threat_actor"], {"hedged": False}),
    (UNIT_WRONG, True, True, ["unit_wrong"], {"unit_wrong": True}),
    (PORT_WRONG, True, True, ["port_not_in_evidence"], {}),
    (T2_PORT, True, False, ["port"], {"tier2": True, "tier1": False}),
    (CLEAN, False, False, [], {}),
    (SOFT, False, False, [], {"ambiguous_strict": True}),
])
def test_sentence_records(sentence, strict, lenient, subtypes, extra):
    alert = {"alert_id": "A1", "alert_type": "DoS", "evidence": evidence(), "evidence_tokens": ["80", "92190", "4", "0"]}
    r = CO.analyze_sentence(sentence, alert, "S1", "attack-flow")
    assert (r["strict"], r["lenient"], r["subtypes"]) == (strict, lenient, subtypes)
    for k, v in extra.items():
        assert r[k] == v


# ── results pack ──────────────────────────────────────────────────────────

def test_results_pack(corpus, tmp_path):
    out = CO.write_results(corpus, tmp_path / "results", n_boot=300)
    assert out.name == corpus["corpus_id"]
    for name in ("prevalence", "attack_vs_benign", "hedging_attack_technique", "durations", "durations_summary",
                 "port_not_in_evidence", "port_not_in_evidence_examples", "flagged_per_explanation",
                 "flagged_per_explanation_histogram"):
        assert read_csv(out / "tables" / f"{name}.csv"), name
    m = json.loads((out / "MANIFEST.json").read_text(encoding="utf-8"))
    assert m["source"] == CO.SOURCE and m["llm_calls"] == 0 and m["counts"]["benign-flow"]["excluded"] == 1
    assert m["rules"]["rules_version"] == "1.0.0" and m["policy"]["policy_version"] == "1.2.0"
    assert CO.SOURCE in (out / "REPORT.md").read_text(encoding="utf-8")
    for line in (out / "sentences.jsonl").read_text(encoding="utf-8").splitlines():
        assert json.loads(line)["source"] == CO.SOURCE

    prev = {(r["level"], r["group"], r["category"]): r for r in read_csv(out / "tables" / "prevalence.csv")}
    # hand counts: every attack explanation has a Tier 1 hit; benign: half T1 (plan k even), half T2 only
    r = prev[("explanation", "attack-flow", "flag (lenient)")]
    assert (r["n_units"], r["count"], float(r["rate"])) == ("16", "16", 1.0)
    r = prev[("explanation", "benign-flow", "flag (lenient)")]
    assert (r["n_units"], r["count"]) == ("16", "8") and float(r["ci95_low"]) <= 0.5 <= float(r["ci95_high"])
    assert prev[("explanation", "benign-flow", "flag (strict)")]["count"] == "16"
    r = prev[("sentence", "all", "subtype unit_wrong (tier 1; counts under both)")]
    assert (r["n_units"], r["count"], r["n_explanations"]) == ("96", "16", "32")

    dur = {r["group"]: r for r in read_csv(out / "tables" / "durations_summary.csv")}
    assert (dur["attack-flow"]["duration_claims"], dur["attack-flow"]["unit_wrong"]) == ("16", "16")
    hedge = {r["group"]: r for r in read_csv(out / "tables" / "hedging_attack_technique.csv")}
    assert (hedge["attack-flow"]["attack_technique_hits"], hedge["attack-flow"]["hedged"]) == ("16", "16")
    port = {r["group"]: r for r in read_csv(out / "tables" / "port_not_in_evidence.csv")}
    assert port["benign-flow"]["sentences_with_port_not_in_evidence"] == "8"
    diff = {(r["level"], r["category"]): r for r in read_csv(out / "tables" / "attack_vs_benign.csv")}
    r = diff[("explanation", "flag (lenient)")]
    assert float(r["difference"]) == pytest.approx(0.5) and float(r["ci95_low"]) <= 0.5 <= float(r["ci95_high"])
    per = {(r["group"], r["policy"]): r for r in read_csv(out / "tables" / "flagged_per_explanation.csv")}
    assert float(per[("attack-flow", "strict")]["mean_flagged_sentences"]) == pytest.approx(2.0)
    assert (out / "samples" / "flagged_tier1.md").exists() and (out / "samples" / "flagged_tier2.md").exists()
    assert not (out / "tables" / "rewrites.csv").exists()          # rewrite files absent -> section skipped

    with pytest.raises(CO.ResultsExistError):
        CO.write_results(corpus, tmp_path / "results", n_boot=300)
    again = CO.write_results(corpus, tmp_path / "results2", n_boot=300)
    assert (again / "tables" / "prevalence.csv").read_text(encoding="utf-8") == \
           (out / "tables" / "prevalence.csv").read_text(encoding="utf-8")          # deterministic


def test_rewrite_number_check():
    pairs = [{"alert_id": "A1", "evidence": evidence(duration=92190), "evidence_tokens": ["92190"],
              "original": "The flow lasted 92 seconds.", "corrected": "The duration value was 92000 microseconds."},
             {"alert_id": "A2", "evidence": evidence(), "evidence_tokens": ["80"],
              "original": "Port 443 is used.", "corrected": "A port value of 443 was noted."},
             {"alert_id": "A3", "evidence": evidence(), "evidence_tokens": ["80"],
              "original": "x", "corrected": "Destination port 80 was observed."}]
    r = CO.check_rewrites(pairs, {})
    assert r[0]["numbers_absent_from_evidence"] == ["92000"] and r[0]["new_numbers_absent_from_evidence_and_original"] == ["92000"]
    assert r[1]["numbers_absent_from_evidence"] == ["443"] and r[1]["new_numbers_absent_from_evidence_and_original"] == []
    assert r[2]["numbers_absent_from_evidence"] == []


@pytest.mark.skipif(not (CO.PROJECT_ROOT / "old_run" / "hallucination_masks.json").exists(),
                    reason="old_run/ not present")
def test_old_run_rewrites_reproduce_the_audit_finding():
    data = CO.load_corpus(CO.PROJECT_ROOT / "old_run")
    r = CO.check_rewrites(CO.rewrite_pairs(data), {})
    assert len(r) == 132 and sum(bool(x["new_numbers_absent_from_evidence_and_original"]) for x in r) == 28


# ── audit (D28) ───────────────────────────────────────────────────────────

def test_audit_sample(corpus):
    s = AU.sample_audit(corpus["alerts"], corpus["explanations"])
    assert s["per_class"] == {"DoS": 3, "DDoS": 3, "Port Scanning": 3, "Brute Force": 3, "benign-flow": 13}
    assert len(s["primary"]) == 25 and "A999" not in s["primary"] and s["reliability"] == s["retest"] == []
    assert s == AU.sample_audit(corpus["alerts"], corpus["explanations"])
    assert s["primary"] != AU.sample_audit(corpus["alerts"], corpus["explanations"], seed=7)["primary"]
    with pytest.raises(ValueError, match="Brute Force"):
        AU.sample_audit(corpus["alerts"], corpus["explanations"], per_class={"Brute Force": 5})


def test_audit_export_is_blind_with_a_primary_sheet_only(corpus, tmp_path):
    out = AU.export_audit(corpus, tmp_path / "ann", unfrozen_ok=True)
    assert sorted(p.name for p in (out / "sheets").iterdir()) == ["primary.csv", "primary.html"]
    key = json.loads((out / "key.json").read_text(encoding="utf-8"))
    assert key["sheets"]["primary"]["n_explanations"] == 25 and set(key["sheets"]) == {"primary"}
    text = (out / "sheets" / "primary.csv").read_text(encoding="utf-8-sig") + (out / "README.txt").read_text()
    for leak in ("Normal Traffic", "DoS", "Brute Force", "Port Scanning", "benign", "attack-flow", "A0"):
        assert leak not in text
    assert "retest" not in (out / "README.txt").read_text()


def fill_sheet(out, tmp_path, rule):
    rows = list(csv.DictReader((out / "sheets" / "primary.csv").read_text(encoding="utf-8-sig").splitlines()))
    rows = [{**r, **{c: "" for c in AN.ANNOTATION_COLUMNS}, **rule(r)} for r in rows]
    path = tmp_path / "filled.csv"
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=AN.SHEET_COLUMNS)
        w.writeheader()
        w.writerows(rows)
    key = json.loads((out / "key.json").read_text(encoding="utf-8"))
    return AN.import_sheet(path, key, "primary", "me")["labels"]


AGREE = {T1_HEDGED: ("attack_technique", "yes"), T1_PLAIN: ("threat_actor", "no"), UNIT_WRONG: ("unit_wrong", "no"),
         PORT_WRONG: ("port_not_in_evidence", "no"), T2_PORT: ("port", "no")}


def human_agrees(r):
    if r["sentence"] in AGREE:
        sub, hedged = AGREE[r["sentence"]]
        return {"label": "hallucinated", "subtype": sub, "hedged": hedged}
    return {"label": "grounded"}


def test_audit_metrics_perfect_agreement(corpus, tmp_path):
    gold = fill_sheet(AU.export_audit(corpus, tmp_path / "ann", unfrozen_ok=True), tmp_path, human_agrees)
    res = AU.audit_metrics(gold, corpus, n_boot=200)
    for r in res["metrics"]:
        if r["human_positive"]:
            assert r["precision"] == r["recall"] == r["f1"] == 1.0, r
    assert res["disagreements"] == [] and res["n_explanations"] == 25


def test_audit_metrics_with_hand_counted_errors(corpus, tmp_path):
    def human(r):                     # the human also flags SOFT (rules: not flagged) and clears T1_HEDGED
        if r["sentence"] == SOFT:
            return {"label": "hallucinated", "subtype": "hard_certainty", "hedged": "no"}
        if r["sentence"] == T1_HEDGED:
            return {"label": "grounded"}
        return human_agrees(r)
    gold = fill_sheet(AU.export_audit(corpus, tmp_path / "ann", unfrozen_ok=True), tmp_path, human)
    res = AU.audit_metrics(gold, corpus, n_boot=200)
    row = next(r for r in res["metrics"] if (r["policy"], r["level"], r["group"]) == ("strict", "sentence", "all"))
    # 12 attack explanations: T1_HEDGED (rules +, human -) = 12 FP; UNIT_WRONG agree = 12 TP.
    # 13 benign: plan k odd -> T2_PORT agree (TP), SOFT (rules -, human +) FN; k even -> T1_PLAIN, PORT_WRONG TP.
    n_odd = sum(1 for g in gold if g.subtype == "port")
    n_even = 13 - n_odd
    assert (row["tp"], row["fp"], row["fn"]) == (12 + n_odd + 2 * n_even, 12, n_odd)
    assert row["precision"] == pytest.approx(row["tp"] / (row["tp"] + 12))
    assert row["precision_ci95"][0] <= row["precision"] <= row["precision_ci95"][1]
    kinds = {d["kind"] for d in res["disagreements"]}
    assert kinds == {"rules only (FP)", "missed by rules (FN)"}
    out = AU.write_audit(res, tmp_path / "audit")
    assert read_csv(out / "audit_metrics.csv") and read_csv(out / "audit_disagreements.csv")
    with pytest.raises(FileExistsError):
        AU.write_audit(res, tmp_path / "audit")


# ── the command line, end to end ──────────────────────────────────────────

def test_cli_corpus_study(tmp_path, monkeypatch, capsys):
    from test_run_infrastructure import BASE, _to_toml
    corpus_dir = make_corpus(tmp_path / "old_run")
    monkeypatch.setattr(CO, "RESULTS_DIR", tmp_path / "results")
    toml = tmp_path / "cfg.toml"
    toml.write_text(_to_toml(BASE, tmp_path), encoding="utf-8")
    c = ["--config", str(toml), "--corpus-dir", str(corpus_dir)]
    cid = CO.corpus_fingerprint(corpus_dir)["corpus_id"]

    assert cli.main(["audit_export", "--unfrozen", *c]) == 0
    sheet_dir = tmp_path / "annotation" / cid
    gold_rows = fill_sheet(sheet_dir, tmp_path, human_agrees)
    assert gold_rows
    assert cli.main(["annotation_import", cid, str(tmp_path / "filled.csv"), "--sheet", "primary",
                     "--annotator", "me", "--config", str(toml)]) == 0
    labels = sheet_dir / "imported" / "primary_me.json"
    assert cli.main(["audit_metrics", cid, str(labels), *c]) == 1               # analyze_corpus not run yet
    assert cli.main(["analyze_corpus", *c]) == 0
    assert "LLM calls: 0" in capsys.readouterr().out
    assert cli.main(["analyze_corpus", *c]) == 1                                # never overwritten
    assert cli.main(["audit_metrics", cid, str(labels), *c]) == 0
    assert "precision" in capsys.readouterr().out
    assert (tmp_path / "results" / cid / "audit" / "audit_metrics.csv").exists()

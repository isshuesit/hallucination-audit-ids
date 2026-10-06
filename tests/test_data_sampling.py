"""M1: stratified attack-only sampling, label hygiene, column checks, benign control arm."""

import json
import os
import sys

import pandas as pd
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fakes import FakeGemini, make_cicids_csv
from hallucination_pipeline.data_loader import REQUIRED_COLUMNS, MissingColumnsError, load_cicids
from hallucination_pipeline.run import execute_run
from hallucination_pipeline.sampling import (LabelHygieneError, assert_distribution, build_samples,
                                             coarse_label, normalize_label)
from test_run_infrastructure import make_cfg

# Both benign spellings, classes above and below a cap of 5.
LABELS_A = {"BENIGN": 40, "DoS Hulk": 12, "PortScan": 9, "SSH-Patator": 3, "Heartbleed": 2}
LABELS_B = {"Normal Traffic": 25, "DDoS": 7, "Bot": 5, "Web Attack – Sql Injection": 4}
CAP = 5


@pytest.fixture
def raw_dir(tmp_path):
    d = tmp_path / "raw"
    d.mkdir()
    make_cicids_csv(d / "a.csv", LABELS_A, seed=1)
    make_cicids_csv(d / "b.csv", LABELS_B, seed=2)
    return d


def samples(raw_dir, cap=CAP, seed=42, benign_n=10):
    df, _ = load_cicids(raw_dir)
    return build_samples(df, cap, seed, benign_n, run_id="r")


# ── labels ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("fine,coarse", [
    ("BENIGN", "Benign"), ("Normal Traffic", "Benign"), ("DDoS", "DDoS"), ("DoS Hulk", "DoS"),
    ("DoS slowloris", "DoS"), ("PortScan", "Port Scanning"), ("FTP-Patator", "Brute Force"),
    ("SSH-Patator", "Brute Force"), ("Web Attack \x96 Brute Force", "Web Attack"),
    ("Web Attack � XSS", "Web Attack"), ("Bot", "Botnet"), ("Infiltration", "Infiltration"),
    ("Heartbleed", "Heartbleed"),
])
def test_every_cicids_2017_label_has_a_coarse_class(fine, coarse):
    assert coarse_label(fine) == coarse


def test_unknown_label_stops_sampling():
    with pytest.raises(LabelHygieneError, match="Unknown"):
        coarse_label("Exfiltration")
    df = pd.DataFrame({"Label": ["DDoS", "Mystery"], "source_row": [0, 1]})
    with pytest.raises(LabelHygieneError, match="Mystery"):
        build_samples(df, 5, 42, 0, "r")


def test_dash_variants_are_normalised():
    for raw in ("Web Attack \x96 Brute Force", "Web Attack � Brute Force", "Web Attack – Brute Force",
                " Web Attack  -  Brute Force "):
        assert normalize_label(raw) == "Web Attack - Brute Force"


# ── sampling ──────────────────────────────────────────────────────────────

def test_sample_is_attack_only_and_capped_per_class(raw_dir):
    attacks, benign, dist = samples(raw_dir)
    assert dist["realized_fine"] == {"Bot": 5, "DDoS": 5, "DoS Hulk": 5, "Heartbleed": 2, "PortScan": 5,
                                     "SSH-Patator": 3, "Web Attack - Sql Injection": 4}
    assert dist["total_attack_alerts"] == len(attacks) == 29
    assert {k: v["rows"] for k, v in dist["benign"].items()} == {"BENIGN": 40, "Normal Traffic": 25}
    assert not {a["label_fine"] for a in attacks} & {"BENIGN", "Normal Traffic"}
    assert dist["classes_below_cap"] == {"Heartbleed": 2, "SSH-Patator": 3, "Web Attack - Sql Injection": 4}
    assert dist["realized_coarse"] == {"Botnet": 5, "Brute Force": 3, "DDoS": 5, "DoS": 5, "Heartbleed": 2,
                                       "Port Scanning": 5, "Web Attack": 4}
    assert [a["alert_id"] for a in attacks[:2]] == ["A0001", "A0002"]


def test_alert_evidence_never_contains_the_label(raw_dir):
    attacks, benign, _ = samples(raw_dir)
    for a in attacks + benign:
        assert a["evidence"] and a["source_file"] in {"a.csv", "b.csv"} and a["source_row"] >= 0
        for word in ("attack", "benign", "normal", "dos", "patator", "portscan", "bot", "heartbleed"):
            assert word not in a["evidence"].lower()


def test_sampling_is_deterministic_and_seed_dependent(raw_dir):
    rows = lambda s: [(a["source_file"], a["source_row"]) for a in samples(raw_dir, seed=s)[0]]
    assert rows(42) == rows(42)
    assert rows(42) != rows(7)


def test_one_class_does_not_change_another_class_sample(tmp_path, raw_dir):
    other = tmp_path / "raw2"
    other.mkdir()
    make_cicids_csv(other / "a.csv", LABELS_A, seed=1)
    make_cicids_csv(other / "b.csv", {**LABELS_B, "DDoS": 30}, seed=2)   # more DDoS rows than before
    pick = lambda d, lab: [a["source_row"] for a in samples(d)[0] if a["label_fine"] == lab and a["source_file"] == "a.csv"]
    assert pick(raw_dir, "DoS Hulk") == pick(other, "DoS Hulk")


def test_benign_control_is_separate_and_benign_only(raw_dir):
    attacks, benign, dist = samples(raw_dir, benign_n=10)
    assert len(benign) == 10 and dist["benign_control"] == {"requested": 10, "realized": 10}
    assert {b["label_coarse"] for b in benign} == {"Benign"} and {b["arm"] for b in benign} == {"benign_control"}
    assert all(b["alert_id"].startswith("B") for b in benign) and all(a["alert_id"].startswith("A") for a in attacks)
    # all there is: 65 benign rows minus the 4 with NaN/inf evidence the fixture plants (D12)
    assert samples(raw_dir, benign_n=1000)[2]["benign_control"]["realized"] == 61


def test_distribution_assertion_catches_violations(raw_dir):
    attacks, benign, dist = samples(raw_dir)
    leaked = attacks + [{**benign[0], "alert_id": "A9999"}]
    with pytest.raises(LabelHygieneError, match="benign label"):
        assert_distribution(dist, leaked, benign)
    short = json.loads(json.dumps(dist))
    short["realized_fine"]["DDoS"] = 4
    with pytest.raises(LabelHygieneError, match="DDoS: realized 4"):
        assert_distribution(short, attacks, benign)


# ── eligibility: D11 duplicates, D12 non-finite evidence ─────────────────

def flows(rows):
    """rows: list of (label, port, duration, bytes_per_s). Other evidence fields fixed."""
    df = pd.DataFrame([{"Destination Port": p, "Flow Duration": dur, "Total Fwd Packets": 3,
                        "Total Backward Packets": 1, "Flow Bytes/s": bps, "Flow Packets/s": 2.5,
                        "SYN Flag Count": 1, "ACK Flag Count": 0, "RST Flag Count": 0, "Label": lab}
                       for lab, p, dur, bps in rows])
    df["source_file"], df["source_row"] = "x.csv", range(len(df))
    return df


def test_d11_exact_duplicates_removed_within_each_attack_class_only():
    df = flows([("PortScan", 80, 5, 1.0)] * 4                  # 4 identical -> 1
               + [("PortScan", 81, 5, 1.0), ("PortScan", 80, 5, 1.5)]   # differ in one field -> kept
               + [("DDoS", 80, 5, 1.0)] * 2                      # same values, other class -> kept once
               + [("BENIGN", 80, 5, 1.0)] * 3)                   # benign is not de-duplicated
    attacks, benign, dist = build_samples(df, 30, 42, 10, "r")
    pc = dist["attack_classes"]["PortScan"]
    assert (pc["rows"], pc["dropped_duplicate"], pc["eligible"], pc["sampled"]) == (6, 3, 3, 3)
    assert dist["attack_classes"]["DDoS"]["sampled"] == 1
    assert [a["source_row"] for a in attacks if a["label_fine"] == "PortScan"] == [0, 4, 5]   # first kept
    assert len(benign) == 3 and dist["attack_totals"]["dropped_duplicate"] == 4


def test_d12_rows_with_missing_or_infinite_evidence_are_never_sampled():
    df = flows([("Bot", 80, 5, float("nan")), ("Bot", 80, 6, float("inf")), ("Bot", 80, 7, -float("inf")),
                ("Bot", 80, 8, 2.0), ("BENIGN", 80, 9, float("nan")), ("BENIGN", 80, 9, 3.0)])
    df.loc[3, "Flow Duration"] = None          # missing value in an integer column
    df = pd.concat([df, flows([("Bot", 80, 10, 2.0)])], ignore_index=True)
    attacks, benign, dist = build_samples(df, 30, 42, 10, "r")
    bot = dist["attack_classes"]["Bot"]
    assert (bot["rows"], bot["dropped_nonfinite"], bot["eligible"]) == (5, 4, 1)
    assert dist["benign"]["BENIGN"]["dropped_nonfinite"] == 1 and len(benign) == 1
    for a in attacks + benign:
        assert len(a["evidence"].splitlines()) == 9


def test_filters_give_the_same_rows_in_either_order():
    df = flows([("SSH-Patator", 22, 5, float("nan"))] * 2 + [("SSH-Patator", 22, 5, 1.0)] * 3
               + [("SSH-Patator", 22, 6, 1.0)])
    from hallucination_pipeline.sampling import finite_evidence_mask
    from hallucination_pipeline.data_loader import EVIDENCE_COLUMNS
    keys = [*EVIDENCE_COLUMNS, "Label"]
    a = df[finite_evidence_mask(df)].drop_duplicates(subset=keys)
    b = df.drop_duplicates(subset=keys)
    b = b[finite_evidence_mask(b)]
    assert list(a["source_row"]) == list(b["source_row"]) == [2, 5]


# ── loading ───────────────────────────────────────────────────────────────

def test_real_unb_replacement_character_labels_stay_one_class_each(tmp_path):
    # The UNB MachineLearningCSV Thursday file is valid UTF-8 and literally contains U+FFFD.
    d = tmp_path / "raw"
    d.mkdir()
    make_cicids_csv(d / "thursday.csv", {"BENIGN": 3, "Web Attack � Brute Force": 4,
                                         "Web Attack � XSS": 3, "Web Attack � Sql Injection": 2}, seed=3)
    assert "�".encode("utf-8") in (d / "thursday.csv").read_bytes()
    df, fingerprint = load_cicids(d)
    assert fingerprint["files"][0]["encoding"] == "utf-8"
    assert not df["Label"].str.contains("�").any()
    _, _, dist = build_samples(df, CAP, 42, 0, "r")
    assert dist["realized_fine"] == {"Web Attack - Brute Force": 4, "Web Attack - Sql Injection": 2,
                                     "Web Attack - XSS": 3}
    assert set(dist["realized_coarse"]) == {"Web Attack"}


def test_cp1252_fallback_for_the_raw_0x96_byte(tmp_path):
    d = tmp_path / "raw"
    d.mkdir()
    make_cicids_csv(d / "thursday.csv", {"BENIGN": 3, "WEBATTACKPLACEHOLDER": 4}, seed=3)
    path = d / "thursday.csv"
    # The real Thursday file stores the dash as the single cp1252 byte 0x96 (invalid UTF-8).
    path.write_bytes(path.read_bytes().replace(b"WEBATTACKPLACEHOLDER", b"Web Attack \x96 Brute Force"))
    df, fingerprint = load_cicids(d)
    assert fingerprint["files"][0]["encoding"] == "cp1252"
    _, _, dist = build_samples(df, CAP, 42, 0, "r")
    assert dist["realized_fine"] == {"Web Attack - Brute Force": 4}


def test_missing_columns_stop_with_a_clear_error(tmp_path):
    d = tmp_path / "raw"
    d.mkdir()
    make_cicids_csv(d / "good.csv", {"DDoS": 3})
    make_cicids_csv(d / "bad.csv", {"DDoS": 3}, drop_columns=["Flow Bytes/s", "RST Flag Count"])
    with pytest.raises(MissingColumnsError) as err:
        load_cicids(d)
    msg = str(err.value)
    assert "bad.csv: missing Flow Bytes/s, RST Flag Count" in msg and "good.csv" not in msg
    assert "Required columns: " + ", ".join(REQUIRED_COLUMNS) in msg


def test_processed_attack_type_copy_is_rejected(tmp_path):
    # D1: the processed copy has 'Attack Type' instead of 'Label'. It must be refused, not guessed at.
    d = tmp_path / "raw"
    d.mkdir()
    make_cicids_csv(d / "processed.csv", {"Normal Traffic": 3})
    df = pd.read_csv(d / "processed.csv").rename(columns={" Label": "Attack Type"})
    df.to_csv(d / "processed.csv", index=False)
    with pytest.raises(MissingColumnsError, match="missing Label"):
        load_cicids(d)


def test_padded_column_names_are_accepted_and_extra_columns_dropped(raw_dir):
    df, fingerprint = load_cicids(raw_dir)
    assert set(df.columns) == set(REQUIRED_COLUMNS) | {"source_file", "source_row"}
    assert [f["rows"] for f in fingerprint["files"]] == [sum(LABELS_A.values()), sum(LABELS_B.values())]


def test_no_csvs_is_a_clear_error(tmp_path):
    with pytest.raises(FileNotFoundError, match="No CSV files"):
        load_cicids(tmp_path)


# ── run level ─────────────────────────────────────────────────────────────

def test_run_writes_asserted_distribution_and_keeps_benign_control_apart(tmp_path, raw_dir):
    cfg = make_cfg(tmp_path, data={"per_class_cap": CAP, "benign_control_n": 6})
    run_dir = execute_run(cfg, client=FakeGemini(), sleep=False)
    dist = json.loads((run_dir / "class_distribution.json").read_text(encoding="utf-8"))
    assert dist["total_attack_alerts"] == 29 and dist["benign_control"]["realized"] == 6
    assert dist["fine_to_coarse"]["Normal Traffic"] == "Benign"
    attack_ids = {e["alert_id"] for e in json.loads((run_dir / "explanations.json").read_text(encoding="utf-8"))}
    benign_ids = {e["alert_id"] for e in
                  json.loads((run_dir / "benign_control" / "explanations.json").read_text(encoding="utf-8"))}
    assert len(attack_ids) == 29 and len(benign_ids) == 6 and not attack_ids & benign_ids
    m = json.loads((run_dir / "MANIFEST.json").read_text(encoding="utf-8"))
    assert m["counts"]["attack_realized_fine"] == dist["realized_fine"]
    assert m["dataset"]["total_rows"] == sum(LABELS_A.values()) + sum(LABELS_B.values())


def test_data_only_run_needs_no_llm_and_writes_p1_files(tmp_path, raw_dir):
    class NoLLM:
        @property
        def models(self):
            raise AssertionError("a data-only run must not touch the LLM")

    cfg = make_cfg(tmp_path, data={"per_class_cap": CAP})
    run_dir = execute_run(cfg, client=NoLLM(), data_only=True)
    m = json.loads((run_dir / "MANIFEST.json").read_text(encoding="utf-8"))
    assert m["stages"] == ["data"] and "skipped" in m["llm"]
    assert m["counts"]["attack"] == {"alerts": 29}
    assert (run_dir / "class_distribution.json").exists() and not (run_dir / "explanations.json").exists()


def test_p1_outbox_contains_exactly_the_handoff_files(tmp_path, raw_dir):
    import zipfile
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))
    from make_outbox import check_allowed, make_outbox

    run_dir = execute_run(make_cfg(tmp_path, data={"per_class_cap": CAP}), data_only=True, client=object())
    zpath = make_outbox("P1", run_dir, tmp_path / "outbox", "96 passed")
    with zipfile.ZipFile(zpath) as z:
        assert sorted(z.namelist()) == ["DECISIONS.md", "MANIFEST.json", "anomalies.md",
                                        "class_distribution.json", "test_summary.txt"]
    for bad in (".env", "data/raw/Monday.csv", "llm_cache/llm_cache.jsonl"):
        with pytest.raises(ValueError):
            check_allowed(bad)

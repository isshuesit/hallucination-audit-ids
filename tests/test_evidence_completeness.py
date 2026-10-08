"""tools/evidence_completeness.py: read-only counts of evidence lines and missing fields."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

import evidence_completeness as EC

FULL = "\n".join(f"{f}: 1" for f in EC.FIELDS)
NO_DURATION = "\n".join(f"{f}: 1" for f in EC.FIELDS if f != "Flow Duration")
SIX = "\n".join(f"{f}: 1" for f in EC.FIELDS if f not in ("Backward Packets", "SYN Flag Count", "RST Flag Count"))


def corpus():
    alerts = [{"alert_id": "A1", "alert_type": "DoS", "evidence": FULL},
              {"alert_id": "A2", "alert_type": "Normal Traffic", "evidence": SIX},
              {"alert_id": "A3", "alert_type": "Normal Traffic", "evidence": NO_DURATION},
              {"alert_id": "A4", "alert_type": "Normal Traffic", "evidence": FULL}]
    expl = [{"alert_id": "A1", "explanation": "Some text here."}, {"alert_id": "A2", "explanation": "More text."},
            {"alert_id": "A3", "explanation": "Even more text."},
            {"alert_id": "A4", "explanation": "[GENERATION FAILED]"}]          # not used by the analysis
    return alerts, expl


def test_counts_lines_missing_fields_and_flow_duration():
    r = EC.completeness(*corpus())
    assert r["explanations_used"] == 3
    a, n, t = r["groups"]["attack-flow"], r["groups"]["benign-flow"], r["groups"]["all"]
    assert (a["alerts"], n["alerts"], t["alerts"]) == (1, 2, 3)
    assert t["by_number_of_lines"] == {9: 1, 8: 1, 6: 1} and n["by_number_of_lines"] == {8: 1, 6: 1}
    assert n["missing_field_counts"]["Backward Packets"] == 1 and n["missing_field_counts"]["Flow Duration"] == 1
    assert a["missing_field_counts"] == {f: 0 for f in EC.FIELDS}
    assert (t["flow_duration_present"], n["flow_duration_present"]) == (2, 1)
    assert t["unrecognised_lines"] == 0
    assert t["mean_fields_present"] == (9 + 6 + 8) / 3 and n["mean_fields_present"] == 7.0
    # each of these four is missing once: a tie, so they keep the nine-field order
    assert EC.missing_ranked(t)[:4] == [("Flow Duration", 1), ("Backward Packets", 1), ("SYN Flag Count", 1),
                                        ("RST Flag Count", 1)]
    assert EC.missing_ranked(n)[0][1] == 1 and EC.missing_ranked(a)[0][1] == 0


def test_cli_prints_a_table_and_json(tmp_path, capsys):
    alerts, expl = corpus()
    (tmp_path / "alerts.json").write_text(json.dumps(alerts), encoding="utf-8")
    (tmp_path / "llm_explanations.json").write_text(json.dumps(expl), encoding="utf-8")
    assert EC.main(["--corpus-dir", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "3 explanations used" in out and "benign-flow" in out and "Flow Duration present" in out
    assert EC.main(["--corpus-dir", str(tmp_path), "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["explanations_used"] == 3


def test_writes_tables_into_a_new_folder_only(tmp_path):
    from hallucination_pipeline import corpus as CO
    out = EC.write_outputs(EC.completeness(*corpus()), tmp_path / "extra")
    names = sorted(p.name for p in out.iterdir())
    assert names == ["evidence_fields_distribution.csv", "evidence_fields_missing.csv", "evidence_fields_summary.csv",
                     "summary.md"]
    for name in names[:3]:
        lines = (out / name).read_text(encoding="utf-8").splitlines()
        assert lines[0] == f"# {CO.SOURCE}" and "D34" in lines[1]
    summary = (out / "evidence_fields_summary.csv").read_text(encoding="utf-8").splitlines()
    assert "benign-flow,2,7.0000,1" in summary
    import pytest
    with pytest.raises(FileExistsError):
        EC.write_outputs(EC.completeness(*corpus()), tmp_path / "extra")

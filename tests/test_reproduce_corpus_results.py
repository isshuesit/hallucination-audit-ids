"""tools/reproduce_corpus_results.py: re-runs analysis, final labels and evidence tables; detects any change."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

import ai_labelling as AL
import evidence_completeness as EC
import reproduce_corpus_results as RC
from hallucination_pipeline import corpus as CO
from test_ai_labelling import adjudicate, disagreeing, fill_manifest, setup, truthful, write_replies  # noqa: F401


def test_reproduction_matches_and_detects_a_change(setup, tmp_path):
    s = setup
    write_replies(s, "gemini", truthful)
    write_replies(s, "gpt", disagreeing)
    AL.ai_import(s["ann"], s["cid"], "gemini")
    AL.ai_import(s["ann"], s["cid"], "gpt")
    AL.ai_compare(s["ann"], s["cid"], "gemini", "gpt")
    fill_manifest(s)
    results = s["tmp"] / "results"
    CO.write_results(s["corpus"], results)
    adjudicate(s, truthful)
    AL.ai_finalize(s["ann"], s["cid"], "gemini", "gpt", "IS", s["corpus_dir"], results_dir=results)
    load = lambda n: json.loads((s["corpus_dir"] / n).read_text(encoding="utf-8"))
    EC.write_outputs(EC.completeness(load("alerts.json"), load("llm_explanations.json")), results / f"{s['cid']}_extra")

    problems, info = RC.reproduce(s["corpus_dir"], s["ann"], results, tmp_path / "work")
    assert problems == [] and info["corpus_id"] == s["cid"] and "author-adjudicated" in info["labels"]

    table = results / s["cid"] / "tables" / "prevalence.csv"
    table.write_text(table.read_text(encoding="utf-8") + "tampered\n", encoding="utf-8")
    (results / s["cid"] / "audit_ai" / "audit_metrics.csv").unlink()
    problems, _ = RC.reproduce(s["corpus_dir"], s["ann"], results, tmp_path / "work2")
    assert "analysis: differs: tables/prevalence.csv" in problems
    assert "audit_ai: only in the re-run: audit_metrics.csv" in problems

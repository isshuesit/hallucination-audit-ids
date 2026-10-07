"""M3b pilot stage: pilot config, detection C0-C3 x policies, sentence stage, dry run, call limit, report."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fakes import FakeGemini, make_cicids_csv
from hallucination_pipeline import cli
from hallucination_pipeline import policy as POL
from hallucination_pipeline import run as RUN
from hallucination_pipeline.detection import split_sentences
from hallucination_pipeline.llm_client import LLMCache
from hallucination_pipeline.pilot_report import build_report, format_report, problem_kind, write_samples
from hallucination_pipeline.run_config import load_run_config
from test_run_infrastructure import _to_toml, calls, cfg, make_cfg  # noqa: F401  (cfg is a fixture)

LOAD = lambda d, n: json.loads((d / n).read_text(encoding="utf-8"))


@pytest.fixture
def run(cfg):
    fake = FakeGemini()
    return RUN.execute_run(cfg, client=fake, sleep=False), cfg, fake


# ── config ────────────────────────────────────────────────────────────────

def test_pilot_config():
    pilot, fresh = load_run_config("configs/pilot.toml"), load_run_config()
    assert (pilot.name, pilot.per_class_cap, pilot.benign_control_n, pilot.max_calls) == ("pilot", 3, 6, 1500)
    assert pilot.generation_params == fresh.generation_params == {"temperature": 0.0,
                                                                   "thinking_config": {"thinking_budget": 0}}
    assert pilot.escalate_clean == "all" and fresh.max_calls is None
    for section in ("generation", "detection", "mitigation"):
        assert pilot.raw[section] == fresh.raw[section]
    assert pilot.cache_dir != fresh.cache_dir                     # pilot answers never reach the real run
    assert pilot.run_id != fresh.run_id


# ── detection stage ───────────────────────────────────────────────────────

def test_detection_covers_every_explanation_config_and_policy(run):
    run_dir, cfg, _ = run
    for prefix in ("", "benign_control/"):
        expl = [e for e in LOAD(run_dir, prefix + "explanations.json") if e["status"] == "ok"]
        det = LOAD(run_dir, prefix + "detection.json")
        assert len(det) == len(expl) * 4 * 2
        assert {(r["config"], r["policy"]) for r in det} == {(c, p) for c in ("C0", "C1", "C2", "C3")
                                                              for p in ("strict", "lenient")}
        for r in det:
            opts = POL.detection_options(r["config"], r["policy"])
            assert (r["use_tier2_rules"], r["judge_prompt"]) == (opts["use_tier2_rules"], opts["judge_prompt"])
            assert r["escalate_clean"] == "all" and r["rules_version"] == "1.0.0"
            assert r["policy_version"] == POL.POLICY_VERSION
            judge_files = POL.judge_prompt_files(opts["judge_prompt"])
            assert set(r["prompt_hashes"]) == {"generate_system.txt", *judge_files}
            assert all({"subtype", "tier", "hedged"} <= set(h) for h in r["rule_hits"])
            counted = [h for h in r["rule_hits"] if POL.counts_as_hallucination(h["tier"], r["policy"])]
            # D15: every explanation without a counted rule hit (clean or soft certainty) goes to the judge
            assert (r["detection_method"] == "rule") == bool(counted)
            if r["detection_method"] != "rule":
                assert r["judge"]["prompt"] == opts["judge_prompt"] and "reply_problems" in r["judge"]
                if r["judge"]["prompt"] != "v1" and r["judge"]["reply"] is not None:
                    assert {"tier", "subtype", "note"} <= set(r["judge"])


def test_c0_and_c1_judge_is_the_same_under_both_policies(run):
    run_dir, _, _ = run
    det = LOAD(run_dir, "detection.json")
    c0 = {(r["alert_id"], r["policy"]): r for r in det if r["config"] == "C0"}
    for (aid, policy), r in c0.items():
        if policy == "strict":   # Tier 1 rules only: both policies see the same hits and the same judge
            other = c0[(aid, "lenient")]
            assert (r["contains_hallucination"], r["detection_method"]) == \
                   (other["contains_hallucination"], other["detection_method"])


def test_at_most_three_judge_calls_per_explanation(run):
    run_dir, _, fake = run
    m = LOAD(run_dir, "MANIFEST.json")
    n_expl = m["counts"]["attack"]["explanations_ok"] + m["counts"]["benign_control"]["explanations_ok"]
    assert 0 < m["llm"]["per_stage"]["detect"]["api_calls"] <= 3 * n_expl
    assert m["llm"]["per_stage"]["detect"]["cache_hits"] > 0       # shared prompts are not called twice
    assert m["llm"]["api_calls"] == calls(fake)


# ── sentence stage ────────────────────────────────────────────────────────

def test_sentence_stage_judges_only_ambiguous_sentences(run):
    run_dir, cfg, _ = run
    alerts = {a["alert_id"]: a for a in LOAD(run_dir, "alerts.json")}
    expl = [e for e in LOAD(run_dir, "explanations.json") if e["status"] == "ok"]
    sent = LOAD(run_dir, "sentences.json")
    assert len(sent) == sum(len(split_sentences(e["explanation"])) for e in expl) * 2 * 2   # 2 styles x 2 policies
    for r in sent:
        tok = {str(t).lower() for t in alerts[r["alert_id"]]["evidence_tokens"]}
        rules = POL.classify_sentence_rules(r["sentence_text"], tok,
                                            POL.flow_duration_from_evidence(alerts[r["alert_id"]]["evidence"]))
        ambiguous = POL.sentence_policy_decision(rules, r["sentence_text"], r["policy"])["label"] == "ambiguous"
        assert r["judge_called"] == ambiguous
        assert r["sentence_prompt"] == ("v1" if r["style"] == "v1" else f"v2-{r['policy']}")
        if r["judge_called"]:
            assert r["judge"]["prompt"] == r["sentence_prompt"]
        assert {"rule_hits", "subtypes", "hedged", "policy_version", "rules_version"} <= set(r)
    assert any(r["judge_called"] for r in sent)


# ── dry run ───────────────────────────────────────────────────────────────

def test_dry_run_makes_no_call_needs_no_key_and_writes_nothing(cfg, monkeypatch):
    def no_key():
        raise AssertionError("a dry run must not create a real client")
    monkeypatch.setattr(RUN, "get_client", no_key)
    d = RUN.dry_run(cfg)
    assert d["per_stage"]["generate"]["would_call"] == d["alerts"] == 13 and d["not_yet_generated"] == 13
    assert d["per_stage"]["detect"]["would_call"] == 0 and d["detect_upper_bound_for_those"] == 13 * 3
    assert d["distinct_judge_prompts"] == ["v1", "v2-lenient", "v2-strict"]
    assert not (cfg.runs_dir / cfg.run_id).exists()
    assert not (cfg.cache_dir / RUN.CACHE_FILE).exists()
    assert "would call" in RUN.format_dry_run(d)


def test_dry_run_counts_exactly_once_explanations_are_cached(run, monkeypatch):
    run_dir, cfg, _ = run
    assert RUN.dry_run(cfg)["exact_total"] == 0                     # everything cached
    cache_path = cfg.cache_dir / RUN.CACHE_FILE
    entries = [json.loads(line) for line in cache_path.read_text(encoding="utf-8").splitlines()]
    gen_only = [e for e in entries if "Explain what this network flow data indicates" in e["prompt"]]
    cache_path.write_text("".join(json.dumps(e) + "\n" for e in gen_only), encoding="utf-8")
    d = RUN.dry_run(cfg)
    m = LOAD(run_dir, "MANIFEST.json")
    assert d["per_stage"]["generate"]["would_call"] == 0 and d["not_yet_generated"] == 0
    assert d["per_stage"]["detect"]["would_call"] == m["llm"]["per_stage"]["detect"]["api_calls"]
    assert d["per_stage"]["sentences"]["would_call"] == m["llm"]["per_stage"]["sentences"]["api_calls"]


# ── call limit ────────────────────────────────────────────────────────────

def test_max_calls_stops_the_run_cleanly_and_a_rerun_continues(tmp_path):
    (tmp_path / "raw").mkdir()
    make_cicids_csv(tmp_path / "raw" / "a.csv", {"BENIGN": 12, "DoS Hulk": 5, "PortScan": 4}, seed=1)
    limited = make_cfg(tmp_path, run={"max_calls": 5})
    fake = FakeGemini()
    run_dir = RUN.execute_run(limited, client=fake, sleep=False, run_id="limited")
    m = LOAD(run_dir, "MANIFEST.json")
    assert calls(fake) == 5 and m["llm"]["status"].startswith("stopped") and m["stages"] == ["data"]
    assert "RUN STOPPED" in (run_dir / "anomalies.md").read_text(encoding="utf-8")
    assert len(LLMCache(limited.cache_dir / RUN.CACHE_FILE).entries) == 5           # answers kept
    fake2 = FakeGemini()
    full = RUN.execute_run(make_cfg(tmp_path), client=fake2, sleep=False, run_id="limited")
    m2 = LOAD(full, "MANIFEST.json")
    assert m2["llm"]["status"] == "complete" and m2["llm"]["per_stage"]["generate"]["cache_hits"] == 5


# ── report ────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("reply,kind", [
    ({"contains_hallucination": True, "tier": 1, "subtype": "port_scan"}, "unknown subtype"),
    ({"contains_hallucination": True, "tier": 2, "subtype": "cve"}, "tier mismatch"),
    ({"contains_hallucination": True, "tier": 1, "subtype": "other_fabrication"}, "missing note"),
    ({"contains_hallucination": True, "tier": None, "subtype": None}, "verdict/tier inconsistent"),
    ({"contains_hallucination": "yes", "tier": None, "subtype": None}, "invalid verdict"),
])
def test_problem_kinds(reply, kind):
    assert problem_kind(POL.parse_v2_reply(reply, "explanation")["reply_problems"][0]) == kind
    assert problem_kind("bad JSON") == "bad JSON" and problem_kind("call failed") == "call failed"


def test_pilot_report(run):
    run_dir, cfg, _ = run
    rep = build_report(run_dir, seed=cfg.seed)
    text = format_report(rep)
    for needle in ("generate", "detect", "sentences", "TOTAL", "rate-limit", "Reply problems by kind",
                   "C3/lenient", "benign_control"):
        assert needle in text
    total_problems = sum(len(r["judge"]["reply_problems"]) for d in rep["data"].values()
                         for lvl in ("detect", "sentences") for r in d[lvl] if r.get("judge"))
    assert sum(rep["reply_problems"].values()) == total_problems > 0
    assert set(rep["flagged"]["attack"]) == {f"C{i}/{p}" for i in range(4) for p in ("strict", "lenient")}
    path = write_samples(run_dir, rep)
    md = path.read_text(encoding="utf-8")
    assert path.name == "pilot_judge_replies.md" and md.count("## ") == len(rep["samples"]) == 20
    assert md.count("Evidence:") == 20 and "judge v2-" in md and "judge v1" not in md


def test_cli_dry_run_and_pilot_report(cfg, tmp_path, capsys):
    toml = tmp_path / "cfg.toml"
    toml.write_text(_to_toml(cfg.raw, tmp_path), encoding="utf-8")
    assert cli.main(["run", "--dry-run", "--config", str(toml)]) == 0
    assert "DRY RUN" in capsys.readouterr().out and not (cfg.runs_dir / cfg.run_id).exists()
    RUN.execute_run(cfg, client=FakeGemini(), sleep=False)
    assert cli.main(["pilot_report", cfg.run_id, "--config", str(toml)]) == 0
    assert "PILOT REPORT" in capsys.readouterr().out

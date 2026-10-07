"""M0: run config, rule/prompt fingerprints, LLM cache, manifest, freezing."""

import json
import os
import stat
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fakes import FakeGemini, make_cicids_csv
from hallucination_pipeline import cli
from hallucination_pipeline.detection import patterns as P
from hallucination_pipeline.detection.version import (RULES_VERSION, rules_patterns_sha256,
                                                      rules_source_sha256)
from hallucination_pipeline.llm_client import CachedClient, LLMCache, cache_key
from hallucination_pipeline.policy import POLICY_VERSION
from hallucination_pipeline.prompt_store import prompt_hashes
from hallucination_pipeline.run import execute_run
from hallucination_pipeline.run_config import ConfigError, config_from_dict, load_run_config
from hallucination_pipeline.run_dir import FrozenRunError, freeze_run, verify_frozen, write_json

# ── pins ──────────────────────────────────────────────────────────────────

# RULES_VERSION -> (patterns sha256, source sha256). If you change a rule, this test fails:
# bump RULES_VERSION in detection/version.py and ADD a new line here (never edit an old one).
RULES_PINS = {
    "1.0.0": ("1d10799fee96d6fb918bc2242fc744d3ac424f3bdc13d10c9e545bc3690c98b0",
              "e2d2e17c8c786603aca128a0fb253360bb524aaf1dd4d57dacd13bd0f2cc22b8"),
}

# v1 prompts, byte-exact from the old run. They must never change; new wording = new *_v2.txt file.
V1_PROMPT_PINS = {
    "detect_explanation_system.txt": "a307be45d947448ecd9105421253937b74ce4f7f0ebdd16c85bde2799541d069",
    "detect_explanation_template.txt": "a3721214880d516a81e28e6e31612a19fc718176a9db5875ea3bc5e8d9d1f31a",
    "generate_system.txt": "5afc538ce83fccb6c9d0b8c01b394ddf95d76e7795d310ba209c7ef8bc8f2913",
    "localize_sentence_system.txt": "d7d5abda91a8fbf0af011740410f326ab6e44399ebf15e61f30d29ced6feb69a",
    "qualify_certainty.txt": "ed87237858ff7004957e21f9ff0e0a459868c959ed731cc59421eae7dbce78dd",
    "qualify_external_knowledge.txt": "8c67e372ec5a9dd28821a379024acce0fec5b3eff7efc73fb2f62f5f915d92ae",
    "qualify_reasoning.txt": "4a86f47cf1096083e74b84db6c9efd14392cf823a44dc8109dede5600792287f",
    "recheck_template.txt": "d03f377d02d5d1223d2d5613d5b03c9cde5f23a2e781ce6683ccbc7befd168da",
}

# ── helpers ───────────────────────────────────────────────────────────────

BASE = {
    "run": {"name": "test"},
    "data": {"per_class_cap": 3, "seed": 42, "benign_control_n": 2},
    "generation": {"model": "gemini-2.5-flash", "temperature": 0.0, "prompt": "generate_system.txt",
                   "thinking_budget": 0},
    "detection": {"configs": ["C0", "C1", "C2", "C3"], "policies": ["strict", "lenient"], "escalate_clean": "all"},
    "mitigation": {"arms": ["M0", "M-prompt", "M-auto", "M-auto+val", "M-gold"]},
    "paths": {"raw_dir": "raw", "runs_dir": "runs", "cache_dir": "cache"},
}


def make_cfg(tmp_path, **section_overrides):
    raw = json.loads(json.dumps(BASE))
    for section, values in section_overrides.items():
        raw[section].update(values)
    return config_from_dict(raw, base_dir=tmp_path)


@pytest.fixture
def cfg(tmp_path):
    (tmp_path / "raw").mkdir()
    make_cicids_csv(tmp_path / "raw" / "monday.csv", {"BENIGN": 12, "DoS Hulk": 5, "PortScan": 4}, seed=1)
    make_cicids_csv(tmp_path / "raw" / "friday.csv", {"BENIGN": 6, "DDoS": 4, "Bot": 2}, seed=2)
    return make_cfg(tmp_path)


def calls(fake: FakeGemini) -> int:
    return sum(fake.seen.values())


# ── config ────────────────────────────────────────────────────────────────

def test_project_config_loads_with_decided_values():
    cfg = load_run_config()
    assert (cfg.per_class_cap, cfg.seed, cfg.benign_control_n) == (30, 42, 60)       # D2, D9
    assert cfg.raw["detection"]["escalate_clean"] == "all"                              # D15
    assert cfg.model == "gemini-2.5-flash"
    assert cfg.generation_params == {"temperature": 0.0, "thinking_config": {"thinking_budget": 0}}  # D4, D13
    assert cfg.run_id == f"fresh-{cfg.config_hash[:8]}"


def test_config_hash_ignores_paths_but_not_settings(tmp_path):
    a = make_cfg(tmp_path)
    assert make_cfg(tmp_path, paths={"runs_dir": "elsewhere"}).run_id == a.run_id
    assert make_cfg(tmp_path, data={"seed": 43}).run_id != a.run_id
    assert make_cfg(tmp_path, generation={"temperature": 0.5}).run_id != a.run_id


@pytest.mark.parametrize("section,values,message", [
    ("data", {"per_class_cap": "30"}, "wrong type"),
    ("data", {"per_clas_cap": 30}, "Unknown key"),
    ("detection", {"policies": ["strict", "loose"]}, "policies"),
    ("detection", {"configs": ["C4"]}, "configs"),
    ("detection", {"escalate_clean": "attacks"}, "escalate_clean"),
    ("mitigation", {"arms": ["M-magic"]}, "arms"),
    ("generation", {"temperature": 3.0}, "temperature"),
    ("generation", {"thinking_budget": -1}, "thinking_budget"),
])
def test_config_rejects_bad_values(tmp_path, section, values, message):
    with pytest.raises(ConfigError, match=message):
        make_cfg(tmp_path, **{section: values})


def test_config_rejects_missing_section(tmp_path):
    raw = {k: v for k, v in BASE.items() if k != "mitigation"}
    with pytest.raises(ConfigError, match="mitigation"):
        config_from_dict(raw, base_dir=tmp_path)


# ── rule and prompt fingerprints ──────────────────────────────────────────

def test_rules_version_matches_pinned_fingerprints():
    assert RULES_VERSION in RULES_PINS, "new RULES_VERSION: add its fingerprints to RULES_PINS"
    assert (rules_patterns_sha256(), rules_source_sha256()) == RULES_PINS[RULES_VERSION], (
        "The rule engine changed. Bump RULES_VERSION and add a new RULES_PINS entry "
        "(and a DECISIONS.md entry if this happens after freeze-1)."
    )


def test_rules_fingerprint_sees_a_single_pattern_change(monkeypatch):
    before = rules_patterns_sha256()
    changed = list(P.FACTUAL_PATTERNS)
    pat, typ, desc = changed[0]
    changed[0] = (P.re.compile(pat.pattern + "|xyz", pat.flags), typ, desc)
    monkeypatch.setattr(P, "FACTUAL_PATTERNS", changed)
    assert rules_patterns_sha256() != before


def test_prompt_registry_covers_every_file_and_v1_prompts_are_unchanged():
    hashes = prompt_hashes()
    for name, digest in V1_PROMPT_PINS.items():
        assert hashes[name] == digest, f"{name} was edited in place; add a *_v2.txt file instead"
    assert set(V1_PROMPT_PINS) <= set(hashes)


# ── LLM cache ─────────────────────────────────────────────────────────────

def test_cache_answers_repeat_calls_without_the_api(tmp_path):
    fake = FakeGemini()
    client = CachedClient(fake, LLMCache(tmp_path / "c.jsonl"), {"temperature": 0.0})
    first = client.models.generate_content(model="m", contents="Evidence:\nDestination Port: 22\n")
    second = client.models.generate_content(model="m", contents="Evidence:\nDestination Port: 22\n")
    assert first.text == second.text and second.cache_hit and not first.cache_hit
    assert calls(fake) == 1 and client.stats()["cache_hits"] == 1
    assert client.stats()["model_versions_returned"] == ["fake-gemini-001"]
    assert client.stats()["tokens"]["total_token_count"] > 0

    # a new process (new cache object, new fake) still makes zero calls
    fake2 = FakeGemini()
    client2 = CachedClient(fake2, LLMCache(tmp_path / "c.jsonl"), {"temperature": 0.0})
    assert client2.models.generate_content(model="m", contents="Evidence:\nDestination Port: 22\n").text == first.text
    assert calls(fake2) == 0


def test_cache_key_includes_model_params_and_prompt():
    k = cache_key("m", {"temperature": 0.0}, "p")
    assert k != cache_key("m2", {"temperature": 0.0}, "p")
    assert k != cache_key("m", {"temperature": 0.7}, "p")
    assert k != cache_key("m", {"temperature": 0.0}, "p ")
    assert k == cache_key("m", {"temperature": 0.0}, "p")


def test_errors_are_not_cached(tmp_path):
    class Flaky:
        def __init__(self):
            self.models, self.n = self, 0

        def generate_content(self, model, contents, config=None):
            self.n += 1
            if self.n == 1:
                raise RuntimeError("503 service unavailable")
            return FakeGemini().models.generate_content(model=model, contents=contents)

    flaky = Flaky()
    client = CachedClient(flaky, LLMCache(tmp_path / "c.jsonl"))
    with pytest.raises(RuntimeError):
        client.models.generate_content(model="m", contents="x")
    assert client.models.generate_content(model="m", contents="x").text
    assert flaky.n == 2 and client.stats()["api_errors"] == 1


def test_cache_survives_a_line_cut_short_by_a_crash(tmp_path):
    path = tmp_path / "c.jsonl"
    client = CachedClient(FakeGemini(), LLMCache(path))
    client.models.generate_content(model="m", contents="a")
    with open(path, "a", encoding="utf-8") as f:
        f.write('{"key": "trunc')
    cache = LLMCache(path)
    assert cache.skipped_lines == 1 and len(cache.entries) == 1


# ── freezing ──────────────────────────────────────────────────────────────

def test_freeze_writes_checksums_and_refuses_later_writes(tmp_path):
    run = tmp_path / "run"
    write_json(run, "a.json", {"x": 1})
    write_json(run, "sub/b.json", [1, 2])
    freeze_run(run)
    sums = (run / "SHA256SUMS").read_text(encoding="utf-8").splitlines()
    assert [line.split("  ")[1] for line in sums] == ["a.json", "sub/b.json"]
    assert verify_frozen(run) == []
    with pytest.raises(FrozenRunError):
        write_json(run, "c.json", {})
    with pytest.raises(FrozenRunError):
        freeze_run(run)
    with pytest.raises(PermissionError):           # the OS refuses too: files are read-only
        open(run / "a.json", "w").close()


def test_verify_detects_a_tampered_frozen_run(tmp_path):
    run = tmp_path / "run"
    write_json(run, "a.json", {"x": 1})
    freeze_run(run)
    os.chmod(run / "a.json", stat.S_IWRITE | stat.S_IREAD)
    (run / "a.json").write_text('{"x": 2}')
    (run / "new.json").write_text("{}")
    assert verify_frozen(run) == ["added after freeze: new.json", "changed: a.json"]


# ── end to end with the fake LLM ──────────────────────────────────────────

def test_fake_run_writes_manifest_and_stamps_every_record(cfg):
    fake = FakeGemini()
    run_dir = execute_run(cfg, client=fake, sleep=False)
    assert run_dir.name == cfg.run_id
    m = json.loads((run_dir / "MANIFEST.json").read_text(encoding="utf-8"))

    assert m["run_id"] == cfg.run_id and m["config"]["hash"] == cfg.config_hash
    assert m["rules"]["rules_version"] == RULES_VERSION
    assert m["policy"]["policy_version"] == POLICY_VERSION and len(m["policy"]["tier_map_sha256"]) == 64   # D20
    assert m["prompts"]["generate_system.txt"] == V1_PROMPT_PINS["generate_system.txt"]
    assert [f["name"] for f in m["dataset"]["files"]] == ["friday.csv", "monday.csv"]
    assert m["dataset"]["total_rows"] == 33 and all(len(f["sha256"]) == 64 for f in m["dataset"]["files"])
    assert m["llm"]["api_calls"] == calls(fake) > 0 and m["llm"]["cache_hits"] == 0
    assert m["llm"]["model_versions_returned"] == ["fake-gemini-001"]
    assert m["llm"]["generation_params"] == {"temperature": 0.0, "thinking_config": {"thinking_budget": 0}}
    assert m["llm"]["enforced_params"] == {"thinking_config": {"thinking_budget": 0}}
    assert set(m["git"]) >= {"commit", "dirty"} and m["environment"]["python"]
    assert m["counts"]["attack"]["explanations_ok"] == m["counts"]["attack"]["alerts"] == 11   # cap 3: DoS Hulk 3, PortScan 3, DDoS 3, Bot 2
    assert m["counts"]["benign_control"]["explanations_ok"] == m["counts"]["benign_control"]["alerts"] == 2

    for name in ("explanations.json", "detection_rules.json",
                 "benign_control/explanations.json", "benign_control/detection_rules.json"):
        for rec in json.loads((run_dir / name).read_text(encoding="utf-8")):
            assert rec["run_id"] == cfg.run_id and rec["rules_version"] == RULES_VERSION
            assert rec["prompt_hashes"] == {"generate_system.txt": V1_PROMPT_PINS["generate_system.txt"]}


def test_second_run_of_the_same_config_makes_zero_api_calls(cfg):
    first = execute_run(cfg, client=FakeGemini(), sleep=False)
    fake = FakeGemini()
    second = execute_run(cfg, client=fake, run_id=cfg.run_id + "-rerun", sleep=False)
    assert calls(fake) == 0
    m = json.loads((second / "MANIFEST.json").read_text(encoding="utf-8"))
    assert m["llm"]["api_calls"] == 0
    assert m["llm"]["cache_hits"] == m["counts"]["attack"]["alerts"] + m["counts"]["benign_control"]["alerts"]
    texts = lambda d: [e["explanation"] for e in json.loads((d / "explanations.json").read_text(encoding="utf-8"))]
    assert texts(first) == texts(second)


def test_frozen_run_cannot_be_rerun_in_place(cfg):
    run_dir = execute_run(cfg, client=FakeGemini(), sleep=False)
    freeze_run(run_dir)
    with pytest.raises(FrozenRunError, match="new run_id"):
        execute_run(cfg, client=FakeGemini(), sleep=False)
    assert verify_frozen(run_dir) == []


def test_cli_freeze_and_verify(cfg, tmp_path, capsys):
    execute_run(cfg, client=FakeGemini(), sleep=False)
    toml = tmp_path / "cfg.toml"
    toml.write_text(_to_toml(cfg.raw, tmp_path), encoding="utf-8")
    assert cli.main(["freeze_run", cfg.run_id, "--config", str(toml)]) == 0
    assert cli.main(["verify_run", cfg.run_id, "--config", str(toml)]) == 0
    assert "OK:" in capsys.readouterr().out


def _to_toml(raw: dict, base) -> str:
    out = []
    for section, values in raw.items():
        out.append(f"[{section}]")
        for k, v in values.items():
            if section == "paths":
                v = str(base / v)
            out.append(f"{k} = {json.dumps(v)}")
    return "\n".join(out) + "\n"


def test_d13_thinking_budget_is_forced_on_every_call_and_recorded(tmp_path):
    seen = []

    class Recorder:
        def __init__(self):
            self.models = self

        def generate_content(self, model, contents, config=None):
            seen.append(config)
            return FakeGemini().models.generate_content(model=model, contents=contents)

    enforced = {"thinking_config": {"thinking_budget": 0}}
    client = CachedClient(Recorder(), LLMCache(tmp_path / "c.jsonl"), {"temperature": 0.0}, enforced)
    plain = client.models.generate_content(model="m", contents="generation prompt")
    # a caller asking for its own thinking budget (and a JSON response) still gets budget 0
    own = client.models.generate_content(model="m", contents="judge prompt",
                                         config={"thinking_config": {"thinking_budget": 512},
                                                 "response_mime_type": "application/json"})
    assert all(c["thinking_config"] == {"thinking_budget": 0} for c in seen)
    assert own.call_params == {"temperature": 0.0, "thinking_config": {"thinking_budget": 0},
                               "response_mime_type": "application/json"}
    assert plain.call_params["thinking_config"] == {"thinking_budget": 0}
    assert client.stats()["enforced_overrides"] == 1
    cached = LLMCache(tmp_path / "c.jsonl").entries.values()
    assert all(e["params"]["thinking_config"] == {"thinking_budget": 0} for e in cached)


def test_generation_records_carry_their_call_params(cfg):
    run_dir = execute_run(cfg, client=FakeGemini(), sleep=False)
    for rec in json.loads((run_dir / "explanations.json").read_text(encoding="utf-8")):
        assert rec["llm_params"] == {"temperature": 0.0, "thinking_config": {"thinking_budget": 0}}
        assert rec["tier_map_sha256"] and rec["policy_version"]

"""
Run orchestrator for the fresh, controlled run: config -> runs/<run_id>/.

Stages so far (later milestones add more):
  1. data      load + validate CSVs, stratified attack sample, -> alerts.json, class_distribution.json,
               separate benign control sample                    benign_control/alerts.json
  2. generate  explanations through the cached LLM client      -> explanations.json (+ benign_control/)
  3. detect    rule-based explanation-level detection          -> detection_rules.json (+ benign_control/)
  4. manifest                                                  -> MANIFEST.json, anomalies.md

The benign control arm (DECISIONS D9) goes through the same stages but lives in
benign_control/ so it can never be mixed into headline numbers.

Every record carries run_id, rules_version (+ fingerprints) and the hashes of the
prompts in its lineage. All LLM calls go through CachedClient, so re-running the
same config (under a new run_id) makes zero API calls.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from . import data_loader, sampling
from .detection import rule_based_detect_explanation
from .detection.version import rules_stamp
from .explanation_generator import build_prompt
from .llm_client import CachedClient, LLMCache, generate_text, get_client
from .manifest import build_manifest, utc_now
from .policy import policy_stamp
from .prompt_store import prompt_sha256
from .run_config import RunConfig
from .run_dir import ensure_writable, write_json, write_text

CACHE_FILE = "llm_cache.jsonl"


def stamp(run_id: str, prompt_names: list[str]) -> dict:
    """Provenance fields written to every record."""
    return {"run_id": run_id, **rules_stamp(), **policy_stamp(),
            "prompt_hashes": {n: prompt_sha256(n) for n in prompt_names}}


# ── stages ────────────────────────────────────────────────────────────────

def stage_data(cfg: RunConfig, run_id: str) -> tuple[list[dict], list[dict], dict, dict]:
    """Returns (attack alerts, benign control alerts, class distribution, dataset fingerprint)."""
    df, fingerprint = data_loader.load_cicids(cfg.raw_dir)
    attacks, benign, dist = sampling.build_samples(df, cfg.per_class_cap, cfg.seed, cfg.benign_control_n, run_id)
    return attacks, benign, dist, fingerprint


def stage_generate(cfg: RunConfig, run_id: str, client, alerts: list[dict], *,
                   sleep: bool, anomalies: list[str]) -> list[dict]:
    records = []
    for i, alert in enumerate(alerts):
        prompt = build_prompt(alert, cfg.generate_prompt)
        response, errors = generate_text(client, cfg.model, prompt, sleep=sleep)
        ok = response is not None
        if errors:
            anomalies.append(f"generate {alert['alert_id']}: {len(errors)} failed attempt(s)"
                             f"{'' if ok else ', GAVE UP'}: {errors[-1][:120]}")
        records.append({
            "alert_id": alert["alert_id"],
            "arm": alert["arm"],
            "alert_type": alert["alert_type"],
            "status": "ok" if ok else "failed",
            "explanation": response.text.strip() if ok else None,
            "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            "model_requested": cfg.model,
            "model_version": getattr(response, "model_version", None) if ok else None,
            "cache_hit": getattr(response, "cache_hit", None) if ok else None,
            "cache_key": getattr(response, "cache_key", None) if ok else None,
            "llm_params": getattr(response, "call_params", None) if ok else None,
            "failed_attempts": len(errors),
            **stamp(run_id, [cfg.generate_prompt]),
        })
        if (i + 1) % 25 == 0:
            print(f"  generated {i + 1}/{len(alerts)}")
    return records


def stage_detect_rules(cfg: RunConfig, run_id: str, alerts: list[dict], explanations: list[dict]) -> list[dict]:
    tokens = {a["alert_id"]: a["evidence_tokens"] for a in alerts}
    return [
        {"alert_id": e["alert_id"], "arm": e["arm"], "detector": "rules_only",
         **rule_based_detect_explanation(e["explanation"], tokens[e["alert_id"]]),
         **stamp(run_id, [cfg.generate_prompt])}
        for e in explanations if e["status"] == "ok"
    ]


# ── orchestration ─────────────────────────────────────────────────────────

def execute_run(cfg: RunConfig, *, client=None, run_id: str | None = None, sleep: bool = True,
                data_only: bool = False) -> Path:
    """Run every stage into runs/<run_id>/. Refuses to touch a frozen run.

    `client` defaults to the real Gemini client; tests pass tests/fakes.FakeGemini().
    `data_only` stops after sampling: no LLM calls, no API key needed (Pass-through P1).
    """
    run_id = run_id or cfg.run_id
    run_dir = cfg.runs_dir / run_id
    ensure_writable(run_dir)
    started_at = utc_now()
    anomalies: list[str] = []
    outputs: list[str] = []

    def save(name: str, obj) -> None:
        write_json(run_dir, name, obj)
        outputs.append(name)

    print(f"=== Run {run_id} -> {run_dir} ===")
    alerts, benign, distribution, dataset = stage_data(cfg, run_id)   # fails before anything is written
    save("config.json", {"run_id": run_id, "config_hash": cfg.config_hash, "config": cfg.raw})
    save("class_distribution.json", distribution)
    save("alerts.json", alerts)
    save("benign_control/alerts.json", benign)
    counts: dict = {"attack": {"alerts": len(alerts)}, "benign_control": {"alerts": len(benign)},
                    "attack_realized_fine": distribution["realized_fine"]}
    if data_only:
        return _finish(cfg, run_id, run_dir, started_at, ["data"], dataset,
                       {"skipped": "data-only run: no LLM calls"}, counts, outputs, anomalies)

    cache = LLMCache(cfg.cache_dir / CACHE_FILE)
    if cache.skipped_lines:
        anomalies.append(f"LLM cache: skipped {cache.skipped_lines} unreadable line(s)")
    cached = CachedClient(client if client is not None else get_client(), cache,
                          default_params=cfg.default_llm_params, enforced_params=cfg.enforced_llm_params)

    for arm, arm_alerts, prefix in (("attack", alerts, ""), ("benign_control", benign, "benign_control/")):
        explanations = stage_generate(cfg, run_id, cached, arm_alerts, sleep=sleep, anomalies=anomalies)
        save(f"{prefix}explanations.json", explanations)
        detections = stage_detect_rules(cfg, run_id, arm_alerts, explanations)
        save(f"{prefix}detection_rules.json", detections)
        counts[arm].update({
            "explanations_ok": sum(e["status"] == "ok" for e in explanations),
            "generation_failed": sum(e["status"] == "failed" for e in explanations),
            "rules_triggered": sum(d["triggered"] is True for d in detections),
            "rules_uncertain": sum(d["triggered"] is None for d in detections),
            "rules_clean": sum(d["triggered"] is False for d in detections),
        })
    llm = cached.stats()
    print(f"LLM: {llm['api_calls']} API call(s), {llm['cache_hits']} cache hit(s)")
    return _finish(cfg, run_id, run_dir, started_at, ["data", "generate", "detect_rules"], dataset,
                   llm, counts, outputs, anomalies)


def _finish(cfg: RunConfig, run_id: str, run_dir: Path, started_at: str, stages: list[str], dataset: dict,
            llm: dict, counts: dict, outputs: list[str], anomalies: list[str]) -> Path:
    write_text(run_dir, "anomalies.md", f"# Anomalies - run {run_id}\n\n"
               + ("\n".join(f"- {a}" for a in anomalies) if anomalies else "None recorded.") + "\n")
    outputs.append("anomalies.md")
    manifest = build_manifest(cfg, run_id, started_at=started_at, dataset=dataset,
                              llm=llm, counts=counts, outputs=sorted(outputs), stages=stages)
    write_json(run_dir, "MANIFEST.json", manifest)
    print(f"Wrote {run_dir / 'MANIFEST.json'}")
    return run_dir

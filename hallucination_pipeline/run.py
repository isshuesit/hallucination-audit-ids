"""
Run orchestrator for the fresh, controlled run: config -> runs/<run_id>/.

Stages so far (later milestones add more):
  1. data      load + validate CSVs, sample alerts            -> alerts.json
  2. generate  explanations through the cached LLM client      -> explanations.json
  3. detect    rule-based explanation-level detection          -> detection_rules.json
  4. manifest                                                  -> MANIFEST.json, anomalies.md

Every record carries run_id, rules_version (+ fingerprints) and the hashes of the
prompts in its lineage. All LLM calls go through CachedClient, so re-running the
same config (under a new run_id) makes zero API calls.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from . import config as legacy_config
from . import data_loader
from .detection import rule_based_detect_explanation
from .detection.version import rules_stamp
from .explanation_generator import build_prompt
from .llm_client import CachedClient, LLMCache, generate_text, get_client
from .manifest import build_manifest, utc_now
from .prompt_store import prompt_sha256
from .run_config import RunConfig
from .run_dir import ensure_writable, write_json, write_text

CACHE_FILE = "llm_cache.jsonl"


def stamp(run_id: str, prompt_names: list[str]) -> dict:
    """Provenance fields written to every record."""
    return {"run_id": run_id, **rules_stamp(), "prompt_hashes": {n: prompt_sha256(n) for n in prompt_names}}


# ── stages ────────────────────────────────────────────────────────────────

def stage_data(cfg: RunConfig, run_id: str) -> tuple[list[dict], dict, dict]:
    """Returns (alerts, dataset fingerprint, extra counts)."""
    df, fingerprint = data_loader.load_cicids(cfg.raw_dir)
    sampled = data_loader.sample_attack_alerts(df, target_count=legacy_config.TARGET_ALERT_COUNT, seed=cfg.seed)
    alerts = [{**data_loader.build_alert(i + 1, row), "run_id": run_id}
              for i, (_, row) in enumerate(sampled.iterrows())]
    return alerts, fingerprint, {"alerts": len(alerts)}


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
            "alert_type": alert["alert_type"],
            "status": "ok" if ok else "failed",
            "explanation": response.text.strip() if ok else None,
            "prompt_sha256": hashlib.sha256(prompt.encode("utf-8")).hexdigest(),
            "model_requested": cfg.model,
            "model_version": getattr(response, "model_version", None) if ok else None,
            "cache_hit": getattr(response, "cache_hit", None) if ok else None,
            "cache_key": getattr(response, "cache_key", None) if ok else None,
            "failed_attempts": len(errors),
            **stamp(run_id, [cfg.generate_prompt]),
        })
        if (i + 1) % 25 == 0:
            print(f"  generated {i + 1}/{len(alerts)}")
    return records


def stage_detect_rules(cfg: RunConfig, run_id: str, alerts: list[dict], explanations: list[dict]) -> list[dict]:
    tokens = {a["alert_id"]: a["evidence_tokens"] for a in alerts}
    return [
        {"alert_id": e["alert_id"], "detector": "rules_only",
         **rule_based_detect_explanation(e["explanation"], tokens[e["alert_id"]]),
         **stamp(run_id, [cfg.generate_prompt])}
        for e in explanations if e["status"] == "ok"
    ]


# ── orchestration ─────────────────────────────────────────────────────────

def execute_run(cfg: RunConfig, *, client=None, run_id: str | None = None, sleep: bool = True) -> Path:
    """Run every stage into runs/<run_id>/. Refuses to touch a frozen run.

    `client` defaults to the real Gemini client; tests pass tests/fakes.FakeGemini().
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
    save("config.json", {"run_id": run_id, "config_hash": cfg.config_hash, "config": cfg.raw})

    alerts, dataset, counts = stage_data(cfg, run_id)
    save("alerts.json", alerts)

    cache = LLMCache(cfg.cache_dir / CACHE_FILE)
    if cache.skipped_lines:
        anomalies.append(f"LLM cache: skipped {cache.skipped_lines} unreadable line(s)")
    cached = CachedClient(client if client is not None else get_client(), cache, cfg.generation_params)

    explanations = stage_generate(cfg, run_id, cached, alerts, sleep=sleep, anomalies=anomalies)
    save("explanations.json", explanations)
    detections = stage_detect_rules(cfg, run_id, alerts, explanations)
    save("detection_rules.json", detections)

    counts.update({
        "explanations_ok": sum(e["status"] == "ok" for e in explanations),
        "generation_failed": sum(e["status"] == "failed" for e in explanations),
        "rules_triggered": sum(d["triggered"] is True for d in detections),
        "rules_uncertain": sum(d["triggered"] is None for d in detections),
        "rules_clean": sum(d["triggered"] is False for d in detections),
    })
    llm = cached.stats()
    print(f"LLM: {llm['api_calls']} API call(s), {llm['cache_hits']} cache hit(s)")

    write_text(run_dir, "anomalies.md", f"# Anomalies - run {run_id}\n\n"
               + ("\n".join(f"- {a}" for a in anomalies) if anomalies else "None recorded.") + "\n")
    outputs.append("anomalies.md")
    manifest = build_manifest(cfg, run_id, started_at=started_at, dataset=dataset,
                              llm=llm, counts=counts, outputs=sorted(outputs))
    write_json(run_dir, "MANIFEST.json", manifest)
    print(f"Wrote {run_dir / 'MANIFEST.json'}")
    return run_dir

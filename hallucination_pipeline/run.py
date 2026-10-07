"""
Run orchestrator for the fresh, controlled run: config -> runs/<run_id>/.

Stages (later milestones add more):
  1. data       load + validate CSVs, stratified attack sample,  -> alerts.json, class_distribution.json,
                separate benign control sample                      benign_control/alerts.json
  2. generate   explanations through the cached LLM client       -> explanations.json
  3. detect     explanation level, every config (C0-C3) x policy  -> detection.json
  4. sentences  every sentence: all rule layers; only ambiguous   -> sentences.json
                sentences go to the sentence judge
  5. manifest                                                     -> MANIFEST.json, anomalies.md
Each of 2-4 writes the same file for the benign control arm under benign_control/ (D9): same
processing, kept apart so it can never be mixed into headline numbers.

Detection (EXPERIMENT_PLAN section 7): C0 = Tier 1 rules + v1 judge, C1 = Tier 1+2 rules + v1
judge, C2 = Tier 1 rules + aligned v2 judge, C3 = Tier 1+2 rules + aligned v2 judge, each under
both policies. The v1 judge prompt does not depend on the policy and C2/C3 share the v2 prompt of
a policy, so identical calls are cache hits: at most 3 judge calls per explanation (v1, v2-strict,
v2-lenient). Rule-clean and soft-certainty explanations all go to the judge (D15).
Sentences: "v1" style (C0/C1) uses the v1 sentence judge; "v2" style (C2/C3) the aligned v2 one.

Every record carries run_id, rules_version, policy_version (+ fingerprints) and the hashes of
the prompts in its lineage. All LLM calls go through CachedClient: re-running the same config
makes zero API calls, `max_calls` stops a run cleanly, and a dry run makes no call at all.
"""

from __future__ import annotations

import hashlib
import time
from pathlib import Path

from . import data_loader, sampling
from .detection import split_sentences
from .detection.version import rules_stamp
from .detection_pipeline import classify_sentence, detect_explanation
from .explanation_generator import build_prompt
from .llm_client import CachedClient, CallLimitReached, LLMCache, generate_text, get_client
from .manifest import build_manifest, utc_now
from .policy import detection_options, judge_prompt_files, policy_stamp, sentence_prompt_files
from .prompt_store import prompt_sha256
from .run_config import RunConfig
from .run_dir import ensure_writable, write_json, write_text

CACHE_FILE = "llm_cache.jsonl"
ARMS = (("attack", ""), ("benign_control", "benign_control/"))


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
    """status: ok | failed | pending (dry run: not generated yet)."""
    records = []
    for i, alert in enumerate(alerts):
        prompt = build_prompt(alert, cfg.generate_prompt)
        response, errors = generate_text(client, cfg.model, prompt, sleep=sleep)
        ok = response is not None
        pending = ok and getattr(response, "dry", False)
        if errors:
            anomalies.append(f"generate {alert['alert_id']}: {len(errors)} failed attempt(s)"
                             f"{'' if ok else ', GAVE UP'}: {errors[-1][:120]}")
        records.append({
            "alert_id": alert["alert_id"],
            "arm": alert["arm"],
            "alert_type": alert["alert_type"],
            "status": "pending" if pending else ("ok" if ok else "failed"),
            "explanation": response.text.strip() if ok and not pending else None,
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


def stage_detect(cfg: RunConfig, run_id: str, client, alerts: list[dict], explanations: list[dict], *,
                 sleep: bool) -> list[dict]:
    """One record per explanation x detection config x policy (only generated explanations)."""
    by_id = {a["alert_id"]: a for a in alerts}
    records = []
    for e in explanations:
        if e["status"] != "ok":
            continue
        for config_name in cfg.detection_configs:
            for policy in cfg.policies:
                opts = detection_options(config_name, policy)
                rec = detect_explanation(client, by_id[e["alert_id"]], e, sleep=sleep, policy=policy,
                                         use_tier2_rules=opts["use_tier2_rules"], judge_prompt=opts["judge_prompt"],
                                         escalate_clean=cfg.escalate_clean)
                records.append({**rec, "arm": e["arm"], "config": config_name,
                                **stamp(run_id, [cfg.generate_prompt, *judge_prompt_files(opts["judge_prompt"])])})
    return records


def sentence_styles(cfg: RunConfig) -> list[str]:
    """'v1' if C0 or C1 is configured (v1 sentence judge), 'v2' if C2 or C3 is (aligned v2 judge)."""
    styles = []
    if {"C0", "C1"} & set(cfg.detection_configs):
        styles.append("v1")
    if {"C2", "C3"} & set(cfg.detection_configs):
        styles.append("v2")
    return styles


def stage_sentences(cfg: RunConfig, run_id: str, client, alerts: list[dict], explanations: list[dict], *,
                    sleep: bool) -> list[dict]:
    """One record per sentence x style x policy. Rules always run with every layer; only sentences
    the policy leaves ambiguous are sent to the sentence judge."""
    by_id = {a["alert_id"]: a for a in alerts}
    records = []
    for e in explanations:
        if e["status"] != "ok":
            continue
        for j, sentence in enumerate(split_sentences(e["explanation"]), start=1):
            for style in sentence_styles(cfg):
                for policy in cfg.policies:
                    prompt = "v1" if style == "v1" else f"v2-{policy}"
                    rec, used = classify_sentence(client, by_id[e["alert_id"]], f"S{j}", sentence, sleep=sleep,
                                                  policy=policy, sentence_prompt=prompt)
                    files = [f for f in sentence_prompt_files(prompt) if f]
                    records.append({**rec, "arm": e["arm"], "style": style, "judge_called": used,
                                    **stamp(run_id, [cfg.generate_prompt, *files])})
    return records


# ── orchestration ─────────────────────────────────────────────────────────

def _llm_client(cfg: RunConfig, client, *, dry_run: bool) -> tuple[CachedClient, list[str]]:
    cache = LLMCache(cfg.cache_dir / CACHE_FILE)
    notes = [f"LLM cache: skipped {cache.skipped_lines} unreadable line(s)"] if cache.skipped_lines else []
    inner = None if dry_run else (client if client is not None else get_client())
    return CachedClient(inner, cache, default_params=cfg.default_llm_params, enforced_params=cfg.enforced_llm_params,
                        max_calls=None if dry_run else cfg.max_calls, dry_run=dry_run), notes


def dry_run(cfg: RunConfig, *, run_id: str | None = None) -> dict:
    """Count the LLM calls each stage WOULD make (identical calls counted once, cached ones not at all).
    Makes no API call, needs no API key, writes nothing. Detection and sentence counts are exact for
    explanations already in the cache; for the others they are only bounded (see the result)."""
    run_id = run_id or cfg.run_id
    alerts, benign, _, _ = stage_data(cfg, run_id)
    client, _ = _llm_client(cfg, None, dry_run=True)
    pending = 0
    for arm_alerts in (alerts, benign):
        client.stage = "generate"
        expl = stage_generate(cfg, run_id, client, arm_alerts, sleep=False, anomalies=[])
        pending += sum(e["status"] == "pending" for e in expl)
        client.stage = "detect"
        stage_detect(cfg, run_id, client, arm_alerts, expl, sleep=False)
        client.stage = "sentences"
        stage_sentences(cfg, run_id, client, arm_alerts, expl, sleep=False)
    judges = {opts["judge_prompt"] for c in cfg.detection_configs for p in cfg.policies
              for opts in [detection_options(c, p)]}
    per = {s: {"would_call": client.per_stage.get(s, {}).get("would_call", 0),
               "cached": client.per_stage.get(s, {}).get("cache_hits", 0)} for s in ("generate", "detect", "sentences")}
    return {"run_id": run_id, "alerts": len(alerts) + len(benign), "max_calls": cfg.max_calls,
            "per_stage": per, "exact_total": sum(v["would_call"] for v in per.values()),
            "not_yet_generated": pending,
            "detect_upper_bound_for_those": pending * len(judges),
            "distinct_judge_prompts": sorted(judges)}


def format_dry_run(d: dict) -> str:
    lines = [f"DRY RUN for {d['run_id']}: no API call made, nothing written. {d['alerts']} alerts.",
             f"  {'stage':<10}{'would call':>12}{'already cached':>16}"]
    for stage in ("generate", "detect", "sentences"):
        s = d["per_stage"].get(stage, {"would_call": 0, "cached": 0})
        lines.append(f"  {stage:<10}{s['would_call']:>12}{s['cached']:>16}")
    lines.append(f"  {'total':<10}{d['exact_total']:>12}")
    if d["not_yet_generated"]:
        lines += [f"  {d['not_yet_generated']} explanation(s) are not generated yet, so their detection and sentence",
                  f"  calls cannot be counted exactly: detection adds at most {d['detect_upper_bound_for_those']}"
                  f" ({len(d['distinct_judge_prompts'])} judge prompts x {d['not_yet_generated']});",
                  "  sentences add one call per ambiguous sentence per judge prompt (usually few)."]
    if d["max_calls"]:
        lines.append(f"  The run stops cleanly at max_calls = {d['max_calls']}.")
    return "\n".join(lines)


def execute_run(cfg: RunConfig, *, client=None, run_id: str | None = None, sleep: bool = True,
                data_only: bool = False) -> Path:
    """Run every stage into runs/<run_id>/. Refuses to touch a frozen run.

    `client` defaults to the real Gemini client; tests pass tests/fakes.FakeGemini().
    `data_only` stops after sampling: no LLM calls, no API key needed (Pass-through P1).
    If the config's max_calls is reached, the run stops cleanly: finished stages are saved, the
    manifest says where it stopped, and re-running continues from the cache.
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

    llm_client, notes = _llm_client(cfg, client, dry_run=False)
    anomalies += notes
    arm_alerts = {"attack": alerts, "benign_control": benign}
    explanations: dict[str, list] = {}
    wall: dict[str, float] = {}
    done, status = ["data"], "complete"

    def timed(stage: str, fn):
        llm_client.stage = stage
        t0 = time.perf_counter()
        try:
            return fn()
        finally:
            wall[stage] = round(wall.get(stage, 0.0) + time.perf_counter() - t0, 3)

    try:
        for arm, prefix in ARMS:
            explanations[arm] = timed("generate", lambda: stage_generate(cfg, run_id, llm_client, arm_alerts[arm],
                                                                         sleep=sleep, anomalies=anomalies))
            save(f"{prefix}explanations.json", explanations[arm])
            counts[arm].update({"explanations_ok": sum(e["status"] == "ok" for e in explanations[arm]),
                                "generation_failed": sum(e["status"] == "failed" for e in explanations[arm])})
        done.append("generate")
        for arm, prefix in ARMS:
            det = timed("detect", lambda: stage_detect(cfg, run_id, llm_client, arm_alerts[arm], explanations[arm],
                                                       sleep=sleep))
            save(f"{prefix}detection.json", det)
            counts[arm]["detection_records"] = len(det)
        done.append("detect")
        for arm, prefix in ARMS:
            sent = timed("sentences", lambda: stage_sentences(cfg, run_id, llm_client, arm_alerts[arm],
                                                              explanations[arm], sleep=sleep))
            save(f"{prefix}sentences.json", sent)
            counts[arm].update({"sentence_records": len(sent), "sentence_judge_calls": sum(r["judge_called"]
                                                                                          for r in sent)})
        done.append("sentences")
    except CallLimitReached as e:
        status = f"stopped: {e}"
        anomalies.append(f"RUN STOPPED at the call limit ({e}); finished stages are saved, "
                         "re-running continues from the cache")
        print(f"\nSTOPPED: {e}")
    llm = {**llm_client.stats(), "wall_seconds": wall, "status": status}
    for stage, secs in wall.items():
        llm["per_stage"].setdefault(stage, {})["wall_seconds"] = secs
    print(f"LLM: {llm['api_calls']} API call(s), {llm['cache_hits']} cache hit(s), "
          f"{llm['rate_limit_errors']} rate-limit wait(s)")
    return _finish(cfg, run_id, run_dir, started_at, done, dataset, llm, counts, outputs, anomalies)


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

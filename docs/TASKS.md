# Tasks — build order for the fresh run

Work top to bottom. Tick boxes as you finish. Each milestone ends with its **Pass-through** (what goes to the
paper side — see `docs/HANDOFF.md`). Do not start a milestone before the previous one's tests are green.

---
## M0 — Run infrastructure
- [x] `config` file for a run (`configs/fresh_run.toml`): dataset path, per_class_cap, seed, model, temperature,
      policy, detection config (C0-C3), mitigation arm, paths. One config -> one `run_id`.
- [x] `RULES_VERSION` constant + SHA-256 of all rule patterns; written to every prediction record.
- [x] Prompt registry: SHA-256 of every file in `prompts/`; written to the manifest.
- [x] **Content-addressed LLM cache** (jsonl): key = hash(model, params, prompt). Raw responses and token usage kept.
      A re-run with the same config makes zero API calls.
- [x] `MANIFEST.json` writer: git commit + dirty flag, python and package versions, model string returned by API,
      date, config hash, rules version, prompt hashes, dataset CSV hashes and row counts, call counts, tokens.
- [x] `freeze_run <run_id>`: make the run directory read-only and write `SHA256SUMS`.
- [x] Move the fake Gemini from `tools/verify_against_original.py` to `tests/fakes.py` and reuse it.
**Accept:** a fake-LLM end-to-end test produces a manifest; second run uses the cache; frozen dirs refuse writes.
**Done 2026-10-07** — `tests/test_run_infrastructure.py`. CLI: `cli run`, `cli freeze_run <run_id>`, `cli verify_run <run_id>`.
The M0 commit's data stage used the legacy random sampler; M1 replaced it.

## M1 — Data
- [x] Stratified sampler: attack classes only, `per_class_cap`, seed, all rows for small classes.
- [x] D11 duplicate removal within attack classes and D12 complete-evidence filter, counts per class.
- [x] U+FFFD Web Attack labels normalised at load (UTF-8, cp1252 fallback).
- [x] Real data: 391 alerts as expected (12 x 30 + 20 + 11), no benign label (asserted).
- [x] Benign set recognised by `config.BENIGN_LABELS`; **assert** no benign label in the attack set.
- [x] Print + save the realized class distribution (`class_distribution.json`) and a fine->coarse map.
- [x] Optional benign control sample (default 60), written to a separate file.
- [x] Dataset fingerprint (CSV SHA-256, row counts) in the manifest.
**Accept:** tests with a synthetic CSV (both `BENIGN` and `Normal Traffic` spellings) pass; distribution asserted.
**Done 2026-10-07** — `hallucination_pipeline/sampling.py`, `tests/test_data_sampling.py`. Required CSV columns are
checked before loading (clear error naming file + column). `cli run --data-only` produces the P1 files without
any LLM call; `python tools/make_outbox.py P1 <run_id>` zips exactly the P1 files.
**Pass-through P1:** `class_distribution.json` + manifest -> paper side.

## M2 — Taxonomy and policy refactor (needs DECISIONS D1-D3 confirmed)
- [x] `policy.py`: Tier 1 / Tier 2 mapping of every hallucination type; `strict` and `lenient` policies.
- [x] Each rule hit carries `tier` and `subtype`; detection returns the tier so both policies derive from one pass.
- [x] Phase 2 options: `use_tier2_rules` (on/off) and `judge_prompt` (v1 / v2-strict / v2-lenient).
- [ ] Prompt files for judge v2 (strict, lenient) and generation v2 are **supplied by the paper side**;
      commit them as new files, never edit v1.
- [x] Sentence-level classifier returns tier + subtype; LLM fallback uses the policy-matched prompt.
**Accept:** existing 46 tests still pass; new tests pin tier/subtype per rule; C0 reproduces the old Phase 2
behaviour exactly on the frozen explanations (`tools/reproduce_frozen.py` still reports 354/354).
**Code part done 2026-10-07** — `policy.py`, `tests/test_policy.py`, `docs/RULE_TIERS.md`. Tier/subtype live in
`policy.RULE_TIERS` (pattern tuples untouched). Open: v2 prompt files from the paper side; the policy-matched LLM
fallback is wired but needs those files.
Also done: D13 thinking_budget = 0 forced on every call.
Also done (2026-10-07): D15 `escalate_clean`, D16 recorded, D17 `hedged` on every hit, D18 all subtypes per
sentence, D19 `unit_wrong` duration check, v2 template/reply handling, `docs/SUBTYPES.md`.
`tools/reproduce_frozen.py --frozen-dir old_run`: 955/955 and 354/354.
Also done: D20 stated-duration `unit` hits (POLICY_VERSION 1.2.0 on every record and the manifest), D21 catch-all
subtypes with required note.
**Pass-through P1b:** rule -> tier table + proposed judge prompts -> paper side for sign-off.

## M3 — Annotation tooling, then FREEZE
- [x] Sampler for the 100 annotated explanations (stratified, seeded) + the 25-explanation reliability subset
      + the 25-explanation test-retest subset.
- [x] **Blind export** to CSV (and a simple local HTML view): alert_id, sentence_id, evidence, sentence, explanation
      context, empty label/subtype/note columns. No pipeline fields. Test that no prediction leaks into the export.
- [x] Import + validation: allowed labels only, every sentence labelled, duplicates rejected; a catch-all subtype
      (`other_fabrication`, `other_knowledge`, D21) without a note is rejected.
- [x] Agreement: Cohen's kappa (overall, Tier 1, Tier 2) with bootstrap CI; disagreement list; adjudication file.
- [x] Derive strict and lenient gold from the single annotation.
**Accept:** synthetic-annotation tests; kappa matches a hand-computed example.
**Done 2026-10-07** — `hallucination_pipeline/annotation.py`, `tests/test_annotation.py` (synthetic data only). CLI:
`annotation_export <run_id>` (refuses before `freeze-1`), `annotation_import <run_id> <csv> --sheet --annotator`,
`annotation_agreement <run_id> <a.json> <b.json>`. Output in `annotation/<run_id>/`.
## Tonight — existing-corpus study (D25-D28), replaces the pilot for now
- [x] `analyze_corpus`: rules + policy 1.2.0 on every sentence of the earlier run's 400 explanations; results pack
      with n and bootstrap CIs in `results/<corpus_id>/` (`hallucination_pipeline/corpus.py`, `tests/test_corpus.py`).
- [x] Audit path (D28): sampler, blind export, D23 import, rules-versus-human P/R/F1 with CIs, disagreement list
      (`hallucination_pipeline/audit.py`).
- [x] `docs/RUNBOOK_TONIGHT.md`.
- [x] Tag `freeze-1` (D26).
- [ ] Human labels for the 25 audit explanations (by hand, outside the code tooling), then import, analyse, audit metrics.
- [ ] Results pack + DECISIONS.md -> paper side.

## M3b — Pilot (D24, superseded by D25 for now: no API quota), before the freeze
- [ ] Pilot: 40 alerts (about 3 per class), generation plus detection for all configs C0-C3 and both policies, run
      under its own config / run_id. Needs `GEMINI_API_KEY`.
- [ ] Check: malformed or contradictory judge replies (`reply_problems`), rate limits and retries, failures, tokens and
      cost, time per call, class balance.
- [ ] Fix only malformed output or contradictions (prompt/format), each change logged in DECISIONS.md before the freeze.
      Never tune rules on pilot output.
- [ ] Discard the pilot run (never used for results).
**Code done 2026-10-07** (not yet run): `configs/pilot.toml` (cap 3 -> 42 attack + 6 benign alerts, max_calls 1500,
own LLM cache), detection stage C0-C3 x both policies and sentence stage in `run.py`, `run --dry-run`,
`pilot_report <run_id>` (`hallucination_pipeline/pilot_report.py`), tests in `tests/test_pilot.py`. Real-data dry run:
48 generation calls, detection at most 144 more (sentence calls depend on the generated text).
**Pass-through P3:** pilot manifest, cost, failures -> paper side.

**FREEZE:** `git tag freeze-1` after M3 and M3b are green and *before* exporting real sheets.
**Pass-through P2:** blind sheets -> the human annotator (outside the code tooling) -> filled sheets back -> import.

## M4 — Mitigation upgrades
- [ ] Numeric-fidelity validator: every number in a rewrite must occur in the evidence tokens (or the original
      sentence's evidence-derived numbers); report violations.
- [ ] Retry (max 2) with a stricter instruction; fall back to REMOVE if still invalid. Log every attempt.
- [ ] Mitigation modes: `gold_driven` and `automatic`, named explicitly in outputs and file names.
- [ ] Prompt-only arm: regenerate with generation prompt v2; no post-hoc correction.
- [ ] Controlled injection generator (E4): templates for regex-friendly, paraphrased, and definitive claims;
      ground truth by construction; seeded.
**Accept:** offline tests with the fake LLM for each arm; REMOVE path exercised by the injection test.

## M5 — Evaluation v2
- [ ] Unconditional explanation- and sentence-level metrics; also the conditional ones, labelled as such.
- [ ] Cluster bootstrap CIs (2000, seed), McNemar between configs, per-class tables, n in every cell.
- [ ] Count catch-all subtypes (D21) separately from listed subtypes in every subtype table.
- [ ] Detection ablation table C0-C3 under both policies; mitigation table M0 / M-prompt / M-auto /
      M-auto+val / M-gold; injection table.
- [ ] Rewrite audit export (100 sampled rewrites, blind, for a human to label).
- [ ] `tools/export_paper_numbers.py` -> `results/<run_id>/paper_numbers.json` and `tables/*.csv`.
      **The paper cites only values from this file.**
**Accept:** tests on hand-checkable toy data; `paper_numbers.json` regenerates byte-identically from a frozen run.

## M6 — Execution
- [x] Pilot: moved before the freeze as M3b (D24).
- [ ] Full run from the frozen config; freeze the run directory.
- [ ] Annotation (human, outside the code tooling) -> import -> agreement -> metrics.
**Pass-through P3 (after pilot), P4 (after full run).**

## M7 — Handoff package
- [ ] `results/<run_id>/` committed (manifest, tables, paper_numbers.json, qualitative samples, anomaly log).
- [ ] `docs/DECISIONS.md` complete (including every post-hoc change).
- [ ] README updated (how to reproduce the paper's numbers from the frozen run).
**Pass-through P5:** package -> paper side; numbers locked.

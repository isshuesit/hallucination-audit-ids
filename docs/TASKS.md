# Tasks — build order for the fresh run

Work top to bottom. Tick boxes as you finish. Each milestone ends with its **Pass-through** (what goes to the
paper side — see `docs/HANDOFF.md`). Do not start a milestone before the previous one's tests are green.

---
## M0 — Run infrastructure
- [ ] `config` file for a run (`configs/fresh_run.toml`): dataset path, per_class_cap, seed, model, temperature,
      policy, detection config (C0-C3), mitigation arm, paths. One config -> one `run_id`.
- [ ] `RULES_VERSION` constant + SHA-256 of all rule patterns; written to every prediction record.
- [ ] Prompt registry: SHA-256 of every file in `prompts/`; written to the manifest.
- [ ] **Content-addressed LLM cache** (jsonl): key = hash(model, params, prompt). Raw responses and token usage kept.
      A re-run with the same config makes zero API calls.
- [ ] `MANIFEST.json` writer: git commit + dirty flag, python and package versions, model string returned by API,
      date, config hash, rules version, prompt hashes, dataset CSV hashes and row counts, call counts, tokens.
- [ ] `freeze_run <run_id>`: make the run directory read-only and write `SHA256SUMS`.
- [ ] Move the fake Gemini from `tools/verify_against_original.py` to `tests/fakes.py` and reuse it.
**Accept:** a fake-LLM end-to-end test produces a manifest; second run uses the cache; frozen dirs refuse writes.

## M1 — Data
- [ ] Stratified sampler: attack classes only, `per_class_cap`, seed, all rows for small classes.
- [ ] Benign set recognised by `config.BENIGN_LABELS`; **assert** no benign label in the attack set.
- [ ] Print + save the realized class distribution (`class_distribution.json`) and a fine->coarse map.
- [ ] Optional benign control sample (default 60), written to a separate file.
- [ ] Dataset fingerprint (CSV SHA-256, row counts) in the manifest.
**Accept:** tests with a synthetic CSV (both `BENIGN` and `Normal Traffic` spellings) pass; distribution asserted.
**Pass-through P1:** `class_distribution.json` + manifest -> paper side.

## M2 — Taxonomy and policy refactor (needs DECISIONS D1-D3 confirmed)
- [ ] `policy.py`: Tier 1 / Tier 2 mapping of every hallucination type; `strict` and `lenient` policies.
- [ ] Each rule hit carries `tier` and `subtype`; detection returns the tier so both policies derive from one pass.
- [ ] Phase 2 options: `use_tier2_rules` (on/off) and `judge_prompt` (v1 / v2-strict / v2-lenient).
- [ ] Prompt files for judge v2 (strict, lenient) and generation v2 are **supplied by the paper side**;
      commit them as new files, never edit v1.
- [ ] Sentence-level classifier returns tier + subtype; LLM fallback uses the policy-matched prompt.
**Accept:** existing 46 tests still pass; new tests pin tier/subtype per rule; C0 reproduces the old Phase 2
behaviour exactly on the frozen explanations (`tools/reproduce_frozen.py` still reports 354/354).
**Pass-through P1b:** rule -> tier table + proposed judge prompts -> paper side for sign-off.

## M3 — Annotation tooling, then FREEZE
- [ ] Sampler for the 100 annotated explanations (stratified, seeded) + the 25-explanation reliability subset
      + the 25-explanation test-retest subset.
- [ ] **Blind export** to CSV (and a simple local HTML view): alert_id, sentence_id, evidence, sentence, explanation
      context, empty label/subtype/note columns. No pipeline fields. Test that no prediction leaks into the export.
- [ ] Import + validation: allowed labels only, every sentence labelled, duplicates rejected.
- [ ] Agreement: Cohen's kappa (overall, Tier 1, Tier 2) with bootstrap CI; disagreement list; adjudication file.
- [ ] Derive strict and lenient gold from the single annotation.
**Accept:** synthetic-annotation tests; kappa matches a hand-computed example.
**FREEZE:** `git tag freeze-1` after M3 is green and *before* exporting real sheets.
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
- [ ] Detection ablation table C0-C3 under both policies; mitigation table M0 / M-prompt / M-auto /
      M-auto+val / M-gold; injection table.
- [ ] Rewrite audit export (100 sampled rewrites, blind, for a human to label).
- [ ] `tools/export_paper_numbers.py` -> `results/<run_id>/paper_numbers.json` and `tables/*.csv`.
      **The paper cites only values from this file.**
**Accept:** tests on hand-checkable toy data; `paper_numbers.json` regenerates byte-identically from a frozen run.

## M6 — Execution
- [ ] Pilot: 40 alerts (about 3 per class). Check cost, time, failures, class balance. Fix, then discard the pilot run.
- [ ] Full run from the frozen config; freeze the run directory.
- [ ] Annotation (human, outside the code tooling) -> import -> agreement -> metrics.
**Pass-through P3 (after pilot), P4 (after full run).**

## M7 — Handoff package
- [ ] `results/<run_id>/` committed (manifest, tables, paper_numbers.json, qualitative samples, anomaly log).
- [ ] `docs/DECISIONS.md` complete (including every post-hoc change).
- [ ] README updated (how to reproduce the paper's numbers from the frozen run).
**Pass-through P5:** package -> paper side; numbers locked.

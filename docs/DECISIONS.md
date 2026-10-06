# Decisions log

Status values: **ACCEPTED** (follow it) · **PROPOSED** (suggested, not yet approved — keep following the
current decision) · **POST-HOC** (changed after the freeze; must be disclosed in the paper).
Append new entries at the bottom. Never delete an entry; supersede it.

| ID | Decision | Value | Status | Why |
|---|---|---|---|---|
| D1 | Dataset source | Original UNB CIC-IDS 2017 CSVs, fine-grained `Label`, plus a coarse mapping | ACCEPTED | The processed 'Attack Type' copy names benign flows `Normal Traffic`, which silently defeated the old filter |
| D2 | Sampling | Attack classes only; `per_class_cap = 30`; seed 42; all rows for classes smaller than the cap | ACCEPTED | Stratified and attack-only, unlike the old run (84% benign) |
| D3 | Hallucination policy | Two tiers (Tier 1 unsupported specifics, Tier 2 external knowledge); **strict** = T1+T2, **lenient** = T1; both reported | ACCEPTED | The old run used both policies in different phases without saying so |
| D4 | Generator | `gemini-2.5-flash`, temperature 0.0, record returned model string and date | ACCEPTED | Continuity with the old run; determinism as far as the API allows |
| D5 | Gold-label sample | 100 explanations, stratified by class, all sentences; blind to pipeline output | ACCEPTED | Unconditional recall requires sampling from all explanations |
| D6 | Reliability | 25 explanations double-labelled (second human), else test-retest after >= 7 days | ACCEPTED | Old gold labels agreed at kappa 0.164 |
| D7 | Statistics | Cluster bootstrap (2000, seed fixed) by explanation; McNemar for paired comparisons | ACCEPTED | Sentences are nested in explanations |
| D8 | Freeze | Tag `freeze-1` after M3, before real annotation sheets are exported | ACCEPTED | Rules, prompts and config must not be tuned after seeing results |
| D9 | Benign control arm | 60 benign flows, analysed separately | ACCEPTED | Tests over-interpretation of normal traffic without contaminating headline numbers |
| D10 | Second generator model | Out of scope for the core; stretch only | ACCEPTED | Keeps the core run finishable |
| D11 | Gemini thinking setting | Proposed: pin `thinking_budget` explicitly in `configs/fresh_run.toml` (e.g. 0) instead of the API default | PROPOSED | gemini-2.5-flash thinks by default with a dynamic budget, which adds variation and cost that temperature 0.0 does not remove. Current behaviour: API default, recorded in the manifest as "not set". |

## Open items for the human to confirm (defaults apply until answered)
- Is a second human annotator available for D6? (default: no -> test-retest)
- Annotation size D5 (default 100 explanations, about 1000 sentences, about 8 hours). Minimum acceptable: 60.
- API budget / rate limits for Gemini (default: free tier with caching and resume).

## Implementation notes (code side, 2026-10-07)
These follow existing decisions; they are recorded so nothing is silent.
- **M0 temperature.** The legacy generator called Gemini without a config, so it used the API's default
  temperature, not 0.0. The fresh run applies D4's temperature to every call through the cached client
  (`generation_params` in the manifest). Old-run numbers were therefore probably produced at the default
  temperature; the paper side may want to state this when describing the old run.
- **M0 run_id.** `run_id = <name>-<first 8 hex of the config hash>`. The hash covers every section except
  `[paths]` (file locations do not change results; the dataset is fingerprinted separately). One config ->
  one run_id. A frozen run is never overwritten: re-running needs `--run-id <new id>`; the shared LLM cache
  makes that re-run free.
- **M0 rule fingerprints.** Two SHA-256 values go into every record: one over all patterns (format-independent),
  one over the source of `patterns.py` + `rules.py` (catches inline regexes). Both are pinned per
  `RULES_VERSION` in `tests/test_run_infrastructure.py`. The 8 v1 prompt hashes are pinned there too.
- **M0 cache.** Errors and empty responses are not cached, so a retry always reaches the API.
- **M0 git line endings.** Git on this machine converts line endings (autocrlf), which would change prompt bytes
  on checkout. `.gitattributes` keeps LF everywhere and marks `prompts/` as binary-safe (`-text`).

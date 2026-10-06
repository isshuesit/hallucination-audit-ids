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
| D11 | Duplicate flows | Before sampling, remove duplicate flows within each attack class; a duplicate = identical values in all nine evidence columns (first occurrence in file order kept). Report counts before and after, per class | ACCEPTED | About 25% of attack rows are exact duplicates (PortScan 43%, FTP-Patator 46%, SSH-Patator 47%); duplicates would yield identical prompts and double-count one explanation |
| D12 | Complete evidence | Only sample rows whose nine evidence fields are all present and finite, so every evidence string has the same nine lines. Report rows dropped per class | ACCEPTED | About 0.2% of rows have NaN/Infinity in Flow Bytes/s and Flow Packets/s; a missing line would change what the model sees |
| D13 | Gemini thinking setting | `thinking_budget = 0` for EVERY Gemini call (generation, judges, rewrites, re-checks), pinned explicitly in `configs/fresh_run.toml` and recorded per call | ACCEPTED | gemini-2.5-flash thinks by default with a dynamic budget, which adds variation and cost that temperature 0.0 does not remove |
| D14 | Thinking sensitivity check | In M6, after the main run: regenerate explanations for 100 of the alerts with the API-default thinking setting and compare hallucination rates. Sensitivity check only, never a headline number | ACCEPTED | Shows whether D13 changes what the model hallucinates |
| D15 | Judge escalation for rule-clean explanations | Proposed: send every rule-clean explanation to the LLM judge, whatever its class, instead of only attack-class ones | PROPOSED | The old Phase 2 escalates a rule-clean explanation to the judge only if its alert is an attack class. The detector thus reads the ground-truth label, and the benign control arm (D9) gets less checking than the attack arm, which biases the attack-vs-benign comparison. Inside the attack arm nothing changes (every alert is an attack). Current behaviour kept: attack-class only, now using `label_coarse` so fine labels such as `DoS Hulk` are recognised (the old check compared coarse names and would have skipped most fine-labelled alerts). |

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
- **M1 labels.** Labels are normalised at load time: whitespace collapsed and dash variants (en dash, the raw
  cp1252 byte 0x96 in the UNB Thursday file, the U+FFFD replacement character) become `-`, so
  `Web Attack  Brute Force` -> `Web Attack - Brute Force`. Every fine label must map to a coarse class
  (D1 mapping in `sampling.coarse_label`); an unknown label stops the run rather than being sampled.
- **M1 required columns.** Every CSV must have Destination Port, Flow Duration, Total Fwd Packets, Total Backward
  Packets, Flow Bytes/s, Flow Packets/s, SYN/ACK/RST Flag Count and Label (after stripping spaces), or loading
  stops with an error naming the file and columns. The processed 'Attack Type' copy is therefore refused (D1).
- **M1 sampling details.** Each fine class is sampled independently with the run seed, so one class's size never
  changes another's draw. Alert ids are `A0001...` (attack) and `B0001...` (benign control). Each alert keeps
  `source_file` + `source_row` for traceability. Benign control alerts (D9) go through generation and rule
  detection in the same run but are written only under `runs/<run_id>/benign_control/`.
- **Renumbering (2026-10-07, before anything left this machine).** Earlier drafts held two code-side PROPOSED
  entries as D11 (thinking budget) and D12 (de-duplication). The paper side's D11 (de-duplication) supersedes
  the second; the thinking-budget proposal is now D13. Neither draft was ever handed over.
- **D11/D12 implementation.** Both filters run before the cap (`sampling.eligible_rows`). They commute: a group
  of identical rows is all finite or all not, so the eligible set is the same in either order (tested).
  D12 also applies to the benign control arm; D11 de-duplicates attack classes only, as worded. Rows with the
  same values but *different* attack labels are kept (44 such rows in the real data, before the cap).
  Counts per class are in `class_distribution.json` under `attack_classes`.
- **Encoding.** The UNB MachineLearningCSV files are valid UTF-8 and contain a literal U+FFFD in the three
  Web Attack labels. Each file is checked as strict UTF-8 first, with a cp1252 fallback; the encoding used is
  recorded per file in the manifest. U+FFFD (and en dash / em dash / byte 0x96) becomes `-`.
- **Real-data check (M1, 2026-10-07).** 2,830,743 rows in 8 files; 557,646 attack rows; 1,090 (0.195%) dropped
  as non-finite; 140,617 (25.2%) dropped as duplicates; 415,939 eligible; 391 sampled = 12 classes x 30 +
  Web Attack - Sql Injection 20 + Heartbleed 11. No benign label in the sample (asserted). 0 sampled alerts share
  an evidence string.
- **D13 implementation (M2).** `thinking_budget` is a required config key. The cached client forces
  `thinking_config = {thinking_budget: 0}` on every call, overriding whatever a caller asks for (count reported as
  `enforced_overrides` in the manifest). The final parameters of every call are stored in its cache entry and on
  every generation record (`llm_params`). Temperature 0.0 stays a default the caller may override. Because the
  config changed, the run id changed from `fresh-74bc2b8c` to a new one; the data settings did not change, so
  the 391-alert sample is identical.
- **M2 tiers.** Tier and subtype live in `policy.RULE_TIERS`, keyed by each rule's description; the pattern tuples
  and `rules.py` are untouched (both fingerprints and `RULES_VERSION 1.0.0` unchanged; pinned in
  `tests/test_policy.py`). The tier map has its own `POLICY_VERSION` and fingerprint, stamped on every record.
  Table: `docs/RULE_TIERS.md` (generated, tested to match the code).
- **M2 port and protocol layers are Tier 1.** "Port N" absent from the evidence -> Tier 1 factual
  `port_not_in_evidence`; a protocol named without its well-known port in the evidence -> Tier 1 factual
  `protocol_without_port`. Both were part of the old Phase 2 rules, so C0 needs them in Tier 1 to reproduce the
  old run. (Naming the protocol of a port that IS in the evidence is not flagged by any rule.)
- **M2 policy derivation.** One rule pass, then the policy. Explanation level: C0 equals the old rule engine under
  both policies (tested on 300 synthetic explanations). Sentence level: the engine stops at the first rule and
  checks Tier 1 layers first, so a Tier 2 verdict means no Tier 1 rule fired; under lenient such a sentence is
  `grounded`, or `ambiguous` (-> LLM) if it also has soft-certainty words the engine never reached.
- **M2 subtype order effect.** At sentence level the first Tier 2 pattern that fires names the subtype. The protocol
  pattern is checked before the baseline pattern, so "deviates from typical web traffic" is labelled `protocol`,
  not `baseline`. Tier and policy outcome are unaffected; per-subtype counts are. Flagged for the paper side.
- **M2 v2 prompt names.** The code expects (but does not have yet): `detect_explanation_system_v2_strict.txt`,
  `detect_explanation_system_v2_lenient.txt` (used with the v1 template), `localize_sentence_system_v2_strict.txt`,
  `localize_sentence_system_v2_lenient.txt`, `generate_system_v2.txt`. Asking for a missing one stops with a
  clear error. Names can change if the paper side prefers others.
- **M2 not verified here: `tools/reproduce_frozen.py`.** The old run's frozen artifacts are not on this machine, so
  354/354 and 955/955 could not be re-run. The functions that tool calls (`rule_classify_sentence`,
  `rule_based_detect_explanation`, masks, impact) are byte-for-byte unchanged (source fingerprint pinned), so the
  result cannot have changed; it should still be run once the artifacts are available.

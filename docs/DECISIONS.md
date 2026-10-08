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
| D15 | Judge escalation for rule-clean explanations | Must not depend on the alert label. Option `escalate_clean`: `"all"` (default for fresh configs, in `configs/fresh_run.toml`) sends every rule-clean explanation to the judge; `"attack_only"` is the legacy behaviour, kept for regression tests | ACCEPTED | The old rule read the ground-truth label and checked the benign control arm less than the attack arm |
| D16 | Ports and protocols | A port or protocol named but ABSENT from the evidence is Tier 1 factual (`port_not_in_evidence`, `protocol_without_port`). Describing what a PRESENT port is used for is Tier 2 `port` | ACCEPTED | Records what M2 built; needed for C0 to reproduce the old Phase 2 |
| D17 | Hedged mentions | Hedged attack-technique / threat-actor / outcome mentions stay Tier 1 `reasoning`. Every rule hit carries a boolean `hedged` from a frozen lexicon in `policy.py` (could, may, might, possibly, potentially, perhaps, appear(s), seem(s), suggest(s), suggesting, consistent with, compatible with, likely, probably). It never changes a tier | ACCEPTED | Lets the paper report hedged and unhedged claims separately without changing the taxonomy |
| D18 | All subtypes | Keep ALL matched rule subtypes per sentence (list) in addition to the primary one | ACCEPTED | The first-match rule hides co-occurring claims |
| D19 | Duration units | Flow Duration is in microseconds (CICFlowMeter). Deterministic `unit_wrong` check: a sentence stating a duration with a unit (microsecond/millisecond/second/minute/hour) whose value differs from Flow Duration / 1,000,000 seconds by more than 10% (rounding allowed) is Tier 1 factual `unit_wrong` under both policies; otherwise `unit` stays Tier 2 | ACCEPTED | 28 of 132 old rewrites had unsupported figures, e.g. 92,190 -> "92 seconds" |
| D20 | Stated durations | Rules stay frozen. In the POLICY layer, when Tier 2 rules are on (C1/C3, and in the sentence classifier), any stated duration with an explicit unit (microsecond, millisecond, second, minute, hour) is a Tier 2 `unit` hit if the rule engine produced no `unit` hit for that sentence. `unit_wrong` (D19) still escalates a wrong duration to Tier 1. POLICY_VERSION is recorded in every record and in the manifest | ACCEPTED | Closes the gap where "lasted 36.2 milliseconds" was never a unit hit |
| D21 | Catch-all subtypes | `other_fabrication` (Tier 1) for an invented specific that fits no listed subtype (e.g. an invented hostname); `other_knowledge` (Tier 2) for outside knowledge that fits none. Rules never produce them; the AI judge and human annotators may. A short free-text note is required whenever one is used; reports count them separately | ACCEPTED | Avoids forcing unlisted claims into a wrong subtype |
| D22 | v2 prompts delivered | The paper side delivered `detect_explanation_system_v2_strict.txt`, `detect_explanation_system_v2_lenient.txt`, `detect_explanation_template_v2.txt`, `localize_sentence_system_v2_strict.txt`, `localize_sentence_system_v2_lenient.txt`, `localize_sentence_template_v2.txt`, `generate_system_v2.txt` (new files in `hallucination_pipeline/prompts/`, byte-exact, hashes pinned in `tests/test_policy.py`) and `docs/ANNOTATION_GUIDE_v2.md`. The v1 guide is archived as `docs/archive/ANNOTATION_GUIDE_v1.md` | ACCEPTED | Completes M2's prompt inputs and the annotation protocol |
| D23 | Annotation CSV | Columns `label` (grounded or hallucinated), `subtype` (a name from SUBTYPES.md; empty if grounded), `hedged` (yes or no; empty if grounded), `other_subtypes` (optional, comma separated), `note`, `unsure` (yes or empty). The tier is derived from the subtype and never typed. Import rejects: unknown subtype names, hallucinated without a subtype, grounded with a subtype, other_fabrication or other_knowledge without a note, and any blank label | ACCEPTED | One unambiguous format for gold labels; errors caught at import, not at analysis |
| D24 | Pilot before the freeze | The 40-alert pilot (generation plus detection, all configs and both policies) runs BEFORE freeze-1, for debugging only (malformed replies, rate limits, cost). Pilot output is discarded and never used to tune rules. Prompt or format changes made because of the pilot are allowed only to fix malformed output or contradictions, and must be logged before the freeze | SUPERSEDED by D25 | Finds plumbing failures while changes are still allowed, without letting results shape the method |
| D25 | Existing-corpus study tonight | Supersedes D24 and the paper side's earlier D25-D29 draft. Tonight is an EXISTING-CORPUS study with no Gemini call at all (free tier: 20 requests per day). The corpus is the earlier run's 400 explanations in `old_run/` (`llm_explanations.json`, `alerts.json`, `corrected_explanations.json`). Every output and table says: "source: earlier run, API-default sampling, prompt v1, 63 attack-flow and 337 benign-flow explanations; not generated under freeze-1" | ACCEPTED | A new generation run is impossible within the quota |
| D26 | freeze-1 | Tag `freeze-1` now: rules 1.0.0, policy 1.2.0, annotation guide v2, analysis code. After it only bug fixes, each logged POST-HOC | ACCEPTED | Nothing may be tuned after results are seen |
| D27 | No LLM arms tonight | No LLM-judge arms, no prompt-v2 comparison, no rewrite arms tonight; future work | ACCEPTED | No API calls available |
| D28 | Human audit | 25 explanations from the corpus: 3 from each of the 4 attack classes present (DoS, DDoS, Port Scanning, Brute Force) = 12 attack-flow, plus 13 benign-flow, fixed seed (42). Blind sheets, no second pass. Reported as an audit with wide intervals | ACCEPTED | Feasible tonight; measures the rules against a human |
| D29 | Test isolated from the freeze tag | `tests/test_annotation.py::test_cli_export_import_agreement` expected the CLI export to be refused because the project had no freeze-1 tag; after D26 it has, so the test failed. The test now runs the real guard against a temporary git repository without the tag (monkeypatched). TEST-ONLY: no non-test code changed; no change to analysis behaviour; frozen files unchanged since freeze-1 (`git diff --stat freeze-1 -- hallucination_pipeline configs docs/ANNOTATION_GUIDE_v2.md` is empty); the freeze-1 tag was not moved. Runbook step 1 now checks the tag exists and that diff is empty, instead of an exact tag match | POST-HOC | The test depended on the state of the real repository |
| D30 | AI annotators, author-adjudicated (pre-labelling amendment, 2026-10-08, made before any labelling and before any result was seen) | Audit labels come from two independent AI annotators (names and versions recorded by the author), each given the same blind items and the frozen text in `docs/AI_LABELLER_PROMPT.md`. The author adjudicates (a) every item where they disagree and (b) a random 20% (seed 42) of items where they agree, shown blind (the adjudication sheet never shows either AI's answer). Final labels = the author's decisions on those items, AI consensus elsewhere | ACCEPTED | Supersedes, for the D28 audit only, the human-only gold of D5/D28, audit lesson 3 of the project instructions and EXPERIMENT_PLAN section 8 (an LLM only as an additional labeller). Must be disclosed: the labels are AI-produced with human adjudication, not independent human gold |
| D31 | Labeller records | Each labeller's model name and version, date, interface (chat or API), tools on/off and any customisation go in `annotation/<corpus_id>/ai/labelling_manifest.json`; any customised instructions are copied into `docs/` | ACCEPTED | Makes the AI labelling reproducible and auditable |
| D32 | Deterministic format repairs of AI replies (2026-10-08, made before any adjudication and before any result was seen) | Each repair is logged, counted per labeller in `labelling_manifest.json`, and reported on import; never silent. (a) A reply line holding several item codes (a whole reply collapsed onto one line) is split into one record per item code before the fields are parsed; item codes look like E001-01 and stand directly before a `|`; bare `
| D33 | Invalid AI items go to the author (2026-10-08, decided before any adjudication and before any result was seen) | After the D32 repairs, an item that still violates the D23 rules for a labeller (unknown subtype name, a catch-all subtype without a note, an invalid label, a missing item code, a duplicate item code) is recorded as INVALID for that labeller. It is never repaired by guessing and the AI is never re-asked. Valid items from that labeller are imported as normal. Invalid items are routed to the author's adjudication sheet exactly like disagreements. The same rule applies to every labeller | ACCEPTED | gpt's replies had content problems in 11 items; re-asking would give the AI a second try on every item of a chunk |
` line breaks and non-breaking spaces are handled. (b) A subtype field holding several names keeps ONE primary (Tier 1 beats Tier 2; within a tier the name listed first in `docs/SUBTYPES.md`) and moves the rest to other_subtypes (this extends the guide's own rule, which covers only Tier 1 pairs). A repair never changes the label, the tier of the primary beyond rule (b), or the hedged value; every other problem (unknown subtype, missing or duplicate item, missing note for a catch-all, bad label) still stops the import with the item codes | ACCEPTED | The first imports failed on format only: gemini wrote several subtypes in one field (14 items), gpt's replies arrived as one line per file |

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
- **D15-D19 implementation (2026-10-07).** All in `policy.py` (POLICY_VERSION 1.1.0, fingerprint pinned); the rule
  patterns and `rules.py` are untouched (`1d10799f...`, RULES_VERSION 1.0.0). `tools/reproduce_frozen.py
  --frozen-dir old_run` still reports 955/955 and 354/354.
  - D15: `escalate_clean` is a required `[detection]` key; with `policy=` the default is `"all"`; without a policy
    (old pipeline, regression tools) it stays `"attack_only"`.
  - D17: a hit is `hedged` if every sentence containing its match contains a lexicon word (whole words; `unlikely`,
    `maybe` and `appearance` do not count). Sentence records also carry `hedged` for the sentence.
  - D18: every rule layer is evaluated for every sentence (`rule_hits`, `subtypes`); the primary hit is the first
    Tier 1 hit in engine order, else the first counted hit, so without a contradicted duration it is exactly the
    engine's own deciding rule (tested on 300 synthetic explanations).
  - D19: claims are `<number> <unit>` (commas allowed, singular or plural). Consistent = within 10% of the true
    value in that unit, or equal to it rounded to the stated decimals ("0.09 seconds" for 92,190 us). A Tier 2
    `unit` hit in a sentence with a contradicted claim becomes Tier 1 `unit_wrong` (keeping `original_subtype:
    unit`); a contradicted claim with no `unit` hit becomes a `unit_wrong` hit of its own. At explanation level the
    check runs with the Tier 2 layer (C1, C3), so C0 and C2 remain exactly the old rule engine. At sentence level
    it always runs.
  - v2 prompts: the code expects exactly the seven files named by the paper side. The v2 sentence user message
    comes from `localize_sentence_template_v2.txt` (v1 stays in code). Templates must use exactly the placeholders
    `{evidence}` + `{explanation}` / `{evidence}` + `{sentence}`, or loading stops. v2 replies are parsed for
    tier and subtype (`policy.parse_v2_reply`); malformed parts are listed in `reply_problems`. A v2 verdict counts
    only if the policy counts its tier (a lenient judge that still says tier 2 is recorded but not counted).
  - `docs/SUBTYPES.md` (generated, tested in sync) is the exact subtype vocabulary.
- **Finding from the old run (D19/D17 applied to its 400 explanations, informational only).** 177 duration claims
  in 3,993 sentences; 176 contradict Flow Duration as microseconds (e.g. 30,777 -> "30.7 seconds",
  73,141,122 -> "20 hours"): the model read the value as milliseconds or seconds. 135 of the 136 Tier 2 `unit`
  hits become Tier 1 `unit_wrong`, which moves them into the lenient policy too. 80 of the 93 Tier 1 `reasoning`
  hits are hedged. (Old-run data: mostly benign flows, default temperature.)
- **D19 coverage gap in the old unit pattern.** The Tier 2 `unit` regex only knows hours/minutes/seconds, so
  "lasted 92 milliseconds" is not a `unit` hit; the D19 check still evaluates it (consistent -> no hit; wrong ->
  `unit_wrong`). A consistent millisecond/microsecond conversion is therefore never Tier 2. Not changed (rule
  patterns frozen); flagged for the paper side.
- **D20/D21 implementation (2026-10-07).** POLICY_VERSION 1.2.0 (fingerprint pinned in `tests/test_policy.py`); rule
  patterns untouched (`1d10799f...`); `tools/reproduce_frozen.py --frozen-dir old_run` still 955/955 and 354/354.
  - D20: a new policy-layer key `[duration stated with an explicit unit]` (Tier 2 `unit`) is added per sentence with
    at least one `<number> <unit>` claim and no rule-engine `unit` hit in that sentence. D19 then converts any `unit`
    hit (rule or D20) in a sentence with a contradicted duration to Tier 1 `unit_wrong`; a contradicted duration
    therefore always arrives via a `unit` hit (`original_key` records which). Without a Flow Duration the claim is
    still a Tier 2 `unit` hit, with `consistent: null`. Consequence: a correct restatement such as
    "36,203 microseconds" is a Tier 2 `unit` hit, so it counts under strict (not under lenient).
    **Confirmed intended by the paper side (2026-10-07):** correct restatements with a unit count as Tier 2 `unit`
    under strict. No code change.
  - D20 records: `policy_version` and `tier_map_sha256` are on every Phase 2/3 record produced with a policy, on
    every run record (`run.stamp`), and in `MANIFEST.json` under `policy`.
  - D21: the vocabulary marks the two catch-alls (`catch_all`); no rule maps to them (tested). v2 replies take an
    optional `note` field, required (non-empty) with a catch-all, else a `reply_problems` entry; parsed records carry
    `catch_all` and `note`. `policy.is_catch_all()` is the hook for separate counting (M5) and for the annotation
    import (M3: catch-all labels without a note are rejected).
- **D22 delivery (2026-10-07).** The files arrived in `paper_side_p1c/` (laid out like the project); they were copied
  into place unchanged (byte-compared), nothing existing was overwritten, and the delivery folder is git-ignored.
  Both v2 templates format with exactly their placeholders (tested). Rule gaps the paper side found are listed in
  `docs/KNOWN_RULE_GAPS.md` (rules unchanged, one test per gap).
- **M3 annotation tooling (2026-10-07, synthetic data only).** Choices within D5, D6, D8, D23:
  - Sample: 100 successfully generated attack-arm explanations, stratified by fine class (floor(100/k) per class, the
    remainder to classes in a seeded random order, a short class's deficit moved to classes with room; 14 classes ->
    7 or 8 each). The reliability (second annotator) and retest (same annotator, >= 7 days) subsets are 25 each,
    drawn from the 100, stratified, each with its own seeded stream, so they may overlap.
  - Blindness: sheets carry only evidence, sentence and explanation. Alert ids are NOT shown (they are assigned in
    class order and would leak the class); explanations get shuffled opaque ids (`E001`...; `T001`... on the retest
    sheet, in a new order, so first answers cannot be looked up). `key.json` maps back and must never reach the
    annotator. Every sentence of a sampled explanation is on the sheet (sentences as split by the pipeline,
    fragments under 15 characters excluded, ids = the pipeline's S1, S2...). A test fills every pipeline field with
    sentinel strings and checks none reaches the sheets.
  - Freeze guard: `annotation_export` refuses to run unless `git tag freeze-1` exists, is in HEAD, and the tree is
    clean; `--unfrozen` (pilot/synthetic only) is recorded in `key.json`. An export or an import is never overwritten.
  - Import (D23) also rejects, beyond the D23 list: hedged other than yes/no on a hallucinated row, hedged or
    other_subtypes on a grounded row, other_subtypes repeating the subtype, unsure other than yes/empty, missing,
    duplicate or unknown rows, and the rule-internal marker `soft_certainty`. A catch-all in other_subtypes also needs
    a note. All problems are listed at once with line numbers. Lines starting with `#` above the header are kept as
    file notes (the guide's integrity note). Excel's cp1252 CSV is accepted.
  - Gold: strict = `hallucinated`; lenient = any Tier 1 subtype among subtype and other_subtypes.
  - Agreement: Cohen's kappa (None when undefined) for label, lenient, tier (grounded / Tier 1 / Tier 2), Tier 1
    present, Tier 2 present, and per primary subtype; 95% CI by cluster bootstrap over explanations (2000 draws,
    seeded). Catch-all and unsure counts are reported separately. Disagreements (label or subtype) are written as
    an adjudication sheet.
  - For M5: the guide picks the primary subtype in its table order (port_not_in_evidence before patch_reference and
    attack_technique); the rule engine's primary follows its layer order (hard patterns before port/protocol). For
    sentences with several problems the primary subtypes can differ while both are right; subtype-level comparisons
    with the pipeline should use the full subtype sets (subtype + other_subtypes vs `subtypes`), not only the primary.
  - Open (no decision needed yet): whether `annotation/<run_id>/` (sheets, key, filled labels) is committed. It is
    not git-ignored now; the key should stay out of the annotator's view either way.
- **M3b pilot stage (2026-10-07, code only; the real pilot has not run).**
  - `configs/pilot.toml` equals `fresh_run.toml` except `[run]` (name `pilot`, `max_calls = 1500`), `[data]`
    (cap 3, benign 6) and its own cache directory `llm_cache/pilot`, so no pilot answer can ever be reused by the
    real run (D24: pilot output is discarded). `max_calls` is an optional `[run]` key (part of the config hash).
  - The run now has stages generate -> detect -> sentences for both arms (files `explanations.json`,
    `detection.json`, `sentences.json`, each also under `benign_control/`); the earlier rules-only
    `detection_rules.json` is replaced by `detection.json` (its C0/C1 rule hits are in every record).
  - Detection: one record per explanation x config x policy. Judge calls are shared through the cache: the v1
    prompt does not depend on the policy and C2/C3 send the same v2 prompt for a policy, so at most 3 calls per
    explanation (v1, v2-strict, v2-lenient). D15 escalation applies (`escalate_clean` from the config).
  - Sentences: rules with every layer on every sentence; only sentences the policy leaves ambiguous go to the
    sentence judge (style v1 for C0/C1, aligned v2 for C2/C3). No judge-on-every-sentence arm yet (to be added
    for the annotated sample only).
  - Every judge call is summarised in `judge`: prompt, raw reply, `reply_problems` ("bad JSON", "call failed", or
    the v2 parser's problems), and for v2 tier/subtype/note.
  - `max_calls`: the cached client stops before the call that would exceed it; finished stages are saved, the
    manifest records `status: stopped: ...`, and re-running continues from the cache.
  - `run --dry-run`: no API call, no API key, nothing written. Counts per stage the distinct calls not in the
    cache; detection/sentence counts are exact only for explanations already cached (otherwise an upper bound
    is printed for detection).
  - `pilot_report <run_id>`: calls, cache hits, tokens, wall time and rate-limit waits per stage; reply problems by
    kind; flagged share per config/policy per arm; 20 seeded-random v2 judge replies in
    `runs/<run_id>/samples/pilot_judge_replies.md`.
- **D25-D28 implementation (2026-10-07, before freeze-1).**
  - `hallucination_pipeline/corpus.py` (`cli analyze_corpus`): every usable explanation split into sentences; every
    sentence gets every rule layer plus policy 1.2.0 (D17-D20). Rules only: a sentence the policy leaves
    ambiguous (soft certainty only) is NOT flagged (no judge, D27); their number is in the manifest. Groups from
    `alert_type` (`Normal Traffic` = benign-flow). 2 explanations are `[GENERATION FAILED]` (both benign-flow) and
    are excluded and reported, so 398 are analysed. Explanation flags = any flagged sentence.
  - Results in `results/<corpus_id>/` (`corpus_id` = hash of the input files plus rule/policy fingerprints; never
    overwritten): prevalence per tier/subtype under both policies at both levels, attack-flow vs benign-flow with
    the CI of the difference, hedged/unhedged attack_technique hits, every stated duration and the unit_wrong share,
    port_not_in_evidence counts and examples, flagged sentences per explanation, 20 random flagged sentences per
    tier. 95% CIs: percentile bootstrap over explanations, 2000 draws, seed 42 (each group resampled on its own
    for differences). Every CSV starts with the source line; JSON records carry it.
  - The 132 old rewrites are rebuilt exactly as `tools/reproduce_frozen.py` does, which also needs
    `phase3_predictions.json` and `hallucination_masks.json` from `old_run/` (hashed into the manifest). Each is
    checked for numbers absent from the evidence, and for numbers absent from both evidence and the original
    sentence (the audit's measure; reproduces 28 of 132, tested when `old_run/` is present).
  - `hallucination_pipeline/audit.py`: the D28 sample (per-class seeded draws), exported with the M3 blind export
    (primary sheet only, shuffled opaque ids), imported with the D23 rules (`annotation_import`), then rules-versus-
    human precision, recall and F1 under both policies, at sentence and explanation level, overall and per group,
    with bootstrap CIs, n shown, and the disagreement list (`cli audit_metrics`). The corpus id for tonight is
    `corpus-7247d3e7` (250 sentences to label).
  - Freeze guard change (before the tag): `freeze_tag_ok` now ignores untracked files, so output folders
    (`results/`, `annotation/`) do not block an export; changed tracked files still do.
  - The runbook is `docs/RUNBOOK_TONIGHT.md`: label first, then analyse (the annotator must not see results first).
- **Freeze guard, as built (2026-10-07, reviewed after freeze-1, not changed).** `annotation.freeze_tag_ok` requires:
  the tag exists; the tag is an ancestor of HEAD (NOT an exact match, so later commits are fine); no tracked file has
  uncommitted changes. Known gap: it does not compare committed changes to the frozen files against the tag, so a
  frozen file changed AND committed after freeze-1 would not be refused by the guard. Closing that would mean editing
  `annotation.py`, itself a frozen file, which a frozen-files check would then report as changed since freeze-1.
  Until the paper side decides, the runbook's `git diff --stat freeze-1 -- ...` check (must print nothing) covers it.
- **D30/D31 implementation (2026-10-08, after freeze-1, tools/ only).** `tools/ai_labelling.py` (`ai_export`,
  `ai_import`, `ai_compare`, `ai_finalize`) uses the frozen annotation, audit and corpus code read-only;
  `git diff --stat freeze-1 -- hallucination_pipeline configs docs/ANNOTATION_GUIDE_v2.md` stays empty. Tests:
  `tests/test_ai_labelling.py` (offline). `docs/AI_LABELLER_PROMPT.md` (the author's text) is committed as delivered.
  - Chunks: 5 explanations each, built only from the blind sheet (explanation code, evidence lines, `[ITEM_CODE]
    sentence`); no class, alert id or pipeline field (tested).
  - Import: one line per item, `ITEM_CODE | label | subtype | hedged | other_subtypes | note | unsure`; tolerated:
    code fences, bullets/numbering, extra spaces, leading/trailing `|`, table header and separator rows, prose
    lines (ignored and counted); `-`, `none`, `null`, `n/a` read as empty. Then the frozen D23 importer. Every
    problem is listed with its item code; nothing is written unless all items are valid. No re-import once the
    adjudication sheet exists.
  - Agreement between the AIs = same label, subtype AND hedged. Kappa (overall, lenient, tier, Tier 1, Tier 2, per
    subtype) via the frozen `annotation.agreement`; hedged kappa on items both call hallucinated.
  - Adjudication sheet: every disagreement + round(20% of agreements) (seeded), shuffled, D23 columns empty, no AI
    answer. Which items were disagreements, both answers and the kappa details are in `ai/hidden/`, not to be
    opened before adjudication is finished.
  - Consensus for non-adjudicated items: the shared label, subtype and hedged; other_subtypes = union; notes joined
    if different; unsure if either was unsure.
  - Overrule rate = share of spot-check items where the author's label or subtype differs from the AI consensus.
    The final labels, metrics and JSON all carry the D25 source line and the D30 label line.
- **Caveats for the write-up (D30).** (1) If one labeller is a Gemini model, it shares a family with the generator
  (gemini-2.5-flash), which can bias it towards the generator's framing. (2) The prompt says the evidence has nine
  numbers, but the earlier run's evidence strings have fewer lines (the old builder dropped some fields, e.g. the
  first audit item has 6); chunks show the evidence exactly as stored, nothing is invented. (3) The labeller prompt
  restates the guide's taxonomy, which the rules also implement, so rules-vs-AI agreement is not independent evidence
  of correctness; the blind spot-check overrule rate is the main check on label quality.

- **Finding: evidence completeness in the earlier run (2026-10-08, `tools/evidence_completeness.py`, read-only).**
  All 398 explanations used by the corpus analysis (63 attack-flow, 335 normal-flow) had exactly 6 evidence lines:
  Destination Port, Flow Duration, Forward Packets, Flow Bytes/s, Flow Packets/s and ACK Flag Count. Backward Packets,
  SYN Flag Count and RST Flag Count are missing in every alert, in both groups (a systematic property of the earlier
  run's evidence, not random gaps). Flow Duration is present in all 398, so the D19 unit_wrong check applies to every
  alert. Consequence for labelling (no decision taken here): `docs/AI_LABELLER_PROMPT.md` and the guide say the model
  saw nine numbers, and the guide's grounded example "No packets were sent back to the source" relies on Backward
  Packets; for this corpus the model never saw Backward Packets, SYN or RST counts, so such statements are not
  derivable from its evidence. The paper side should decide, before labelling, how labellers treat them.
- **D32 implementation (2026-10-08, tools/ only).** `tools/ai_labelling.py`: `normalise_text` (
 and 
 line breaks,
  non-breaking and zero-width spaces), `split_collapsed` (split before every item code that directly precedes a `|`;
  a numbering marker such as `2.` left at the end of a split record, and code-fence backticks glued to a record, are
  dropped as formatting), `repair_multi_subtype` (only on lines labelled `hallucinated`; a multi-subtype field on any
  other label, or one containing an unknown name, is NOT repaired and stops the import). Counts go to
  `labelling_manifest.json` under `format_repairs.<labeller>`; the per-item details (which reveal an AI's answers) go
  to `ai/hidden/format_repairs_<labeller>.json`. The reply files themselves are never modified. Frozen files untouched.
- **D33 implementation (2026-10-08, tools/ only).** `ai_import` checks each item on its own with the frozen D23
  importer (one-item sheet) and records failures with a reason code (`unknown_subtype`, `catch_all_without_note`,
  `invalid_label`, `label_blank`, `subtype_missing`, `grounded_with_subtype`, `invalid_hedged`, `hedged_on_grounded`,
  `other_subtypes_on_grounded`, `repeated_subtype`, `invalid_unsure`, `missing`, `duplicate`, `too_many_fields`,
  `multi_subtype_not_repairable`). Any D23 violation makes an item invalid, not only the ones named in D33. A
  duplicated code makes the item invalid (neither copy is used). Lines with item codes that are not on the sheet are
  ignored and counted. Only whole-import problems stop it: no reply files, a file that is not UTF-8 text, or no item
  code at all. `labels_<name>.json` holds valid items only; codes and reasons are in `ai/hidden/invalid_<name>.json`;
  `labelling_manifest.json` gets counts per labeller under `import.<name>` (valid, invalid or missing, missing,
  invalid by reason, lines ignored) next to `format_repairs.<name>` (D32). The terminal shows counts only.
  `ai_compare` computes kappa on items valid for both labellers and reports how many were excluded; the adjudication
  sheet holds every disagreement, every item invalid or missing for either labeller, and round(20%) of the
  agreements (seed 42), shuffled, with no answer and no reason; `hidden/adjudication_key.json` gives each item's
  reasons (`disagreement`, `invalid-<name>`, `spot-check`). `ai_finalize` and every output state "N items invalid
  or missing for at least one labeller were adjudicated by the author".


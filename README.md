# LLM Hallucination Localization & Selective Unlearning Pipeline
### Cybersecurity alert explanations on CIC-IDS 2017

**Research question.** How can hallucinated or unsupported claims in LLM-generated
cybersecurity alert explanations be *localized* (which sentence, what kind) and
*selectively corrected* without retraining the model?

The pipeline: build evidence-only alerts from network flows -> have an LLM explain
them -> detect hallucinated explanations -> localize the hallucinated sentences ->
remove or rewrite them -> measure what that did.

---

**Developing this project?** Start with `docs/EXPERIMENT_PLAN.md`, `docs/TASKS.md`, `docs/HANDOFF.md` and `docs/DECISIONS.md`.

## Provenance

This is an independent rewrite of an earlier group project built around this idea.
The earlier code worked but was hard to trust or reuse: three of its files were
60-75% dead code (each held two or three stacked copies of itself, all but the last
commented out), its README named the wrong API key variable, and its run order
skipped a step. This rewrite has one copy of everything, a package structure,
tests, and a way to prove it still behaves like the original (below).

## Verification: does the rebuild behave like the original?

`tools/verify_against_original.py` runs the **original scripts** and **this rebuild**
side by side on the same synthetic inputs (400 alerts, ~1,950 sentences), through every
stage, with the same deterministic fake Gemini client for both. The fake client includes
the awkward cases: HTTP 429 rate limits with a retry delay, generic errors, fenced and
malformed JSON, unchanged rewrites, and rewrites that fail every retry.

```bash
python tools/verify_against_original.py --original-dir /path/to/original/files
```

Result: **every output file is identical** - evidence-pure alerts, explanations,
explanation-level detection, sentence-level localization, masks, corrected explanations,
effect analysis, impact analysis, end-to-end metrics, and both markdown reports - apart from
the deliberate deviations listed next. This verifies the *logic*. It cannot verify real
Gemini behaviour, which is non-deterministic; see the notes on reproducing results.

### Deliberate deviations from the original

| Deviation | Why |
|---|---|
| Qualitative before/after examples are aligned using the masks | The original paired a flagged sentence with the wrong "corrected" sentence whenever an earlier sentence in the same explanation had been removed (it indexed the corrected list by the *original* sentence number). The verification run reproduced this: a flagged CVE sentence was shown with an unrelated surviving sentence as its "correction". **Check any before/after examples in the paper.** |
| `evidence_tokens` are sorted | The original wrote `list(set(...))`, whose order changes between runs, so files differed byte-for-byte run to run. |
| Impact report says the real alert count | The original hard-coded "all 400 alerts" in its report text. |
| Total rewrite failure keeps the (softened) original sentence | An early draft of this rebuild inserted a bracketed placeholder instead; the original's behaviour was the right one. |
| Loader drops every benign label (`BENIGN`, `Normal Traffic`, `normal`) | The original excluded only `BENIGN`. On the processed 'Attack Type' version of CIC-IDS 2017, benign flows are named `Normal Traffic`, so 337 of the 400 "attack-class" alerts in the frozen data were actually benign traffic. |
| Gold labels may be booleans or the strings `hallucinated`/`grounded` | The original evaluated explanation-level labels with `1 if gold else 0`, which counts the string `'grounded'` as hallucinated (precision 1.00 / recall 0.24 on the frozen file instead of 0.94 / 1.00). |
| `HALLUC_ROOT` environment variable | Lets two experiments (a reproduction run and a fresh run) keep separate data trees. |

## Things about the original method worth stating in the paper

These come from reading and testing the original behaviour, not from the rebuild:

1. **Phase 4 is driven by human gold labels where they exist.** Masks use the gold label
   first and the pipeline's prediction only as a fallback. So the Phase 4 results measure
   mitigation *given accurate localization* - an upper bound - not the fully automatic
   pipeline. Run Phase 4 with no gold labels filled in to measure the automatic case.
2. **Hallucination reduction is measured with the same rule engine that produced most of the
   Phase 3 labels.** That is partly circular. The independent LLM re-check
   (QUALIFY effectiveness) is the less circular signal; report both.
3. **The threat-actor rule matches "an attacker" but not "the attacker"** (and needs "port
   scanning"/"network scanning", not bare "scanning"). Real, narrow coverage gaps, preserved
   deliberately (see `tests/test_rules.py`) because changing a rule changes the results.
4. **Dataset-version hazard.** The "clean on an attack-class alert -> double-check with the
   LLM" escalation matches coarse labels (`DoS`, `DDoS`, `Port Scanning`, ...). A CIC-IDS 2017
   copy with only the fine-grained `Label` column (`DoS Hulk`, `PortScan`, `FTP-Patator`) will
   match few of them and silently consult the LLM judge less. State which version you used.
5. **Four measurement bugs were found and fixed over the project's life** (all documented in
   the code): a nonsensical "-413% reduction" from comparing different alert sets; an LLM
   re-check that silently passed everything because of unparsed thinking-mode output; QUALIFY
   pairs silently dropped by a text-prefix match; and the qualitative-example misalignment above.

## Reproducing results from frozen artifacts

`tools/reproduce_frozen.py` recomputes the paper's tables from saved outputs and tests the rebuild against them. It is deterministic and needs no API key.

```bash
python tools/reproduce_frozen.py --frozen-dir /path/to/frozen --out REPRODUCTION_REPORT.md
```

It reports (A) whether this code reproduces the frozen run (rule decisions, masks), (B) each paper table versus the recomputed value, and (C) further findings the data supports (dataset composition, coverage, label stability, rewrite quality). Figures that depend on a live LLM, such as the LLM re-check effectiveness, are reported as not checkable rather than guessed.

## Setup

```bash
pip install -r requirements.txt
export GEMINI_API_KEY="your-key-here"      # the variable is GEMINI_API_KEY: this project uses Gemini
```
`.env.example` is a template only; the scripts read the environment, not the file.

Get CIC-IDS 2017 from https://www.unb.ca/cic/datasets/ids-2017.html and put the CSVs in
`data/raw/`.

## Run order

```bash
python -m hallucination_pipeline.cli load        # 1. evidence-pure alerts
python -m hallucination_pipeline.cli generate     # 2. LLM explanations        (API key)
python -m hallucination_pipeline.cli detect        # 3. explanation-level flags  (API key)
python -m hallucination_pipeline.cli localize       # 4. sentence-level labels    (API key)

#   ---- MANUAL: fill in `gold_label` fields; see docs/archive/ANNOTATION_GUIDE_v1.md (old run) ----

python -m hallucination_pipeline.cli unlearn         # 5. REMOVE / QUALIFY / KEEP  (API key)
python -m hallucination_pipeline.cli impact           # 6. before/after impact      (API key)
python -m hallucination_pipeline.cli evaluate          # 7. precision / recall / F1
python -m hallucination_pipeline.cli report             # 8. markdown results
python -m hallucination_pipeline.cli status              # what exists, what's missing
```

## Fresh controlled run (M0-M1)
```bash
python -m hallucination_pipeline.cli run --data-only    # sample only, no API key needed -> runs/<run_id>/
python -m hallucination_pipeline.cli run                # + generation (needs GEMINI_API_KEY) + rule detection
python -m hallucination_pipeline.cli run --dry-run      # count the LLM calls a run would make; no calls
python -m hallucination_pipeline.cli run --config configs/pilot.toml       # M3b pilot (needs GEMINI_API_KEY)
python -m hallucination_pipeline.cli pilot_report <run_id> --config configs/pilot.toml
python -m hallucination_pipeline.cli freeze_run <run_id> # SHA256SUMS + read-only
python -m hallucination_pipeline.cli verify_run <run_id>
python tools/make_outbox.py P1 <run_id>                  # zip for the paper side
```
Annotation (after `git tag freeze-1`; see `docs/ANNOTATION_GUIDE_v2.md`):
```bash
python -m hallucination_pipeline.cli annotation_export <run_id>
python -m hallucination_pipeline.cli annotation_import <run_id> filled.csv --sheet primary --annotator NAME
python -m hallucination_pipeline.cli annotation_agreement <run_id> annotation/<run_id>/imported/primary_NAME.json annotation/<run_id>/imported/retest_NAME.json
```
Settings live in `configs/fresh_run.toml`; the run id is derived from them. LLM answers are cached in
`llm_cache/`, so re-running costs nothing.

## Tests

```bash
pytest tests/        # 46 offline tests: no API key, no dataset
```
They cover the rule engine, the Phase 4 decisions (including gold-label priority and the
fallback behaviour), the sentence-alignment regressions, the verbatim prompts, and the
evidence-purity guarantee. They do not call Gemini.

## Layout

```
hallucination_pipeline/
  config.py                 paths, model, API-key variable (HALLUC_ROOT overrides the data root)
  prompts/                  the 8 LLM prompts, extracted byte-for-byte from the original experiment
  prompt_store.py           loads them
  data_loader.py            Phase 1: CIC-IDS -> evidence-pure alerts
  explanation_generator.py  Phase 2.2: LLM explanations
  detection/                patterns.py (the one copy of every rule) + rules.py
  detection_pipeline.py     Phase 2.3 + 3: hybrid rule+LLM detection and localization
  unlearning.py             Phase 4: masks, type-aware rewrites, reconstruction
  impact_analysis.py        Phase 5.8: before/after impact (three documented bug fixes)
  evaluation.py             Phase 5.6: precision / recall / F1, qualitative examples
  reporting.py              Phase 5.7: markdown report
  llm_client.py             Gemini wrapper: retries, 429 handling, JSON parsing
tools/verify_against_original.py     differential verification against the original
tests/                               offline tests
docs/ANNOTATION_GUIDE_v2.md          how to label (fresh run); v1 in docs/archive/
```

The prompts are part of the method. Edit them only deliberately: changing a word changes
what the model does, and therefore the results.

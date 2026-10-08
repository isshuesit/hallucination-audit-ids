# Auditing unsupported claims in LLM-generated IDS alert explanations

This repository audits **hallucinated (unsupported) claims** in explanations that a large language model wrote for
network-intrusion alerts. Each explanation was generated from a handful of numeric flow features of the
CIC-IDS 2017 dataset, with no attack label. A claim is unsupported when it says something those numbers do not
support. The repository holds a rule-based detector, a two-tier taxonomy, the analysis of an existing corpus of 400
explanations, a 25-explanation label audit, and every file needed to reproduce the reported numbers offline.

Paper: *placeholder, Zenodo DOI to be added: https://doi.org/10.5281/zenodo.XXXXXXX*

## The taxonomy in five lines

1. **Grounded:** the sentence restates the evidence numbers or follows from them by arithmetic.
2. **Tier 1, unsupported specifics:** invented specifics (CVE, tool, version, IP address, a port or protocol absent from the evidence, a wrong duration unit, a patch), attack techniques and threat actors (hedged or not), impact and outcome claims, and definitive certainty.
3. **Tier 2, knowledge beyond the numbers:** what a port in the evidence is used for, TCP/protocol norms, encryption assumptions, comparisons with "normal" traffic, and a correct unit attached to the raw duration.
4. **Strict policy:** Tier 1 and Tier 2 count as hallucinations. **Lenient policy:** only Tier 1 does.
5. The exact subtype names are in [docs/SUBTYPES.md](docs/SUBTYPES.md), and the rule-to-tier table is in [docs/RULE_TIERS.md](docs/RULE_TIERS.md).

## Headline results

*Source of every number: earlier run, API-default sampling, prompt v1, 63 attack-flow and 337 benign-flow
explanations; not generated under freeze-1.* 398 explanations were analysed (2 benign-flow generations had failed).
Rules only, no LLM call. 95% confidence intervals use a percentile bootstrap over explanations (2000 draws, seed 42).
All numbers are copied from [results/corpus-7247d3e7/REPORT.md](results/corpus-7247d3e7/REPORT.md) and
[results/corpus-7247d3e7/audit_ai/](results/corpus-7247d3e7/audit_ai/).

**Prevalence, detected by the rules (explanation level, n = 398):**

| | strict (Tier 1 + 2) | lenient (Tier 1 only) |
|---|---|---|
| all | 92.5% [89.7%, 95.0%] (368/398) | 53.5% [48.5%, 58.3%] (213/398) |
| attack-flow (n = 63) | 95.2% [88.9%, 100.0%] | 69.8% [58.7%, 81.0%] |
| benign-flow (n = 335) | 91.9% [89.0%, 94.6%] | 50.4% [45.1%, 55.8%] |

- **Durations:** 176 of 177 stated durations (99.4% [98.2%, 100.0%]) contradict Flow Duration read as microseconds.
- **Hedging:** 76 of 88 attack-technique mentions (86.4% [78.2%, 93.5%]) were hedged ("could", "may", "consistent with").
- **Old rewrites:** of the earlier run's 132 automatic rewrites, 28 contain a number absent from both the evidence and the original sentence.

**Label audit (25 explanations, 250 sentences).** Labels: two AI annotators (gemini: Gemini 1.5; gpt: GPT-5.6
Luna 5.6), author-adjudicated; 54 disagreements; 10 items invalid or missing for at least one labeller were
adjudicated by the author; 20% blind spot-check (37 items); overrule rate 14% (5/37).

| rules vs labels, sentence level | n | label positives | rule positives | precision | recall | F1 |
|---|---|---|---|---|---|---|
| strict | 250 | 142 | 50 | 1.00 [1.00, 1.00] | 0.35 [0.28, 0.44] | 0.52 [0.43, 0.61] |
| lenient | 250 | 40 | 14 | 1.00 [1.00, 1.00] | 0.35 [0.21, 0.51] | 0.52 [0.35, 0.68] |

At explanation level, lenient recall is 0.50 [0.29, 0.71] (12 of 24 positive explanations found). Strict
explanation-level metrics are uninformative: all 25 audited explanations are positive for both the rules and the
labels. Per-group rows are in `audit_ai/audit_metrics.csv`.

## Limitations

- **Existing corpus.** The 400 explanations come from an earlier run (gemini-2.5-flash, API-default sampling,
  prompt v1). They were not generated under the frozen protocol, and 337 of the 400 are benign flows. The evidence
  of every alert has 6 of the 9 intended features: Backward Packets, SYN and RST counts are missing
  (`results/corpus-7247d3e7_extra/`).
- **Small audit.** 25 explanations (12 attack-flow, 13 benign-flow), one adjudicator, no second pass, so the
  intervals are wide.
- **AI-annotated, author-adjudicated labels.** The labels are not independent human gold labels (decision D30).
  One labeller (Gemini 1.5) shares a model family with the generator. The labeller instructions and the rules
  implement the same taxonomy, so the perfect precision is not independent evidence of correctness.
- **Rules have low recall.** The rules miss most unsupported sentences the labels identify (sentence recall about
  0.35). Known gaps are listed in [docs/KNOWN_RULE_GAPS.md](docs/KNOWN_RULE_GAPS.md). No LLM judge, prompt-v2 or
  rewrite arm was run (D27).
- Every decision, including those made after the freeze, is logged in [docs/DECISIONS.md](docs/DECISIONS.md).

## Reproduce the results offline

No API key and no network access are needed. Python 3.11 or newer.

```bash
pip install -r requirements.txt
python -m pytest tests/ -q                     # all tests run offline
git diff --stat freeze-1 -- hallucination_pipeline configs docs/ANNOTATION_GUIDE_v2.md   # prints nothing: frozen code unchanged
python tools/reproduce_corpus_results.py       # re-runs everything into a temp folder and compares
```

`reproduce_corpus_results.py` re-runs the rule analysis (`analyze_corpus`), the label merge and audit
(`ai_finalize`, from the committed AI labels and the author's adjudication sheet), and the evidence-completeness
tables. It compares each re-run output with the committed one and prints `REPRODUCED` if every file matches.

The underlying commands write into the repository and refuse to overwrite. To run them directly, first move the
committed outputs aside (`results/corpus-7247d3e7/`, and `final_labels.csv` and `final_summary.json` in
`annotation/corpus-7247d3e7/ai/`):

```bash
python -m hallucination_pipeline.cli analyze_corpus
python tools/ai_labelling.py ai_finalize --labellers gemini gpt --author IS
```

The earlier run's audit of its own reported numbers can be reproduced with
`python tools/reproduce_frozen.py --frozen-dir old_run`.

## Repository layout

```
hallucination_pipeline/   detector, two-tier policy, sampling, annotation and corpus-analysis code (frozen at tag freeze-1)
configs/                  run configurations (frozen)
tools/                    AI-labelling workflow, reproduction and audit tools
tests/                    offline test suite (fake LLM; no API key)
docs/                     decisions log, subtype vocabulary, rule-tier table, annotation guide v2, AI labeller prompt,
                          known rule gaps, experiment plan, runbook
old_run/                  the earlier run's 7 JSON files: the corpus being audited (see DATA.md)
results/corpus-7247d3e7/  results pack: REPORT.md, MANIFEST.json, tables/, samples/, sentences.jsonl, audit_ai/
results/corpus-7247d3e7_extra/   evidence-completeness tables (post-hoc, descriptive)
annotation/corpus-7247d3e7/      blind sheet and key, AI chunks and replies, AI labels, adjudication sheets,
                                 final labels, labelling manifest; ai/hidden/ holds what was hidden during adjudication
data/raw/                 place the CIC-IDS 2017 CSVs here to re-run sampling (not included)
```

The full pipeline for a new, controlled generation run (sampling, Gemini generation, C0-C3 detection, pilot) is in
the code. It was not run for these results. The earlier pipeline documentation is archived in
[docs/archive/README_pipeline_v1.md](docs/archive/README_pipeline_v1.md).

## Data and citation

CIC-IDS 2017 belongs to the Canadian Institute for Cybersecurity, University of New Brunswick, and must be cited
when used. The raw dataset is **not** included. See [DATA.md](DATA.md).

> Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani. *Toward Generating a New Intrusion Detection Dataset
> and Intrusion Traffic Characterization.* Proceedings of the 4th International Conference on Information Systems
> Security and Privacy (ICISSP), 2018, pp. 108-116.

To cite this repository, use [CITATION.cff](CITATION.cff). License: [MIT](LICENSE).

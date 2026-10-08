# Existing-corpus study corpus-7247d3e7

**source: earlier run, API-default sampling, prompt v1, 63 attack-flow and 337 benign-flow explanations; not generated under freeze-1**

Rules only (no LLM call, D27); every rule layer plus policy 1.2.0 checks on every sentence. 95% CIs: percentile bootstrap over explanations (2000 draws, seed 42).

| group | explanations analysed | excluded (generation failed) | sentences |
|---|---|---|---|
| attack-flow | 63 | 0 | 634 |
| benign-flow | 335 | 2 | 3357 |

## Headline prevalence (explanation level)

| group | category | n | count | rate [95% CI] |
|---|---|---|---|---|
| all | flag (strict) | 398 | 368 | 92.5% [89.7%, 95.0%] |
| attack-flow | flag (strict) | 63 | 60 | 95.2% [88.9%, 100.0%] |
| benign-flow | flag (strict) | 335 | 308 | 91.9% [89.0%, 94.6%] |
| all | flag (lenient) | 398 | 213 | 53.5% [48.5%, 58.3%] |
| attack-flow | flag (lenient) | 63 | 44 | 69.8% [58.7%, 81.0%] |
| benign-flow | flag (lenient) | 335 | 169 | 50.4% [45.1%, 55.8%] |
| all | any Tier 1 | 398 | 213 | 53.5% [48.5%, 58.3%] |
| attack-flow | any Tier 1 | 63 | 44 | 69.8% [58.7%, 81.0%] |
| benign-flow | any Tier 1 | 335 | 169 | 50.4% [45.1%, 55.8%] |
| all | any Tier 2 | 398 | 321 | 80.7% [76.6%, 84.4%] |
| attack-flow | any Tier 2 | 63 | 54 | 85.7% [76.2%, 93.7%] |
| benign-flow | any Tier 2 | 335 | 267 | 79.7% [75.2%, 84.2%] |

## Durations

| group | claims | unit_wrong | share [95% CI] |
|---|---|---|---|
| all | 177 | 176 | 99.4% [98.2%, 100.0%] |
| attack-flow | 36 | 36 | 100.0% [100.0%, 100.0%] |
| benign-flow | 141 | 140 | 99.3% [97.7%, 100.0%] |

## Hedged attack_technique hits

| group | hits | hedged | share [95% CI] |
|---|---|---|---|
| all | 88 | 76 | 86.4% [78.2%, 93.5%] |
| attack-flow | 17 | 15 | 88.2% [72.7%, 100.0%] |
| benign-flow | 71 | 61 | 85.9% [77.1%, 93.8%] |

## Old rewrites

132 rewrites; 32 contain a number absent from the evidence; 28 contain a number absent from both the evidence and the original sentence.

All tables (CSV, n in every row) are in `tables/`; sentence-level records in `sentences.jsonl`.
Known rule gaps that lower these counts: `docs/KNOWN_RULE_GAPS.md`.

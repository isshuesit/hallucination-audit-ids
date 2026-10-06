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

## Open items for the human to confirm (defaults apply until answered)
- Is a second human annotator available for D6? (default: no -> test-retest)
- Annotation size D5 (default 100 explanations, about 1000 sentences, about 8 hours). Minimum acceptable: 60.
- API budget / rate limits for Gemini (default: free tier with caching and resume).

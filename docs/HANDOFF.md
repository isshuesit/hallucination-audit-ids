# Handoff protocol — code side <-> paper side

Two workspaces, one project. **The code side owns code, runs and tests. The paper side owns definitions,
wording, interpretation and the manuscript.** They never edit each other's territory directly; they pass
files. The human (you) carries files between them.

## Who owns what
| Code side (VS Code) | Paper side |
|---|---|
| Code, tests, git, run execution | Research design, taxonomy and policy definitions |
| Run manifests, caches, metric computation | Annotation guide, prompt wording (v2 files) |
| Table / figure data exports | Claim audit, literature, interpretation, the manuscript |
| `docs/TASKS.md` status | `docs/DECISIONS.md` approvals |

## The two directions

### Inbox (paper side -> code side)
| Artifact | Why | Rule |
|---|---|---|
| `docs/DECISIONS.md` entries | Taxonomy, policy, sample sizes, config defaults | The code side follows them; disagreement goes in as a `PROPOSED` entry |
| Prompt files `*_v2.txt` | Judge (strict / lenient) and generation v2 | Added as **new files**, hashed in the manifest; v1 files are never edited |
| `ANNOTATION_GUIDE_v2.md` | Defines labels for the human annotator | Frozen at `freeze-1` |
| Table specs (exact columns, rows) | So exports match the paper | Added to `docs/TABLE_SPECS.md` |

### Outbox (code side -> paper side)
Zip the following and upload to the paper chat. **Never include** `.env`, API keys, raw CIC-IDS CSVs, or
the LLM cache.
| Artifact | Contents |
|---|---|
| `MANIFEST.json` | commit, versions, model string, config hash, rules version, prompt hashes, dataset hashes, counts, tokens |
| `class_distribution.json` | realized per-class counts (asserted attack-only) |
| `tables/*.csv`, `metrics.json` | every number that could appear in the paper |
| `paper_numbers.json` | the single source the manuscript cites |
| `samples/*.json` | 20 random qualitative cases per arm |
| `anomalies.md` | anything surprising, failures, retries, fallbacks |
| `DECISIONS.md` | with new `PROPOSED` entries |
| `test_summary.txt` | `pytest` output |

### Outbox log
| Pass | Built by | Contents |
|---|---|---|
| P1 | `python -m hallucination_pipeline.cli run --data-only` then `python tools/make_outbox.py P1 <run_id>` -> `outbox/P1_<run_id>.zip` | `MANIFEST.json`, `class_distribution.json`, `anomalies.md`, `DECISIONS.md` (D11, D12 ACCEPTED; D13 PROPOSED), `test_summary.txt` |

## Pass-through schedule
| # | After | Direction | What moves | Purpose |
|---|---|---|---|---|
| P0 | now | paper -> code | this package, `DECISIONS.md` D1-D8 | start M0 |
| P1 | M1 | code -> paper | manifest, `class_distribution.json` | confirm the sample is attack-only and balanced |
| P1b | M2 | code -> paper | rule -> tier table; proposed judge prompts | sign off the policy before anything is measured |
| P1c | P1b | paper -> code | final prompts v2, annotation guide v2 | enables M3 |
| P2 | M3 + freeze | code -> **human** -> code | blind sheets out; filled sheets back | gold labels (annotators never see predictions) |
| P2b | import | code -> paper | agreement report (kappa, adjudication list) | decide whether labels are good enough to proceed |
| P3 | pilot | code -> paper | pilot manifest, cost, failures | adjust before the full run |
| P4 | full run | code -> paper | frozen run package | write results and discussion |
| P5 | writing | both | `paper_numbers.json` locked | final numbers; any later code change forces a diff |

## Number integrity (non-negotiable)
1. Paper numbers are never typed by hand. The manuscript cites values from `paper_numbers.json` by key
   (for example `det.C1.strict.recall`), and each number carries the `run_id` that produced it.
2. If code changes after the lock, regenerate `paper_numbers.json` and diff it. The paper side reviews
   every changed number before the manuscript is touched.
3. Post-freeze changes to rules, prompts or config are logged in `DECISIONS.md` as **post-hoc** and are
   disclosed in the paper.

## Handling disagreement
The code side finds a problem with a decision -> writes a `PROPOSED` entry with evidence and continues with
the current decision. The paper side answers in the next pass-through. Neither side resolves it silently.

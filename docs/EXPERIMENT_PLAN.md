# Experiment plan — fresh run

Status: DRAFT v1 (paper side). Values marked **[default]** can be changed only via `docs/DECISIONS.md`.

## 1. Overarching question
How can hallucinated or unsupported claims in LLM-generated cybersecurity explanations be detected,
localized and corrected at the output level, without retraining the model?

## 2. Research questions
- **RQ1 — What and how much?** What kinds of unsupported claims does Gemini make when explaining
  evidence-only IDS flows, and how common are they per attack class under a *strict* versus a
  *lenient* hallucination policy?
- **RQ2 — Detection and localization.** How well does the hybrid rule+LLM detector find them, at explanation
  level and sentence level, against independent human labels, and what does each component add
  (external-knowledge rule layer, policy-aligned judge)?
- **RQ3 — Mitigation.** How much does output-level correction (REMOVE / QUALIFY, with numeric-fidelity
  validation) reduce unsupported claims while retaining information, compared with simply improving the
  generation prompt?

## 3. Why the design differs from the old run
| Old-run problem (found in audit) | Fresh-run answer |
|---|---|
| 84% of "attack" alerts were benign flows | Attack-only, stratified sampling; benign flows only as a separate control arm |
| Phases 2/3/4 came from different runs and rule versions | One `run_id`; `rules_version` + prompt hashes on every record |
| Gold labels unstable (kappa 0.16), annotators saw predictions | Blind annotation, double-labelled subset, kappa + test-retest |
| Phase 2 detector had no external-knowledge layer and a judge told to ignore it | Ablation C0-C3 (section 6) |
| "Hallucination" mixed hard fabrication with harmless background knowledge | Two-tier taxonomy; strict and lenient policies reported side by side |
| Phase 3 evaluated only on explanations Phase 2 flagged | Annotated sample drawn from *all* explanations; unconditional recall |
| Phase 4 driven by gold labels; no automatic result | `gold_driven` (upper bound) and `automatic` modes both reported |
| Rewrites introduced unsupported numbers; rules could not see it | Numeric-fidelity validator with retry/fallback; ablated |
| Natural data had no factual fabrications, so REMOVE never ran | Controlled injection experiment (E4) |
| No comparison to "just fix the prompt" | Prompt-only mitigation arm (E3) |

## 4. Data
- **Source [default]:** original UNB CIC-IDS 2017 CSVs (`MachineLearningCVE`), fine-grained `Label`.
  Record the SHA-256 and row count of every CSV in the manifest. Also store the coarse mapping
  (DoS*, DDoS, PortScan->Port Scanning, *-Patator->Brute Force, Web Attack*, Bot->Botnet, ...).
- **Sampling [default]:** attack classes only, `per_class_cap = 30`, seed 42, stratified by fine label,
  using all rows of classes smaller than the cap (Heartbleed 11, SQL injection 21). Expected N about 390.
  Print and assert the realized per-class counts.
- **Evidence:** exactly the evidence-pure construction already implemented (numbers only, no labels).
- **Benign control arm [default]:** 60 benign flows, generated and detected the same way, analysed
  separately (does the model "see" attacks in normal traffic?). Never mixed into headline numbers.

## 5. Generation
- Model `gemini-2.5-flash` **[default]**; record the exact model string returned by the API, the date,
  temperature (0.0 **[default]**), thinking setting, and token usage per call.
- Generation prompt v1 (`generate_system.txt`) is the main arm. The alert label is never in the prompt.
- Cache every LLM call by (model, params, prompt hash) and keep raw responses, so analysis can be redone
  without calling the API again.

## 6. Hallucination definition: two tiers, two policies
- **Tier 1 — unsupported specifics:** `factual` (CVE, tool, IP, version), `reasoning` (named attack
  technique / threat actor not derivable from numbers), `certainty` (definitive outcome or intent),
  `outdated` (patch/date claims).
- **Tier 2 — external knowledge:** `port` (port -> service), `protocol` (TCP/session norms), `encryption`,
  `baseline` ("unusually long", "typical traffic"), `unit` (raw duration -> seconds/minutes).
- **Strict policy** (evidence-only): Tier 1 and Tier 2 are hallucinations.
  **Lenient policy:** only Tier 1 is. Annotate once; derive both.
- The old pipeline used the strict policy at sentence level but a lenient judge at explanation level.
  That inconsistency is removed by making the policy an explicit parameter.

## 7. Detection ablation (RQ2) — explanation level
| Config | Rule layers in Phase 2 | LLM judge policy |
|---|---|---|
| C0 | Tier 1 only (as in the old run) | old prompt (lenient on Tier 2) |
| C1 | Tier 1 + Tier 2 | old prompt |
| C2 | Tier 1 only | aligned to the policy being evaluated |
| C3 | Tier 1 + Tier 2 | aligned |
Run each config under both policies (judge prompt v2 per policy). Report precision, recall, F1, number of
LLM calls, and paired significance (McNemar) between configs. Sentence level: rules-only versus rules+LLM.

## 8. Gold labels (annotation protocol)
- **Sample:** 100 explanations drawn at random, stratified by class (about 7 per class), seed fixed and
  recorded. **All** sentences of each (about 1000), irrespective of what the pipeline flagged.
- **Blind:** annotators see evidence + sentence (+ the surrounding explanation for context). They never
  see predictions, types or reasons from the pipeline.
- **Label per sentence:** `grounded` | `factual` | `reasoning` | `certainty` | `outdated` |
  `external_knowledge` with sub-type (port/protocol/encryption/baseline/unit); plus optional note.
- **Reliability:** a second annotator labels 25 of the 100 explanations (about 250 sentences). If no second
  human is available, the primary annotator re-labels 25 explanations after at least 7 days (test-retest).
  Report Cohen's kappa with a bootstrap CI, per tier. Disagreements are adjudicated and logged.
  An LLM may be reported as an *additional* labeller only, clearly named as such, never as the gold.
- **Freeze point `freeze-1` happens before annotation sheets are exported.**

## 9. Mitigation arms (RQ3) — evaluated on the annotated 100 explanations
| Arm | What it is |
|---|---|
| M0 | No mitigation (the explanation as generated) |
| M-prompt | Regenerate with a stricter generation prompt v2 (evidence-only phrasing, no unit conversion, no port->service). No post-hoc correction |
| M-auto | Phases 2-4 using predicted labels only |
| M-auto+val | M-auto plus numeric-fidelity validator: every number in a rewrite must occur in the evidence; otherwise retry (max 2), then fall back to REMOVE |
| M-gold | Phase 4 driven by human gold labels (upper bound; labelled as such) |
Outcomes per arm: hallucinated-sentence rate (human-verified on a 100-rewrite audit sample, automatic
check on all), numeric-fidelity violations, information retention (share of grounded sentences kept
unchanged; share of evidence tokens still referenced), sentences removed, and a rewrite audit by hand.

## 10. Controlled injection (E4)
Natural data produced almost no Tier-1 factual fabrications, so the REMOVE path and the detector's
factual recall are untested. Insert synthetic fabricated sentences with known ground truth into 100
explanations: (a) regex-friendly (CVE ids, tool names, IPs), (b) paraphrased to evade regexes
("the exploit published for SMB in 2017"), (c) definitive claims. Report recall by type and whether
REMOVE fires. This measures coverage of the detector; it is not evidence about natural prevalence.

## 11. Metrics and statistics
- Detection: precision, recall, F1 at explanation and sentence level, with and without conditioning on
  Phase 2 (both are reported; unconditional is the headline).
- **Cluster bootstrap** (resample explanations, 2000 draws, seed fixed) for 95% CIs, because sentences
  are nested in explanations. McNemar for paired comparisons. Cohen's kappa with CI.
- Per-class breakdown for every headline metric. Report n for every cell.
- Report both policies. Never report a single "hallucination rate" without naming the policy.

## 12. Threats to validity (to be written up, not hidden)
Single generator model; single annotator or two; CIC-IDS 2017 labelling issues and its synthetic
traffic; flow features only (no payloads); rule engine and the strict definition share lineage, so
rule-based metrics are secondary; LLM-judge and rewriter share a model family; Gemini versions change over
time (record the date); sample of 100 annotated explanations limits per-class precision.

## 13. Stretch (only after the core is frozen)
Second generator model through the same `LLMClient` interface; a human audit of benign-control
explanations; per-class error analysis of why Port Scanning explanations are flagged most often.

## 14. Cost and time (rough)
About 400 generation calls, a few hundred judge calls per config, up to roughly 1000 rewrites and re-checks.
A pilot of 40 alerts comes first. Annotation: about 8 hours for the primary annotator, about 2 hours for the
reliability subset, about 1 hour for the rewrite audit.

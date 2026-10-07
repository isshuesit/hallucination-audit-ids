# Runbook: existing-corpus study (D25-D28), tonight

Everything below runs on your machine with **no Gemini call and no API key**. Run the commands in a PowerShell
terminal in VS Code, one at a time, in this order. Each step says what you should see.

Source of every number tonight (D25): *earlier run, API-default sampling, prompt v1, 63 attack-flow and 337
benign-flow explanations; not generated under freeze-1.*

**Order matters.** You are the human annotator (D28), so you label BEFORE you look at any pipeline result.
Do not run step 5 or open anything in `results\` until your labels are imported (step 4).

---

## 0. Go to the project folder

```powershell
cd "C:\Users\ishit\Downloads\hallucination_pipeline\hallucination_pipeline_project"
```

## 1. Check the freeze and the tests

```powershell
git describe --tags --exact-match
python -m pytest tests/ -q
```

You should see `freeze-1`, then `... passed`. If either fails, stop and check before continuing.

## 2. Export the blind audit sheet

```powershell
python -m hallucination_pipeline.cli audit_export
```

You should see `Corpus corpus-7247d3e7` and a short README: one sheet, 25 explanations. Files appear in
`annotation\corpus-7247d3e7\`. **Never open `key.json`** (it maps the sheet back to the alerts and classes).

## 3. Label (about 2 hours: 250 sentences)

1. Read `docs\ANNOTATION_GUIDE_v2.md` once, fully.
2. Open `annotation\corpus-7247d3e7\sheets\primary.html` in a browser to read comfortably.
3. Open `annotation\corpus-7247d3e7\sheets\primary.csv` in Excel and fill only the columns `label`, `subtype`,
   `hedged`, `other_subtypes`, `note`, `unsure`. Do not reorder, add or delete rows.
4. Save as **CSV UTF-8** under a NEW name in a `filled` folder, for example
   `annotation\corpus-7247d3e7\filled\primary_IS.csv` (use your initials). Create the folder first:

   ```powershell
   New-Item -ItemType Directory -Force annotation\corpus-7247d3e7\filled
   ```
5. Label on your own judgement: no AI model, no pipeline output. Sessions of 60 minutes or less. This is the only
   pass (D28: no second pass).

## 4. Import your labels

```powershell
python -m hallucination_pipeline.cli annotation_import corpus-7247d3e7 annotation\corpus-7247d3e7\filled\primary_IS.csv --sheet primary --annotator IS
```

You should see `Imported 250 sentences (...)`. If it lists problems (with line numbers), fix them in the CSV and run
the same command again. Nothing is saved until the whole file is valid.

## 5. Run the rule analysis of the whole corpus

```powershell
python -m hallucination_pipeline.cli analyze_corpus
```

You should see the group counts and `Wrote ...\results\corpus-7247d3e7 ... LLM calls: 0.`

## 6. Compare the rules with your labels

```powershell
python -m hallucination_pipeline.cli audit_metrics corpus-7247d3e7 annotation\corpus-7247d3e7\imported\primary_IS.json
```

You should see precision, recall and F1 (strict and lenient, sentence and explanation level) with 95% intervals.
With 25 explanations the intervals are wide: this is an audit, not a benchmark.

## 7. Read the results

- `results\corpus-7247d3e7\REPORT.md`: summary
- `results\corpus-7247d3e7\tables\*.csv`: every table, n in every row
- `results\corpus-7247d3e7\samples\`: 20 flagged sentences per tier, for reading
- `results\corpus-7247d3e7\audit\`: rules versus your labels, and the disagreement list

## 8. Save and package

```powershell
git add results annotation
git commit -m "Existing-corpus study: results and audit labels (D25-D28)"
Compress-Archive -Path results\corpus-7247d3e7 -DestinationPath outbox\corpus-7247d3e7.zip
```

Upload `outbox\corpus-7247d3e7.zip` and `docs\DECISIONS.md` to the paper chat. Never upload `.env`, `data\raw`,
`old_run\` or `llm_cache\`.

## If something goes wrong

- A command says a results or label file `already exists`: results are never overwritten. Ask for help rather than
  deleting anything.
- Any change to code after `freeze-1` is a POST-HOC bug fix and must be logged in `docs\DECISIONS.md` (D26).

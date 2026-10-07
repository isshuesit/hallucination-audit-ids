# Runbook: existing-corpus study (D25-D31)

Everything below runs on your machine. **No command here calls Gemini or any API.** The two AI labellers are used
by you, in their normal chat windows. Run the commands in a PowerShell terminal in VS Code, one at a time, in order.

Source of every number (D25): *earlier run, API-default sampling, prompt v1, 63 attack-flow and 337 benign-flow
explanations; not generated under freeze-1.* Labels (D30): two AI annotators, adjudicated by you.

**Order matters.** You adjudicate BEFORE you look at any pipeline result. Do not run step 9 or open anything in
`results\` until your adjudication file is saved (step 8). While adjudicating, do not open `ai\hidden\` or
`ai\labels_*.csv`: they show the AIs' answers.

The audit sheet already exists (you ran `audit_export`): `annotation\corpus-7247d3e7\`.

---

## 0. Go to the project folder

```powershell
cd "C:\Users\ishit\Downloads\hallucination_pipeline\hallucination_pipeline_project"
```

## 1. Check the freeze and the tests

```powershell
git tag --list freeze-1
git diff --stat freeze-1 -- hallucination_pipeline configs docs/ANNOTATION_GUIDE_v2.md
python -m pytest tests/ -q
```

You should see `freeze-1`, then **nothing** from the `git diff` line (the frozen files are unchanged), then
`... passed` with no failures. If any is different, stop and check before continuing.

## 2. Make the chunks for the AIs

```powershell
python tools/ai_labelling.py ai_export
```

This cuts the 25 explanations into 5 text files (`ai\chunks\chunk_01.txt` ... `chunk_05.txt`), makes an empty
`ai\replies\` folder, and a form `ai\labelling_manifest.json` for step 4.

## 3. Ask both AIs (by hand, in their chat windows)

Use two labellers, called `gemini` and `gpt` in file names. For EACH labeller and EACH chunk (10 times in total):

1. Open a **new** chat (so nothing carries over), with web search, code tools and any custom instructions or
   memory switched **off**.
2. Copy the instructions plus one chunk to the clipboard (change `chunk_01` each time):

   ```powershell
   Get-Content -Encoding UTF8 docs\AI_LABELLER_PROMPT.md, annotation\corpus-7247d3e7\ai\chunks\chunk_01.txt | Set-Clipboard
   ```

3. Paste into the chat and send. Do not add anything else.
4. Copy the AI's whole reply (its copy button), then save it from the clipboard (change the labeller name and the
   chunk number each time):

   ```powershell
   Get-Clipboard | Set-Content -Encoding UTF8 annotation\corpus-7247d3e7\ai\replies\gemini_chunk_01.txt
   ```

## 4. Record the labellers (D31)

Open `annotation\corpus-7247d3e7\ai\labelling_manifest.json` in VS Code and replace every `FILL IN`: model name,
model version, date, interface (`chat`), tools (`off`), customisation (`none`, or the `docs\` file where you copied
any custom instructions). Save.

## 5. Read each AI's answers into the project

```powershell
python tools/ai_labelling.py ai_import --labeller gemini
python tools/ai_labelling.py ai_import --labeller gpt
```

Each should say `250 items read and valid`. If it lists problems instead (each with its item code), paste the
problem list back into the SAME chat for that chunk, ask the AI to re-send all lines of that chunk, save the new
reply over the old file (step 3.4), write in the manifest's notes that you did this, and run the command again.
Never edit an AI's labels yourself.

## 6. Compare the two AIs and make your adjudication sheet

```powershell
python tools/ai_labelling.py ai_compare --labellers gemini gpt
```

It prints how often the AIs agreed and writes `ai\adjudication.csv`: every item they disagree on plus a random 20%
of the items they agree on, shuffled, with no AI answer shown.

## 7. Adjudicate (you)

1. Read `docs\ANNOTATION_GUIDE_v2.md` once, fully.
2. Open `annotation\corpus-7247d3e7\ai\adjudication.csv` in Excel and fill `label`, `subtype`, `hedged`,
   `other_subtypes`, `note`, `unsure` for every row, on your own judgement. Do not reorder, add or delete rows.
3. Save as **CSV UTF-8** with the name `annotation\corpus-7247d3e7\ai\adjudication_filled.csv`.

## 8. (nothing to run) Your adjudication is saved. Only now look at results.

## 9. Run the rule analysis of the whole corpus

```powershell
python -m hallucination_pipeline.cli analyze_corpus
```

You should see the group counts and `... LLM calls: 0.`

## 10. Make the final labels and compare the rules with them

```powershell
python tools/ai_labelling.py ai_finalize --labellers gemini gpt --author IS
```

(Use your initials for `IS`.) It checks your adjudication file, merges it with the AI consensus into
`ai\final_labels.csv`, and prints the label line (`labels: two AI annotators ...; overrule rate ...`) and the
rules' precision, recall and F1. If it lists problems in your file, fix them and run it again.

## 11. Read the results

- `results\corpus-7247d3e7\REPORT.md` and `tables\`: the corpus analysis
- `results\corpus-7247d3e7\audit_ai\`: rules versus the final labels, and the disagreement list
- `annotation\corpus-7247d3e7\ai\final_summary.json`: disagreements, spot-check, overrule rate
- Now you may open `ai\hidden\` (both AIs' answers, agreement details)

## 12. Save and package

```powershell
git add results annotation
git commit -m "Existing-corpus study: results and AI-adjudicated audit labels (D25-D31)"
Compress-Archive -Path results\corpus-7247d3e7, annotation\corpus-7247d3e7\ai -DestinationPath outbox\corpus-7247d3e7.zip
```

Upload `outbox\corpus-7247d3e7.zip` and `docs\DECISIONS.md` to the paper chat. Never upload `.env`, `data\raw`,
`old_run\` or `llm_cache\`.

## If something goes wrong

- A command says something `already exists`: results, sheets and labels are never overwritten. Ask for help rather
  than deleting anything.
- Any change to frozen code after `freeze-1` is a POST-HOC fix and must be logged in `docs\DECISIONS.md` (D26).
- The human-label commands from the first version of this runbook (`annotation_import` with your own full labels,
  `audit_metrics`) are replaced by steps 5-10 (D30).

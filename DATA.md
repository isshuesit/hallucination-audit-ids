# Data note

## CIC-IDS 2017 (not included)

The network-flow data come from **CIC-IDS 2017**, created by and belonging to the **Canadian Institute for
Cybersecurity (CIC), University of New Brunswick**. The raw dataset is **not** redistributed in this repository.
Download it from the CIC website (https://www.unb.ca/cic/datasets/ids-2017.html) under their terms, and place the
CSV files from `MachineLearningCSV.zip` in `data/raw/` if you want to re-run sampling.

Any use of CIC-IDS 2017, including the derived files below, must cite:

> Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani. *Toward Generating a New Intrusion Detection Dataset
> and Intrusion Traffic Characterization.* Proceedings of the 4th International Conference on Information Systems
> Security and Privacy (ICISSP), 2018, pp. 108-116.

## What is included, and where it comes from

- `old_run/` (7 JSON files, about 3 MB): the earlier run that this repository audits. For 400 sampled flows it holds
  the alert id, the (coarse) attack class and an evidence string of six numeric flow features derived from
  CIC-IDS 2017, plus the explanations an LLM (gemini-2.5-flash) wrote for them and that run's detection, label and
  rewrite files. These are derived from CIC-IDS 2017; the attribution above applies.
- `results/`: tables and records computed from `old_run/` by this repository's code.
- `annotation/`: the blind audit sheet, the two AI labellers' replies and labels, and the author's adjudication.
  The AI-generated text in `old_run/` and `annotation/` is model output, included for reproducibility.

Nothing in this repository contains personal data or credentials.

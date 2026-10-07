"""
Unified CLI for the pipeline. Run phases individually or all at once.

Usage:
    python -m hallucination_pipeline.cli load
    python -m hallucination_pipeline.cli generate
    python -m hallucination_pipeline.cli detect
    python -m hallucination_pipeline.cli localize
    python -m hallucination_pipeline.cli unlearn
    python -m hallucination_pipeline.cli evaluate
    python -m hallucination_pipeline.cli report
    python -m hallucination_pipeline.cli impact
    python -m hallucination_pipeline.cli status

Fresh controlled run (config -> runs/<run_id>/):
    python -m hallucination_pipeline.cli run [--config configs/fresh_run.toml] [--run-id ID] [--data-only] [--dry-run]
    python -m hallucination_pipeline.cli pilot_report <run_id> --config configs/pilot.toml
    python -m hallucination_pipeline.cli freeze_run <run_id> [--config ...]
    python -m hallucination_pipeline.cli verify_run <run_id> [--config ...]

Existing-corpus study (D25-D28; no LLM call; see docs/RUNBOOK_TONIGHT.md):
    python -m hallucination_pipeline.cli audit_export [--corpus-dir old_run]       # needs git tag freeze-1
    python -m hallucination_pipeline.cli analyze_corpus [--corpus-dir old_run]     # -> results/<corpus_id>/
    python -m hallucination_pipeline.cli audit_metrics <corpus_id> <imported labels .json> [--corpus-dir old_run]

Annotation (M3; output in annotation/<run_id>/):
    python -m hallucination_pipeline.cli annotation_export <run_id>            # needs git tag freeze-1
    python -m hallucination_pipeline.cli annotation_import <run_id> <filled.csv> --sheet primary --annotator NAME
    python -m hallucination_pipeline.cli annotation_agreement <run_id> <labels_a.json> <labels_b.json>
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hallucination_pipeline")
    parser.add_argument(
        "phase",
        choices=["load", "generate", "detect", "localize", "unlearn",
                 "evaluate", "report", "impact", "status", "run", "freeze_run", "verify_run", "pilot_report",
                 "annotation_export", "annotation_import", "annotation_agreement",
                 "analyze_corpus", "audit_export", "audit_metrics"],
    )
    parser.add_argument("target_run_id", nargs="?", help="run id for freeze_run / verify_run")
    parser.add_argument("--config", default=None, help="run config TOML (default configs/fresh_run.toml)")
    parser.add_argument("--run-id", default=None, help="override the run id (needed to re-run a frozen config)")
    parser.add_argument("--data-only", action="store_true", help="run: stop after sampling (no LLM calls)")
    parser.add_argument("--dry-run", action="store_true",
                        help="run: print the LLM calls each stage would make (minus cached ones); no calls, no writes")
    parser.add_argument("files", nargs="*", help="annotation_import: filled CSV; annotation_agreement: two label files")
    parser.add_argument("--sheet", choices=["primary", "reliability", "retest"], help="annotation_import: which sheet")
    parser.add_argument("--annotator", help="annotation_import: annotator name or initials")
    parser.add_argument("--corpus-dir", default=None, help="existing-corpus study: the earlier run's files "
                                                            "(default old_run/)")
    parser.add_argument("--unfrozen", action="store_true",
                        help="annotation_export: allow an export before freeze-1 (pilot/synthetic only, marked in key)")
    args = parser.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):   # Windows consoles cannot print every character
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError):
            pass

    if args.phase in ("analyze_corpus", "audit_export", "audit_metrics"):
        from .annotation import AnnotationExportError
        from .corpus import ResultsExistError
        try:
            return _corpus_command(parser, args)
        except (AnnotationExportError, ResultsExistError, FileNotFoundError, FileExistsError, ValueError) as e:
            print(f"\nERROR: {e}", file=sys.stderr)
            return 1
    if args.phase.startswith("annotation_"):
        from .annotation import AnnotationExportError, AnnotationImportError
        try:
            return _annotation_command(parser, args)
        except (AnnotationExportError, AnnotationImportError, FileNotFoundError, ValueError) as e:
            print(f"\nERROR: {e}", file=sys.stderr)
            return 1
    if args.phase in ("run", "freeze_run", "verify_run", "pilot_report"):
        from .data_loader import MissingColumnsError
        from .run_config import ConfigError
        from .run_dir import FrozenRunError
        from .sampling import LabelHygieneError
        try:
            return _fresh_run_command(parser, args)
        except (FileNotFoundError, MissingColumnsError, LabelHygieneError, ConfigError, FrozenRunError) as e:
            print(f"\nERROR: {e}", file=sys.stderr)
            return 1

    if args.phase == "load":
        from . import data_loader
        data_loader.run()
    elif args.phase == "generate":
        from . import explanation_generator
        explanation_generator.run()
    elif args.phase == "detect":
        from . import detection_pipeline
        detection_pipeline.run_explanation_detection()
    elif args.phase == "localize":
        from . import detection_pipeline
        detection_pipeline.run_sentence_localization()
    elif args.phase == "unlearn":
        from . import unlearning
        from .llm_client import get_client
        unlearning.run(get_client())
    elif args.phase == "evaluate":
        from . import evaluation
        evaluation.run()
    elif args.phase == "report":
        from . import reporting
        reporting.run()
    elif args.phase == "impact":
        from . import impact_analysis
        impact_analysis.run()
    elif args.phase == "status":
        from . import status
        status.run()

    return 0


def _fresh_run_command(parser: argparse.ArgumentParser, args) -> int:
    from .run_config import DEFAULT_CONFIG_PATH, load_run_config
    from .run_dir import freeze_run, verify_frozen

    cfg = load_run_config(args.config or DEFAULT_CONFIG_PATH)
    if args.phase == "run":
        from .run import dry_run, execute_run, format_dry_run
        if args.dry_run:
            print(format_dry_run(dry_run(cfg, run_id=args.run_id)))
            return 0
        execute_run(cfg, run_id=args.run_id, data_only=args.data_only)
        return 0
    if not args.target_run_id:
        parser.error(f"{args.phase} needs a run id, e.g. {args.phase} {cfg.run_id}")
    run_dir = cfg.runs_dir / args.target_run_id
    if args.phase == "pilot_report":
        from .pilot_report import build_report, format_report, write_samples
        rep_ = build_report(run_dir, seed=cfg.seed)
        print(format_report(rep_))
        print(f"\nWrote {write_samples(run_dir, rep_)}")
        return 0
    if args.phase == "freeze_run":
        sums = freeze_run(run_dir)
        print(f"Frozen: {run_dir} (checksums in {sums.name}; files are now read-only)")
        return 0
    problems = verify_frozen(run_dir)
    print("\n".join(problems) if problems else f"OK: {run_dir} matches its SHA256SUMS")
    return 1 if problems else 0


def _annotation_command(parser: argparse.ArgumentParser, args) -> int:
    import json

    from . import annotation as AN
    from .run_config import DEFAULT_CONFIG_PATH, load_run_config

    cfg = load_run_config(args.config or DEFAULT_CONFIG_PATH)
    if not args.target_run_id:
        parser.error(f"{args.phase} needs a run id")
    run_dir, ann_dir = cfg.runs_dir / args.target_run_id, cfg.annotation_dir / args.target_run_id
    if args.phase == "annotation_export":
        load = lambda n: json.loads((run_dir / n).read_text(encoding="utf-8"))
        out = AN.export_annotation(load("explanations.json"), load("alerts.json"), ann_dir,
                                   run_id=args.target_run_id, seed=cfg.seed, unfrozen_ok=args.unfrozen)
        print((out / "README.txt").read_text(encoding="utf-8"))
        return 0
    key = json.loads((ann_dir / "key.json").read_text(encoding="utf-8"))
    if args.phase == "annotation_import":
        if len(args.files) != 1 or not args.sheet or not args.annotator:
            parser.error("annotation_import <run_id> <filled.csv> --sheet SHEET --annotator NAME")
        res = AN.import_sheet(args.files[0], key, args.sheet, args.annotator)
        out = ann_dir / "imported" / f"{args.sheet}_{args.annotator}.json"
        if out.exists():
            raise ValueError(f"{out} already exists; imported labels are never overwritten")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps({"sheet": args.sheet, "annotator": args.annotator, "file_notes": res["file_notes"],
                                   "labels": AN.labels_to_json(res["labels"])}, indent=2, ensure_ascii=False) + "\n",
                       encoding="utf-8", newline="\n")
        n_h = sum(g.label == "hallucinated" for g in res["labels"])
        print(f"Imported {len(res['labels'])} sentences ({n_h} hallucinated) -> {out}")
        return 0
    if len(args.files) != 2:
        parser.error("annotation_agreement <run_id> <labels_a.json> <labels_b.json>")
    a, b = (AN.labels_from_json(json.loads(open(f, encoding="utf-8").read())["labels"]) for f in args.files)
    a = AN.restrict_to(a, b) if len(a) > len(b) else a      # primary pass vs a 25-explanation subset
    b = AN.restrict_to(b, a) if len(b) > len(a) else b
    res = AN.agreement(a, b, seed=cfg.seed)
    stem = f"agreement_{a[0].sheet}-{a[0].annotator}_vs_{b[0].sheet}-{b[0].annotator}"
    (ann_dir / f"{stem}.json").write_text(json.dumps(res, indent=2) + "\n", encoding="utf-8", newline="\n")
    AN.write_disagreements(ann_dir / f"{stem}_disagreements.csv", AN.disagreements(a, b))
    for name, k in res["kappa"].items():
        ci = f"[{k['ci95'][0]:.2f}, {k['ci95'][1]:.2f}]" if k["ci95"] else "n/a"
        kappa = f"{k['kappa']:.3f}" if k["kappa"] is not None else "undefined"
        print(f"  {name:<28} kappa {kappa:>9}  95% CI {ci}")
    print(f"Wrote {ann_dir / (stem + '.json')} and the disagreement list (adjudication sheet)")
    return 0


def _corpus_command(parser: argparse.ArgumentParser, args) -> int:
    import json
    from pathlib import Path

    from . import audit as AU
    from . import corpus as CO
    from .annotation import labels_from_json
    from .run_config import DEFAULT_CONFIG_PATH, PROJECT_ROOT, load_run_config

    cfg = load_run_config(args.config or DEFAULT_CONFIG_PATH)
    corpus_dir = Path(args.corpus_dir) if args.corpus_dir else PROJECT_ROOT / "old_run"
    data = CO.load_corpus(corpus_dir)
    cid = data["corpus_id"]
    print(f"Corpus {cid} ({corpus_dir}); {CO.SOURCE}")
    if args.phase == "audit_export":
        out = AU.export_audit(data, cfg.annotation_dir / cid, unfrozen_ok=args.unfrozen)
        print((out / "README.txt").read_text(encoding="utf-8"))
        return 0
    if args.phase == "analyze_corpus":
        out = CO.write_results(data)
        m = json.loads((out / "MANIFEST.json").read_text(encoding="utf-8"))
        for g, c in m["counts"].items():
            print(f"  {g}: {c['analysed']} explanations analysed ({c['excluded']} excluded), {c['sentences']} sentences")
        print(f"Wrote {out} (open REPORT.md there). LLM calls: 0.")
        return 0
    if not args.target_run_id or len(args.files) != 1:
        parser.error("audit_metrics <corpus_id> <imported labels .json>")
    if args.target_run_id != cid:
        raise ValueError(f"corpus id {args.target_run_id} does not match the files in {corpus_dir} ({cid})")
    results = CO.RESULTS_DIR / cid
    if not (results / "MANIFEST.json").exists():
        raise FileNotFoundError(f"run analyze_corpus first ({results} does not exist)")
    gold = labels_from_json(json.loads(Path(args.files[0]).read_text(encoding="utf-8"))["labels"])
    res = AU.audit_metrics(gold, data)
    out = AU.write_audit(res, results / "audit")
    print(AU.format_audit(res))
    print(f"\nWrote {out} (metrics, disagreement list)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

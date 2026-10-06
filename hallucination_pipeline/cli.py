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
    python -m hallucination_pipeline.cli run [--config configs/fresh_run.toml] [--run-id ID] [--data-only]
    python -m hallucination_pipeline.cli freeze_run <run_id> [--config ...]
    python -m hallucination_pipeline.cli verify_run <run_id> [--config ...]
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hallucination_pipeline")
    parser.add_argument(
        "phase",
        choices=["load", "generate", "detect", "localize", "unlearn",
                 "evaluate", "report", "impact", "status", "run", "freeze_run", "verify_run"],
    )
    parser.add_argument("target_run_id", nargs="?", help="run id for freeze_run / verify_run")
    parser.add_argument("--config", default=None, help="run config TOML (default configs/fresh_run.toml)")
    parser.add_argument("--run-id", default=None, help="override the run id (needed to re-run a frozen config)")
    parser.add_argument("--data-only", action="store_true", help="run: stop after sampling (no LLM calls)")
    args = parser.parse_args(argv)

    if args.phase in ("run", "freeze_run", "verify_run"):
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
        from .run import execute_run
        execute_run(cfg, run_id=args.run_id, data_only=args.data_only)
        return 0
    if not args.target_run_id:
        parser.error(f"{args.phase} needs a run id, e.g. {args.phase} {cfg.run_id}")
    run_dir = cfg.runs_dir / args.target_run_id
    if args.phase == "freeze_run":
        sums = freeze_run(run_dir)
        print(f"Frozen: {run_dir} (checksums in {sums.name}; files are now read-only)")
        return 0
    problems = verify_frozen(run_dir)
    print("\n".join(problems) if problems else f"OK: {run_dir} matches its SHA256SUMS")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

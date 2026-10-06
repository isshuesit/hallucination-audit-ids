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
"""

from __future__ import annotations

import argparse
import sys


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="hallucination_pipeline")
    parser.add_argument(
        "phase",
        choices=["load", "generate", "detect", "localize", "unlearn",
                 "evaluate", "report", "impact", "status"],
    )
    args = parser.parse_args(argv)

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


if __name__ == "__main__":
    sys.exit(main())

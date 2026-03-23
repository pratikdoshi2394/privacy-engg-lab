from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Mapping, Sequence

from ai_privacy_guard.evaluator import PolicyEvaluator
from ai_privacy_guard.models import Finding

ENFORCEMENT_ORDER: Mapping[str, int] = {
    "allow": 0,
    "warn": 1,
    "review": 2,
    "block": 3,
}


def meets_or_exceeds_enforcement(enforcement: str, threshold: str) -> bool:
    return ENFORCEMENT_ORDER[enforcement] >= ENFORCEMENT_ORDER[threshold]


def should_fail_on_threshold(findings: Sequence[Finding], threshold: str) -> bool:
    return any(
        meets_or_exceeds_enforcement(finding.enforcement, threshold) for finding in findings
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apg",
        description="Run policy-driven privacy checks for an AI configuration.",
    )
    parser.add_argument("--config", required=True, help="Path to JSON config file.")
    parser.add_argument(
        "--policy",
        default="default_us_privacy",
        help="Policy pack name (without .yaml) or policy filename.",
    )
    parser.add_argument(
        "--fail-on",
        choices=tuple(ENFORCEMENT_ORDER.keys()),
        help="Fail with non-zero exit code when findings meet or exceed this enforcement level.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        config_path = Path(args.config)
        with config_path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)

        evaluator = PolicyEvaluator(policy_name=args.policy)
        result = evaluator.evaluate(payload)
        print(json.dumps(result.to_dict(), indent=2))
        if args.fail_on and should_fail_on_threshold(result.findings, args.fail_on):
            return 1
        return 0
    except Exception as exc:  # pragma: no cover
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

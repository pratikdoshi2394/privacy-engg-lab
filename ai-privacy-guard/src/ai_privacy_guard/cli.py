from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ai_privacy_guard.engine import RiskEngine


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="apg",
        description="Evaluate privacy risk for an AI deployment config.",
    )
    parser.add_argument("--config", required=True, help="Path to JSON config file.")
    parser.add_argument(
        "--policy",
        default="default_us_privacy",
        help="Policy name (without .yaml) or policy filename.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    try:
        config_path = Path(args.config)
        with config_path.open("r", encoding="utf-8") as handle:
            config_payload = json.load(handle)

        engine = RiskEngine(policy_name=args.policy)
        result = engine.evaluate(config_payload)
        print(json.dumps(result.to_dict(), indent=2))
        return 0
    except Exception as exc:  # pragma: no cover
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

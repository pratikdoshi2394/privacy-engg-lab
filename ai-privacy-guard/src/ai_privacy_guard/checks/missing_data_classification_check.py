from __future__ import annotations

from typing import Any

from ai_privacy_guard.models import PolicyRule, ScanConfig


def evaluate(config: ScanConfig, rule: PolicyRule) -> dict[str, Any] | None:
    """Trigger when no developer-declared data classifications are provided."""

    if config.data_types:
        return None

    return {
        "reason": "No data classifications were declared for this AI integration.",
        "evidence": {
            "declared_data_types": [],
            "source_of_truth": "developer_declared_data_types",
        },
    }

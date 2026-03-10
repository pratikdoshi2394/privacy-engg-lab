from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ai_privacy_guard.checks import (
    metadata_check,
    pii_check,
    region_check,
    retention_check,
    sensitive_data_check,
    transfer_check,
)
from ai_privacy_guard.models import APGConfig, EvaluationResult, Finding, Policy

CHECK_RUNNERS = (
    pii_check.run,
    sensitive_data_check.run,
    transfer_check.run,
    retention_check.run,
    region_check.run,
    metadata_check.run,
)


class RiskEngine:
    """Evaluates model deployment configs against policy-driven checks."""

    def __init__(self, policy_name: str = "default_us_privacy") -> None:
        self.policy_name = policy_name
        self.policy = self._load_policy(policy_name)

    def evaluate(self, config_input: dict[str, Any] | APGConfig) -> EvaluationResult:
        config = (
            config_input
            if isinstance(config_input, APGConfig)
            else APGConfig.from_dict(config_input)
        )
        findings = [runner(config, self.policy) for runner in CHECK_RUNNERS]
        risk_score = max(0, min(100, sum(finding.score for finding in findings)))
        summary = self._build_summary(risk_score, findings)

        return EvaluationResult(risk_score=risk_score, findings=findings, summary=summary)

    @staticmethod
    def _build_summary(risk_score: int, findings: list[Finding]) -> str:
        failed = [finding for finding in findings if not finding.passed]
        if risk_score >= 70:
            bucket = "high"
        elif risk_score >= 35:
            bucket = "moderate"
        else:
            bucket = "low"

        return (
            f"Overall {bucket} privacy risk (score={risk_score}) with "
            f"{len(failed)} flagged checks out of {len(findings)}."
        )

    def _load_policy(self, policy_name: str) -> Policy:
        policy_path = self._resolve_policy_path(policy_name)
        if not policy_path.exists():
            raise FileNotFoundError(f"Policy file not found: {policy_path}")

        with policy_path.open("r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle) or {}
        return Policy.from_dict(payload)

    @staticmethod
    def _resolve_policy_path(policy_name: str) -> Path:
        filename = policy_name if policy_name.endswith(".yaml") else f"{policy_name}.yaml"
        return Path(__file__).resolve().parent / "policies" / filename

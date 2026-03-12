from __future__ import annotations

from typing import Any, Callable, Optional

from ai_privacy_guard.checks import sensitive_data_check
from ai_privacy_guard.models import Finding, ScanConfig, ScanResult
from ai_privacy_guard.policy_loader import PolicyLoader

CheckFn = Callable[[ScanConfig, Any], Optional[dict[str, Any]]]

CHECK_REGISTRY: dict[str, CheckFn] = {
    "sensitive_data_check": sensitive_data_check,
}


class PolicyEvaluator:
    """Evaluates a scan config against rules from a named policy pack."""

    def __init__(self, policy_name: str = "default_us_privacy") -> None:
        self.loader = PolicyLoader()
        self.policy_pack = self.loader.load(policy_name)
        self.policy_name = str(self.policy_pack["policy_name"])
        self.rules = self.policy_pack["rules"]

    def evaluate(self, config_input: dict[str, Any] | ScanConfig) -> ScanResult:
        config = (
            config_input
            if isinstance(config_input, ScanConfig)
            else ScanConfig.from_dict(config_input)
        )

        findings: list[Finding] = []
        for rule in self.rules:
            if not rule.enabled:
                continue

            check_fn = CHECK_REGISTRY.get(rule.check)
            if check_fn is None:
                raise ValueError(
                    f"No check implementation is registered for check '{rule.check}'"
                )

            check_result = check_fn(config, rule)
            if check_result is None:
                continue

            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    severity=rule.severity,
                    enforcement=rule.enforcement,
                    reason=str(check_result["reason"]),
                    evidence=dict(check_result["evidence"]),
                    recommendations=rule.recommendations,
                )
            )

        summary = self._build_summary(findings)
        return ScanResult(policy_name=self.policy_name, findings=findings, summary=summary)

    @staticmethod
    def _build_summary(findings: list[Finding]) -> str:
        if not findings:
            return "No policy violations detected for current developer-declared data types."
        return f"{len(findings)} policy finding(s) detected."

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class ScanConfig:
    provider: str
    model: str | None = None
    deployment_region: str | None = None
    data_types: list[str] = field(default_factory=list)
    stores_prompts: bool = False
    stores_outputs: bool = False
    end_users: str | None = None
    use_case: str | None = None

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ScanConfig":
        if "provider" not in payload:
            raise ValueError("Missing required config field: provider")
        if "data_types" not in payload:
            raise ValueError("Missing required config field: data_types")

        raw_data_types = payload["data_types"]
        if not isinstance(raw_data_types, list) or not all(
            isinstance(item, str) for item in raw_data_types
        ):
            raise ValueError("Field 'data_types' must be a list[str]")

        normalized_data_types = [
            item.strip().lower() for item in raw_data_types if item.strip()
        ]

        return cls(
            provider=str(payload["provider"]).strip().lower(),
            model=(
                str(payload["model"]).strip().lower()
                if payload.get("model") is not None
                else None
            ),
            deployment_region=(
                str(payload["deployment_region"]).strip().lower()
                if payload.get("deployment_region") is not None
                else None
            ),
            data_types=normalized_data_types,
            stores_prompts=bool(payload.get("stores_prompts", False)),
            stores_outputs=bool(payload.get("stores_outputs", False)),
            end_users=(
                str(payload["end_users"]).strip().lower()
                if payload.get("end_users") is not None
                else None
            ),
            use_case=(
                str(payload["use_case"]).strip().lower()
                if payload.get("use_case") is not None
                else None
            ),
        )


@dataclass
class PolicyRule:
    rule_id: str
    title: str
    check: str
    severity: str
    enforcement: str
    recommendations: list[str]
    description: str = ""
    enabled: bool = True
    params: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "PolicyRule":
        required = {
            "rule_id",
            "title",
            "check",
            "severity",
            "enforcement",
            "recommendations",
        }
        missing = required - payload.keys()
        if missing:
            missing_list = ", ".join(sorted(missing))
            raise ValueError(f"Missing required policy rule fields: {missing_list}")

        recommendations = payload["recommendations"]
        if not isinstance(recommendations, list) or not all(
            isinstance(item, str) for item in recommendations
        ):
            raise ValueError("Field 'recommendations' must be a list[str]")

        return cls(
            rule_id=str(payload["rule_id"]),
            title=str(payload["title"]),
            check=str(payload["check"]),
            severity=str(payload["severity"]),
            enforcement=str(payload["enforcement"]),
            recommendations=recommendations,
            description=str(payload.get("description", "")),
            enabled=bool(payload.get("enabled", True)),
            params=dict(payload.get("params", {})),
        )


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    enforcement: str
    reason: str
    evidence: dict[str, Any]
    recommendations: list[str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    policy_name: str
    policy_version: str
    findings: list[Finding]
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_name": self.policy_name,
            "policy_version": self.policy_version,
            "findings": [finding.to_dict() for finding in self.findings],
            "summary": self.summary,
        }

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


REQUIRED_CONFIG_FIELDS = {
    "provider",
    "model",
    "deployment_region",
    "data_types",
    "stores_prompts",
    "stores_outputs",
    "end_users",
    "use_case",
}


@dataclass
class APGConfig:
    provider: str
    model: str
    deployment_region: str
    data_types: list[str]
    stores_prompts: bool
    stores_outputs: bool
    end_users: str
    use_case: str

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "APGConfig":
        missing = REQUIRED_CONFIG_FIELDS - payload.keys()
        if missing:
            missing_list = ", ".join(sorted(missing))
            raise ValueError(f"Missing required config fields: {missing_list}")

        data_types = payload["data_types"]
        if not isinstance(data_types, list) or not all(
            isinstance(item, str) for item in data_types
        ):
            raise ValueError("Field 'data_types' must be a list[str]")

        return cls(
            provider=str(payload["provider"]),
            model=str(payload["model"]),
            deployment_region=str(payload["deployment_region"]),
            data_types=[entry.strip().lower() for entry in data_types if entry.strip()],
            stores_prompts=bool(payload["stores_prompts"]),
            stores_outputs=bool(payload["stores_outputs"]),
            end_users=str(payload["end_users"]).strip().lower(),
            use_case=str(payload["use_case"]).strip().lower(),
        )


@dataclass
class Policy:
    name: str
    description: str
    allowed_regions: list[str]
    sensitive_data_types: list[str]
    trusted_providers: list[str]
    high_risk_use_cases: list[str]
    required_metadata_fields: list[str]
    weights: dict[str, int]

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Policy":
        required = {
            "name",
            "description",
            "allowed_regions",
            "sensitive_data_types",
            "trusted_providers",
            "high_risk_use_cases",
            "required_metadata_fields",
            "weights",
        }
        missing = required - payload.keys()
        if missing:
            missing_list = ", ".join(sorted(missing))
            raise ValueError(f"Missing required policy fields: {missing_list}")

        return cls(
            name=str(payload["name"]),
            description=str(payload["description"]),
            allowed_regions=[str(item).lower() for item in payload["allowed_regions"]],
            sensitive_data_types=[
                str(item).lower() for item in payload["sensitive_data_types"]
            ],
            trusted_providers=[str(item).lower() for item in payload["trusted_providers"]],
            high_risk_use_cases=[
                str(item).lower() for item in payload["high_risk_use_cases"]
            ],
            required_metadata_fields=[
                str(item) for item in payload["required_metadata_fields"]
            ],
            weights={
                str(key): int(value) for key, value in dict(payload["weights"]).items()
            },
        )


@dataclass
class Finding:
    check: str
    score: int
    severity: str
    passed: bool
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class EvaluationResult:
    risk_score: int
    findings: list[Finding]
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "findings": [finding.to_dict() for finding in self.findings],
            "summary": self.summary,
        }

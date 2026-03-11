from __future__ import annotations

from typing import Any

from ai_privacy_guard.models import PolicyRule, ScanConfig


def evaluate(config: ScanConfig, rule: PolicyRule) -> dict[str, Any] | None:
    """Trigger when high-risk sensitive data is sent to third-party providers."""

    sensitive_data_types = {
        "health_info",
        "financial_info",
        "ssn",
        "precise_location",
        "child_data",
        "biometric_data",
        "government_id",
        "race_ethnicity",
        "sexual_orientation",
        "religious_belief",
    }
    high_risk_sensitive_data_types = {
        "health_info",
        "financial_info",
        "ssn",
        "child_data",
        "biometric_data",
        "government_id",
    }
    third_party_providers = {
        "openai",
        "anthropic",
        "google",
        "cohere",
        "mistral",
        "bedrock",
    }

    declared_sensitive_data = sorted(set(config.data_types) & sensitive_data_types)
    high_risk_declared_data = sorted(set(config.data_types) & high_risk_sensitive_data_types)
    provider = config.provider.lower()

    if provider not in third_party_providers or not high_risk_declared_data:
        return None

    return {
        "reason": (
            "High-risk sensitive data types are declared and sent to a third-party "
            "model provider."
        ),
        "evidence": {
            "provider": provider,
            "stores_prompts": config.stores_prompts,
            "declared_sensitive_data_types": declared_sensitive_data,
            "high_risk_sensitive_data_types": high_risk_declared_data,
            "uses_third_party_provider": True,
            "source_of_truth": "developer_declared_data_types",
        },
    }

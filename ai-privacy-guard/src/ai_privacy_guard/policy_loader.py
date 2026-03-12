from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ai_privacy_guard.models import PolicyRule


class PolicyLoader:
    """Loads policy packs from YAML files in the local policies directory."""

    def __init__(self, policies_dir: Path | None = None) -> None:
        self.policies_dir = policies_dir or (Path(__file__).resolve().parent / "policies")

    def load(self, policy_name: str) -> dict[str, Any]:
        path = self._resolve_policy_path(policy_name)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")

        with path.open("r", encoding="utf-8") as handle:
            payload = yaml.safe_load(handle) or {}

        if "policy_name" not in payload:
            raise ValueError("Policy YAML is missing required field: policy_name")
        if "version" not in payload:
            raise ValueError("Policy YAML is missing required field: version")
        if "rules" not in payload:
            raise ValueError("Policy YAML is missing required field: rules")
        if not isinstance(payload["rules"], list):
            raise ValueError("Policy YAML field 'rules' must be a list")

        payload["rules"] = [PolicyRule.from_dict(rule) for rule in payload["rules"]]
        return payload

    def _resolve_policy_path(self, policy_name: str) -> Path:
        filename = policy_name if policy_name.endswith(".yaml") else f"{policy_name}.yaml"
        return self.policies_dir / filename

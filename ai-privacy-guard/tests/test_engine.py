import pytest

from ai_privacy_guard.evaluator import PolicyEvaluator
from ai_privacy_guard.policy_loader import PolicyLoader


def _base_config(**overrides):
    payload = {
        "provider": "openai",
        "model": "gpt-4.1",
        "deployment_region": "us-east-1",
        "data_types": ["product_feedback"],
        "stores_prompts": False,
        "stores_outputs": False,
        "end_users": "internal",
        "use_case": "support_assistant",
    }
    payload.update(overrides)
    return payload


def test_policy_loading_reads_rules():
    pack = PolicyLoader().load("default_us_privacy")

    assert pack["policy_name"] == "default_us_privacy"
    assert str(pack["version"]) == "0.1"
    assert len(pack["rules"]) == 2
    assert {rule.rule_id for rule in pack["rules"]} == {"PRIV-DATA-001", "PRIV-SENS-001"}


def test_policy_loading_fails_when_version_missing(tmp_path):
    policy_file = tmp_path / "missing_version.yaml"
    policy_file.write_text(
        "policy_name: default_us_privacy\n"
        "rules:\n"
        "  - rule_id: PRIV-SENS-001\n"
        "    title: Sensitive data sent to third-party AI provider\n"
        "    check: sensitive_data_check\n"
        "    severity: high\n"
        "    enforcement: block\n"
        "    recommendations:\n"
        "      - Apply redaction or tokenization before sending data to the model\n",
        encoding="utf-8",
    )

    loader = PolicyLoader(policies_dir=tmp_path)

    with pytest.raises(ValueError, match="missing required field: version"):
        loader.load("missing_version")


def test_policy_loading_uses_injected_policies_dir(tmp_path):
    policy_file = tmp_path / "custom_policy.yaml"
    policy_file.write_text(
        "policy_name: custom_policy\n"
        "version: 0.1\n"
        "rules:\n"
        "  - rule_id: PRIV-SENS-001\n"
        "    title: Sensitive data sent to third-party AI provider\n"
        "    check: sensitive_data_check\n"
        "    severity: high\n"
        "    enforcement: block\n"
        "    recommendations:\n"
        "      - Apply redaction or tokenization before sending data to the model\n",
        encoding="utf-8",
    )

    pack = PolicyLoader(policies_dir=tmp_path).load("custom_policy")

    assert pack["policy_name"] == "custom_policy"
    assert str(pack["version"]) == "0.1"
    assert pack["rules"][0].rule_id == "PRIV-SENS-001"


def test_finding_triggers_for_high_risk_sensitive_data_with_third_party_provider():
    evaluator = PolicyEvaluator("default_us_privacy")

    result = evaluator.evaluate(
        _base_config(data_types=["health_info", "race_ethnicity"], stores_prompts=True)
    )

    finding = next(item for item in result.findings if item.rule_id == "PRIV-SENS-001")
    assert finding.rule_id == "PRIV-SENS-001"
    assert finding.severity == "high"


def test_no_finding_when_no_sensitive_data_matches():
    evaluator = PolicyEvaluator("default_us_privacy")

    result = evaluator.evaluate(_base_config(data_types=["product_feedback", "preferences"]))

    assert result.findings == []
    assert result.policy_version == "0.1"
    assert "No policy violations" in result.summary


def test_finding_includes_evidence_enforcement_and_recommendations():
    evaluator = PolicyEvaluator("default_us_privacy")

    result = evaluator.evaluate(_base_config(data_types=["ssn"], stores_prompts=True))

    finding = next(item for item in result.findings if item.rule_id == "PRIV-SENS-001")
    assert finding.enforcement == "block"
    assert finding.evidence["provider"] == "openai"
    assert finding.evidence["high_risk_sensitive_data_types"] == ["ssn"]
    assert isinstance(finding.recommendations, list)
    assert len(finding.recommendations) >= 1


def test_missing_data_classification_triggers_when_data_types_empty():
    evaluator = PolicyEvaluator("default_us_privacy")
    result = evaluator.evaluate(_base_config(data_types=[]))

    finding = next(item for item in result.findings if item.rule_id == "PRIV-DATA-001")
    assert finding.severity == "medium"
    assert finding.enforcement == "warn"
    assert finding.reason == "No data classifications were declared for this AI integration."
    assert finding.evidence == {
        "declared_data_types": [],
        "source_of_truth": "developer_declared_data_types",
    }
    assert len(finding.recommendations) == 3


def test_missing_data_classification_triggers_when_data_types_missing():
    evaluator = PolicyEvaluator("default_us_privacy")
    payload = _base_config()
    payload.pop("data_types")
    result = evaluator.evaluate(payload)

    finding = next(item for item in result.findings if item.rule_id == "PRIV-DATA-001")
    assert finding.severity == "medium"
    assert finding.enforcement == "warn"


def test_missing_data_classification_not_triggered_when_data_types_declared():
    evaluator = PolicyEvaluator("default_us_privacy")
    result = evaluator.evaluate(_base_config(data_types=["product_feedback"]))

    assert all(item.rule_id != "PRIV-DATA-001" for item in result.findings)

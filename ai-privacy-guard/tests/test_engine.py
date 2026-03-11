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

    assert pack["name"] == "default_us_privacy"
    assert len(pack["rules"]) == 1
    assert pack["rules"][0].rule_id == "US.SENSITIVE.THIRD_PARTY.HIGH_RISK"


def test_finding_triggers_for_high_risk_sensitive_data_with_third_party_provider():
    evaluator = PolicyEvaluator("default_us_privacy")

    result = evaluator.evaluate(
        _base_config(data_types=["health_info", "race_ethnicity"], stores_prompts=True)
    )

    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.rule_id == "US.SENSITIVE.THIRD_PARTY.HIGH_RISK"
    assert finding.severity == "high"


def test_no_finding_when_no_sensitive_data_matches():
    evaluator = PolicyEvaluator("default_us_privacy")

    result = evaluator.evaluate(_base_config(data_types=["product_feedback", "preferences"]))

    assert result.findings == []
    assert "No policy violations" in result.summary


def test_finding_includes_evidence_enforcement_and_recommendations():
    evaluator = PolicyEvaluator("default_us_privacy")

    result = evaluator.evaluate(_base_config(data_types=["ssn"], stores_prompts=True))

    finding = result.findings[0]
    assert finding.enforcement == "block"
    assert finding.evidence["provider"] == "openai"
    assert finding.evidence["high_risk_sensitive_data_types"] == ["ssn"]
    assert isinstance(finding.recommendations, list)
    assert len(finding.recommendations) >= 1

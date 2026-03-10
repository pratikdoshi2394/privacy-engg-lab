from ai_privacy_guard.engine import RiskEngine


def _sample_config(**overrides):
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


def test_engine_returns_expected_shape_and_all_checks():
    engine = RiskEngine()
    result = engine.evaluate(
        _sample_config(
            data_types=["ssn", "payment_card"],
            stores_prompts=True,
            stores_outputs=True,
            deployment_region="eu-west-1",
            end_users="public",
        )
    )

    result_dict = result.to_dict()
    assert set(result_dict.keys()) == {"risk_score", "findings", "summary"}
    assert isinstance(result_dict["risk_score"], int)
    assert isinstance(result_dict["summary"], str)
    assert len(result_dict["findings"]) == 6

    expected_checks = {
        "pii_in_prompt_sample",
        "sensitive_data",
        "third_party_transfer",
        "retention_risk",
        "region_policy_mismatch",
        "missing_metadata",
    }
    observed_checks = {entry["check"] for entry in result_dict["findings"]}
    assert observed_checks == expected_checks
    assert result_dict["risk_score"] > 0


def test_region_mismatch_flags_risk():
    engine = RiskEngine()
    result = engine.evaluate(_sample_config(deployment_region="eu-central-1"))

    region_finding = next(item for item in result.findings if item.check == "region_policy_mismatch")
    assert region_finding.passed is False
    assert region_finding.score > 0

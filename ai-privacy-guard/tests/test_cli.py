import json

from ai_privacy_guard import cli


def _sample_config():
    return {
        "provider": "openai",
        "model": "gpt-4.1",
        "deployment_region": "us-east-1",
        "data_types": ["health_info"],
        "stores_prompts": True,
        "stores_outputs": False,
        "end_users": "internal",
        "use_case": "support_assistant",
    }


def test_cli_outputs_policy_scan_result(tmp_path, capsys):
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(_sample_config()), encoding="utf-8")

    exit_code = cli.main(["--config", str(config_path)])
    captured = capsys.readouterr()

    assert exit_code == 0
    payload = json.loads(captured.out)
    assert payload["policy_name"] == "default_us_privacy"
    assert isinstance(payload["findings"], list)
    assert "summary" in payload


def test_cli_returns_error_for_invalid_payload(tmp_path, capsys):
    config_path = tmp_path / "bad.json"
    config_path.write_text(json.dumps({"data_types": ["ssn"]}), encoding="utf-8")

    exit_code = cli.main(["--config", str(config_path)])
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "Missing required config field: provider" in captured.err

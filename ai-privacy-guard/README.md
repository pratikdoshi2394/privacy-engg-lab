# ai-privacy-guard

`ai-privacy-guard` is a policy-driven privacy risk evaluator for AI application configs.
It accepts a JSON deployment config, runs modular checks, and returns a standardized JSON risk report.

## Features

- `src/` layout package with clean module boundaries
- CLI entrypoint: `apg`
- Policy-driven risk scoring from YAML profiles
- Structured output: `risk_score`, `findings[]`, `summary`
- Placeholder checks for:
  - `pii_in_prompt_sample`
  - `sensitive_data`
  - `third_party_transfer`
  - `retention_risk`
  - `region_policy_mismatch`
  - `missing_metadata`

## Install

```bash
cd ai-privacy-guard
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

For tests:

```bash
pip install -e .[dev]
pytest
```

## Input Contract

Required JSON fields:

- `provider`
- `model`
- `deployment_region`
- `data_types`
- `stores_prompts`
- `stores_outputs`
- `end_users`
- `use_case`

See [`examples/sample_config.json`](examples/sample_config.json).

## CLI Usage

```bash
apg --config examples/sample_config.json
```

Use a specific policy profile:

```bash
apg --config examples/sample_config.json --policy financial_services
```

## Example Output

```json
{
  "risk_score": 22,
  "findings": [
    {
      "check": "pii_in_prompt_sample",
      "score": 15,
      "severity": "high",
      "passed": false,
      "detail": "PII-like fields were declared, and prompts are stored."
    }
  ],
  "summary": "Overall low privacy risk (score=22) with 2 flagged checks out of 6."
}
```

## Python API

```python
from ai_privacy_guard.engine import RiskEngine

engine = RiskEngine(policy_name="default_us_privacy")
result = engine.evaluate({
    "provider": "openai",
    "model": "gpt-4.1",
    "deployment_region": "us-east-1",
    "data_types": ["email", "product_feedback"],
    "stores_prompts": True,
    "stores_outputs": False,
    "end_users": "internal",
    "use_case": "support_assistant"
})

print(result.to_dict())
```

## Project Layout

```text
ai-privacy-guard/
  src/ai_privacy_guard/
    checks/
    policies/
    cli.py
    engine.py
    models.py
  examples/
  tests/
```

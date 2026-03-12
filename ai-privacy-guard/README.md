# ai-privacy-guard

`ai-privacy-guard` is a policy-driven privacy scanner MVP for AI applications.
This first version focuses on developer-declared `data_types` and evaluates them
against YAML policy packs to produce evidence-backed findings.

## MVP Scope

- Policy-driven scanner architecture
- Developer-declared data types as v1 source of truth
- Rule evaluation with check registry dispatch
- Evidence-backed findings with policy-defined recommendations
- Enforcement metadata per finding (`monitor`, `warn`, `block`)

No runtime prompt scanning is implemented yet.

## Install

```bash
cd ai-privacy-guard
python -m venv .venv
source .venv/bin/activate
pip install .[dev]
```

## Configuration Input

`apg` accepts a JSON config. Required fields for v1:

- `provider`

Supported optional fields include:
- `model`
- `deployment_region`
- `data_types`
- `stores_prompts`
- `stores_outputs`
- `end_users`
- `use_case`

See [`examples/sample_config.json`](examples/sample_config.json).

## Missing Data Classification

The default policy includes a `PRIV-DATA-001` rule that warns when `data_types`
is missing or empty. Engineers should declare AI input data classifications so
privacy review and controls can be applied before deployment.

## Policy Packs

Policy files live under `src/ai_privacy_guard/policies/`.

The default pack (`default_us_privacy.yaml`) defines rules with:
- top-level `policy_name`
- top-level `version`
- top-level `rules`
- `rule_id`
- `title`
- `check`
- `severity`
- `enforcement`
- `recommendations`

## CLI Usage

```bash
apg --config examples/sample_config.json
```

Use a named policy pack:

```bash
apg --config examples/sample_config.json --policy default_us_privacy
```

## Python Usage

```python
from ai_privacy_guard.evaluator import PolicyEvaluator

config = {
    "provider": "openai",
    "data_types": ["health_info", "product_feedback"],
    "stores_prompts": True,
}

result = PolicyEvaluator("default_us_privacy").evaluate(config)
print(result.to_dict())
```

## Output Shape

```json
{
  "policy_name": "default_us_privacy",
  "policy_version": "0.1",
  "findings": [
    {
      "rule_id": "PRIV-SENS-001",
      "title": "High-risk sensitive data shared with third-party provider",
      "severity": "high",
      "enforcement": "block",
      "reason": "High-risk sensitive data types are declared and sent to a third-party model provider.",
      "evidence": {
        "provider": "openai",
        "high_risk_sensitive_data_types": ["health_info"],
        "source_of_truth": "developer_declared_data_types"
      },
      "recommendations": [
        "Avoid sending high-risk sensitive data to third-party model providers."
      ]
    }
  ],
  "summary": "1 policy finding(s) detected."
}
```

## Architecture

```text
src/ai_privacy_guard/
  models.py            # ScanConfig, PolicyRule, Finding, ScanResult
  policy_loader.py     # YAML policy loading and validation
  evaluator.py         # Rule iteration + check dispatch registry
  checks/
    sensitive_data_check.py
  policies/
    default_us_privacy.yaml
```

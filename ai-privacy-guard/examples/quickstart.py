from ai_privacy_guard.engine import RiskEngine

config = {
    "provider": "openai",
    "model": "gpt-4.1",
    "deployment_region": "us-east-1",
    "data_types": ["email", "product_feedback"],
    "stores_prompts": True,
    "stores_outputs": False,
    "end_users": "internal",
    "use_case": "support_assistant",
}

engine = RiskEngine(policy_name="default_us_privacy")
result = engine.evaluate(config)
print(result.to_dict())

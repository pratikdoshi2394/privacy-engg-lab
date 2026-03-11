from ai_privacy_guard.evaluator import PolicyEvaluator

config = {
    "provider": "openai",
    "model": "gpt-4.1",
    "deployment_region": "us-east-1",
    "data_types": ["health_info", "product_feedback"],
    "stores_prompts": True,
    "stores_outputs": False,
    "end_users": "internal",
    "use_case": "support_assistant",
}

evaluator = PolicyEvaluator(policy_name="default_us_privacy")
result = evaluator.evaluate(config)
print(result.to_dict())

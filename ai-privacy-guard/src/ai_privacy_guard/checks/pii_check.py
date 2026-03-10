from ai_privacy_guard.models import APGConfig, Finding, Policy

PII_MARKERS = {"email", "phone", "ssn", "name", "address"}


def run(config: APGConfig, policy: Policy) -> Finding:
    contains_pii = any(item in PII_MARKERS for item in config.data_types)
    base_weight = policy.weights.get("pii_in_prompt_sample", 0)

    if not contains_pii:
        return Finding(
            check="pii_in_prompt_sample",
            score=0,
            severity="low",
            passed=True,
            detail="No obvious PII markers were declared in data_types.",
        )

    score = base_weight if config.stores_prompts else max(1, base_weight // 2)
    detail = (
        "PII-like fields were declared, and prompts are stored."
        if config.stores_prompts
        else "PII-like fields were declared; prompts are not persisted."
    )
    return Finding(
        check="pii_in_prompt_sample",
        score=score,
        severity="high" if score >= 15 else "medium",
        passed=False,
        detail=detail,
    )

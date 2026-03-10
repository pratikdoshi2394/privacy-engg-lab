from ai_privacy_guard.models import APGConfig, Finding, Policy


def run(config: APGConfig, policy: Policy) -> Finding:
    sensitive_hits = sorted(
        set(config.data_types).intersection(set(policy.sensitive_data_types))
    )
    if not sensitive_hits:
        return Finding(
            check="sensitive_data",
            score=0,
            severity="low",
            passed=True,
            detail="No policy-sensitive data types detected.",
        )

    weight = policy.weights.get("sensitive_data", 0)
    return Finding(
        check="sensitive_data",
        score=weight,
        severity="high",
        passed=False,
        detail=f"Sensitive data types detected: {', '.join(sensitive_hits)}.",
    )

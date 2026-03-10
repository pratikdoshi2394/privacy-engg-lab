from ai_privacy_guard.models import APGConfig, Finding, Policy


def run(config: APGConfig, policy: Policy) -> Finding:
    if not config.stores_prompts and not config.stores_outputs:
        return Finding(
            check="retention_risk",
            score=0,
            severity="low",
            passed=True,
            detail="Neither prompts nor outputs are retained.",
        )

    weight = policy.weights.get("retention_risk", 0)
    if config.stores_prompts and config.stores_outputs:
        score = weight
        detail = "Prompts and outputs are retained, increasing persistence risk."
    else:
        score = max(1, weight // 2)
        detail = "One content stream is retained, creating moderate persistence risk."

    return Finding(
        check="retention_risk",
        score=score,
        severity="medium",
        passed=False,
        detail=detail,
    )

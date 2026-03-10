from ai_privacy_guard.models import APGConfig, Finding, Policy


def run(config: APGConfig, policy: Policy) -> Finding:
    region = config.deployment_region.lower()
    if region in policy.allowed_regions:
        return Finding(
            check="region_policy_mismatch",
            score=0,
            severity="low",
            passed=True,
            detail=f"Region '{config.deployment_region}' is allowed by policy.",
        )

    weight = policy.weights.get("region_policy_mismatch", 0)
    return Finding(
        check="region_policy_mismatch",
        score=weight,
        severity="high",
        passed=False,
        detail=(
            f"Region '{config.deployment_region}' is not in allowed_regions "
            f"for policy '{policy.name}'."
        ),
    )

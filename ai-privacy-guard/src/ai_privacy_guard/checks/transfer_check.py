from ai_privacy_guard.models import APGConfig, Finding, Policy


def run(config: APGConfig, policy: Policy) -> Finding:
    is_untrusted_provider = config.provider.lower() not in policy.trusted_providers
    broad_exposure = config.end_users in {"public", "external", "third_party"}

    if not is_untrusted_provider and not broad_exposure:
        return Finding(
            check="third_party_transfer",
            score=0,
            severity="low",
            passed=True,
            detail="Provider and user access pattern do not indicate transfer risk.",
        )

    weight = policy.weights.get("third_party_transfer", 0)
    reasons = []
    if is_untrusted_provider:
        reasons.append("provider is not in trusted_providers")
    if broad_exposure:
        reasons.append("end_users implies broad external access")

    return Finding(
        check="third_party_transfer",
        score=weight,
        severity="medium",
        passed=False,
        detail="; ".join(reasons).capitalize() + ".",
    )

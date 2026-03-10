from ai_privacy_guard.models import APGConfig, Finding, Policy


def run(config: APGConfig, policy: Policy) -> Finding:
    missing = []
    for field_name in policy.required_metadata_fields:
        value = getattr(config, field_name, None)
        if isinstance(value, str) and not value.strip():
            missing.append(field_name)
        elif isinstance(value, list) and not value:
            missing.append(field_name)
        elif value is None:
            missing.append(field_name)

    if not missing:
        return Finding(
            check="missing_metadata",
            score=0,
            severity="low",
            passed=True,
            detail="Required metadata fields are populated.",
        )

    weight = policy.weights.get("missing_metadata", 0)
    return Finding(
        check="missing_metadata",
        score=weight,
        severity="medium",
        passed=False,
        detail=f"Missing or empty metadata fields: {', '.join(missing)}.",
    )

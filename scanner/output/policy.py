SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def filter_by_min_severity(findings: list, min_severity: str) -> list:
    min_level = SEVERITY_ORDER[min_severity]
    return [finding for finding in findings if SEVERITY_ORDER.get(finding.severity, 0) >= min_level]


def should_fail(findings: list, fail_on: str) -> bool:
    threshold = SEVERITY_ORDER[fail_on]
    return any(SEVERITY_ORDER.get(finding.severity, 0) >= threshold for finding in findings)

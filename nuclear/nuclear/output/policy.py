def should_fail(findings, fail_on):
    severity_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    fail_threshold = severity_levels.index(fail_on)

    for finding in findings:
        if severity_levels.index(finding.severity) >= fail_threshold:
            return True
    return False
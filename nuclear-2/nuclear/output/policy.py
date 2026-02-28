# filepath: nuclear/nuclear/output/policy.py
def should_fail(findings, fail_on):
    severity_levels = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    fail_threshold = severity_levels.index(fail_on) if fail_on in severity_levels else -1

    for finding in findings:
        if finding.severity in severity_levels and severity_levels.index(finding.severity) >= fail_threshold:
            return True
    return False
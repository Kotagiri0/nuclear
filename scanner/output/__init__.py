from scanner.output.reporting import deduplicate, generate_report
from scanner.output.policy import filter_by_min_severity, should_fail, SEVERITY_ORDER

__all__ = [
    "deduplicate",
    "generate_report",
    "filter_by_min_severity",
    "should_fail",
    "SEVERITY_ORDER",
]

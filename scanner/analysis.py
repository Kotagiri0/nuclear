"""Backward compatibility — re-exports from scanner.core.analysis."""
from scanner.core.analysis import *  # noqa: F401,F403
from scanner.core.analysis import (
    Finding,
    TaintStep,
    TaintTrace,
    _confidence,
    _extract_var_name,
    _find_sink_name,
    extract_match_value,
    has_context,
    is_false_positive,
    is_likely_hash,
    scan_content,
    score_to_severity,
    shannon_entropy,
    taint_analysis,
    validate_structure,
)

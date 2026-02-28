"""Backward compatibility — re-exports from scanner.output.reporting."""
from scanner.output.reporting import *  # noqa: F401,F403
from scanner.output.reporting import (
    _json_report,
    _sarif_report,
    _text_report,
    deduplicate,
    generate_report,
)

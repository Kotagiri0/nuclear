"""Backward compatibility — re-exports from scanner.core.patterns."""
from scanner.core.patterns import *  # noqa: F401,F403
from scanner.core.patterns import (
    CONTEXT_KEYWORDS,
    HASH_PATTERNS,
    HIGH_ENTROPY_FILE_TYPES,
    IGNORE_PATTERNS,
    PATTERNS,
    SINK_NAMES,
    SKIP_DIRS,
    SKIP_EXTENSIONS,
)

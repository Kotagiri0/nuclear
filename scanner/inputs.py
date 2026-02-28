"""Backward compatibility — re-exports from scanner.core.inputs.

Functions are imported individually so patch('scanner.inputs.X') works correctly.
"""
from scanner.core.inputs import (
    _clone_git_repo,
    _download_url,
    _looks_like_git_url,
    scan_remote_source,
)

__all__ = [
    "_clone_git_repo",
    "_download_url",
    "_looks_like_git_url",
    "scan_remote_source",
]

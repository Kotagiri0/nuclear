"""
Shared scan runner — used by both cli.py and repl to avoid code duplication.
"""
from __future__ import annotations

import fnmatch
from pathlib import Path

from scanner.core.inputs import scan_remote_source
from scanner.output.policy import filter_by_min_severity
from scanner.core.scanning import scan_directory, scan_file, scan_git_history, scan_zip


def run_scan(
    target: str | None = None,
    url: str | None = None,
    min_severity: str = "LOW",
    scan_history: bool = False,
    history_commits: int = 50,
    exclude: list[str] | None = None,
    include: list[str] | None = None,
    on_file=None,
) -> list:
    """Perform a scan and return filtered findings.

    Exactly one of *target* or *url* must be provided.

    Args:
        target: Local path (file, directory, or .zip archive).
        url: Remote Git/HTTP/ZIP URL.
        min_severity: Minimum severity level to include in results.
        scan_history: Whether to include git commit history.
        history_commits: Maximum number of git commits to scan.
        exclude: Glob patterns to exclude files from scanning.
        include: Glob patterns — only scan files matching these.
        on_file: Optional callback called with each filepath being scanned.

    Returns:
        List of Finding objects filtered by *min_severity*.

    Raises:
        ValueError: If neither or both of target/url are provided.
        FileNotFoundError: If the local target path does not exist.
    """
    if not target and not url:
        raise ValueError("Provide either a local target path or a --url.")
    if target and url:
        raise ValueError("Provide either a local target path or a --url, not both.")

    findings: list = []

    # Build file filter from exclude/include patterns
    def _file_filter(filepath: str) -> bool:
        name = Path(filepath).name
        rel = filepath
        if include:
            if not any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(rel, p) for p in include):
                return False
        if exclude:
            if any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(rel, p) for p in exclude):
                return False
        return True

    def _on_file_wrapper(filepath: str) -> None:
        if on_file is not None:
            on_file(filepath)

    if url:
        findings, _, _ = scan_remote_source(
            url,
            scan_history=scan_history,
            history_commits=history_commits,
        )
    else:
        path = Path(target)  # type: ignore[arg-type]
        if not path.exists():
            raise FileNotFoundError(f"Path does not exist: {target!r}")

        if path.suffix.lower() == ".zip":
            findings = scan_zip(str(path))
        elif path.is_dir():
            findings = scan_directory(str(path), on_file=_on_file_wrapper)
            if scan_history and (path / ".git").exists():
                findings.extend(scan_git_history(str(path), max_commits=history_commits))
        else:
            findings = scan_file(str(path))

    # Apply exclude/include filters to findings
    if exclude or include:
        findings = [f for f in findings if _file_filter(f.file)]

    return filter_by_min_severity(findings, min_severity)

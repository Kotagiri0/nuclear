"""
Shared scan runner — used by both cli.py and repl to avoid code duplication.
"""
from __future__ import annotations

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
) -> list:
    """Perform a scan and return filtered findings.

    Exactly one of *target* or *url* must be provided.

    Args:
        target: Local path (file, directory, or .zip archive).
        url: Remote Git/HTTP/ZIP URL.
        min_severity: Minimum severity level to include in results.
        scan_history: Whether to include git commit history.
        history_commits: Maximum number of git commits to scan.

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
            findings = scan_directory(str(path))
            if scan_history and (path / ".git").exists():
                findings.extend(scan_git_history(str(path), max_commits=history_commits))
        else:
            findings = scan_file(str(path))

    return filter_by_min_severity(findings, min_severity)

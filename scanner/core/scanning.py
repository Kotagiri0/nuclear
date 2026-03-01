import os
import shutil
import subprocess
import tempfile
import zipfile
from pathlib import Path

from scanner.core.analysis import scan_content
from scanner.core.patterns import SKIP_DIRS, SKIP_EXTENSIONS


def scan_file(filepath: str) -> list:
    path = Path(filepath)
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return []
    return scan_content(content, filepath)


def scan_directory(root: str, on_file=None) -> list:
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            if on_file is not None:
                on_file(filepath)
            findings.extend(scan_file(filepath))
    return findings


def scan_zip(zip_path: str) -> list:
    findings = []
    tmp_dir = tempfile.mkdtemp(prefix="secret_scanner_")
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            members = [
                m
                for m in zf.namelist()
                if not m.endswith("/")
                and not any(part in SKIP_DIRS for part in Path(m).parts)
                and Path(m).suffix.lower() not in SKIP_EXTENSIONS
            ]
            zf.extractall(tmp_dir, members=members)

        for member in members:
            extracted_path = os.path.join(tmp_dir, member)
            if not os.path.isfile(extracted_path):
                continue
            file_findings = scan_file(extracted_path)
            for finding in file_findings:
                finding.file = member
            findings.extend(file_findings)
    finally:
        try:
            shutil.rmtree(tmp_dir)
        except OSError:
            pass

    return findings


def _run_git(args: list, cwd: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="ignore",
        timeout=30,
    )
    if result.returncode != 0:
        return ""
    return result.stdout


def scan_git_history(repo_path: str, max_commits: int = 50) -> list:
    repo = Path(repo_path)
    if not (repo / ".git").exists():
        return []

    commit_list_raw = _run_git(["rev-list", f"--max-count={max_commits}", "HEAD"], cwd=repo_path)
    commit_ids = [line.strip() for line in commit_list_raw.splitlines() if line.strip()]
    if not commit_ids:
        return []

    findings = []
    seen_blobs = set()
    for commit in commit_ids:
        tree = _run_git(["ls-tree", "-r", "--name-only", commit], cwd=repo_path)
        files = [p.strip() for p in tree.splitlines() if p.strip()]
        for rel_path in files:
            ext = Path(rel_path).suffix.lower()
            if ext in SKIP_EXTENSIONS:
                continue
            if any(part in SKIP_DIRS for part in Path(rel_path).parts):
                continue

            # Cache by blob hash to avoid re-scanning identical content
            blob_hash = _run_git(["rev-parse", f"{commit}:{rel_path}"], cwd=repo_path).strip()
            if blob_hash in seen_blobs:
                continue
            seen_blobs.add(blob_hash)

            blob = _run_git(["show", f"{commit}:{rel_path}"], cwd=repo_path)
            if not blob:
                continue

            virtual_path = f"history/{commit[:12]}/{rel_path}"
            file_findings = scan_content(blob, virtual_path, source="history")
            findings.extend(file_findings)

    return findings

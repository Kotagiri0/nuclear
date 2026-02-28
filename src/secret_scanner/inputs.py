import shutil
import subprocess
import tempfile
import urllib.parse
import urllib.request
from pathlib import Path

from .scanning import scan_directory, scan_zip


def _looks_like_git_url(url: str) -> bool:
    path_candidate = Path(url)
    if path_candidate.exists() and (path_candidate / ".git").exists():
        return True
    if url.startswith("git@"):
        return True
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme in {"http", "https", "ssh"} and parsed.path.endswith(".git"):
        return True
    if parsed.scheme in {"http", "https"} and "github.com" in parsed.netloc:
        return True
    return False


def _download_url(url: str, out_dir: str) -> str:
    parsed = urllib.parse.urlparse(url)
    filename = Path(parsed.path).name or "downloaded_target"
    destination = Path(out_dir) / filename
    urllib.request.urlretrieve(url, destination)
    return str(destination)


def _clone_git_repo(url: str, out_dir: str, shallow: bool = True) -> str:
    path_candidate = Path(url)
    if path_candidate.exists() and (path_candidate / ".git").exists():
        return str(path_candidate)

    dst = Path(out_dir) / "repo"
    args = ["git", "clone", url, str(dst)]
    if shallow:
        args = ["git", "clone", "--depth", "1", url, str(dst)]

    result = subprocess.run(args, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Ошибка клонирования git-репозитория")
    return str(dst)


def scan_remote_source(url: str, scan_history: bool = False, history_commits: int = 50) -> tuple[list, str, str]:
    from .scanning import scan_git_history

    tmp_dir = tempfile.mkdtemp(prefix="secret_scanner_remote_")
    findings = []
    source_kind = "url"

    try:
        if _looks_like_git_url(url):
            source_kind = "git"
            repo_path = _clone_git_repo(url, tmp_dir, shallow=not scan_history)
            findings.extend(scan_directory(repo_path))
            if scan_history:
                findings.extend(scan_git_history(repo_path, max_commits=history_commits))
            return findings, repo_path, source_kind

        downloaded = _download_url(url, tmp_dir)
        suffix = Path(downloaded).suffix.lower()
        if suffix == ".zip":
            source_kind = "zip"
            findings.extend(scan_zip(downloaded))
            return findings, downloaded, source_kind

        source_kind = "file"
        if Path(downloaded).is_dir():
            findings.extend(scan_directory(downloaded))
        else:
            from .scanning import scan_file

            findings.extend(scan_file(downloaded))
        return findings, downloaded, source_kind
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

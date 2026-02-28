import subprocess
from pathlib import Path

from scanner import scan_remote_source


def test_scan_remote_source_supports_local_git_path(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("API_KEY='AKIAJX7LKQHMBQWRFP2A'\n", encoding="utf-8")

    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)

    findings, scanned_path, kind = scan_remote_source(str(repo), scan_history=False)
    assert kind == "git"
    assert scanned_path
    assert any(item.secret_type == "AWS Access Key" for item in findings)


def test_scan_remote_source_can_scan_history(tmp_path):
    repo = tmp_path / "repo_hist"
    repo.mkdir()

    subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "config", "user.name", "test"], cwd=repo, check=True, capture_output=True)

    (repo / "app.py").write_text("print('clean')\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "clean"], cwd=repo, check=True, capture_output=True)

    (repo / "app.py").write_text("TOKEN='ghp_mNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvW'\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "secret"], cwd=repo, check=True, capture_output=True)

    (repo / "app.py").write_text("print('clean again')\n", encoding="utf-8")
    subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
    subprocess.run(["git", "commit", "-m", "clean again"], cwd=repo, check=True, capture_output=True)

    findings, _, kind = scan_remote_source(str(repo), scan_history=True, history_commits=10)
    assert kind == "git"
    assert any(item.source == "history" for item in findings)
    assert any(item.secret_type == "GitHub Token" for item in findings)

"""
Tests for scanner/scanning.py — all branches.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from scanner.scanning import (
    _run_git,
    scan_directory,
    scan_file,
    scan_git_history,
)


# ── scan_file ──────────────────────────────────────────────────────────────────

class TestScanFile:
    def test_finds_secret_in_file(self, tmp_path):
        f = tmp_path / "config.py"
        f.write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")
        findings = scan_file(str(f))
        assert any(fi.secret_type == "AWS Access Key" for fi in findings)

    def test_returns_empty_for_clean_file(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("print('hello world')\n", encoding="utf-8")
        assert scan_file(str(f)) == []

    def test_skips_jpg_extension(self, tmp_path):
        f = tmp_path / "photo.jpg"
        f.write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")
        assert scan_file(str(f)) == []

    def test_skips_png_extension(self, tmp_path):
        f = tmp_path / "img.png"
        f.write_text("data", encoding="utf-8")
        assert scan_file(str(f)) == []

    def test_skips_lock_extension(self, tmp_path):
        f = tmp_path / "yarn.lock"
        f.write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")
        assert scan_file(str(f)) == []

    def test_returns_empty_on_oserror(self, tmp_path):
        f = tmp_path / "file.py"
        f.write_text("data", encoding="utf-8")
        with patch("pathlib.Path.read_text", side_effect=OSError("permission denied")):
            result = scan_file(str(f))
        assert result == []

    def test_returns_empty_on_permission_error(self, tmp_path):
        f = tmp_path / "file.py"
        f.write_text("data", encoding="utf-8")
        with patch("pathlib.Path.read_text", side_effect=PermissionError("denied")):
            result = scan_file(str(f))
        assert result == []

    def test_handles_utf8_errors_without_crash(self, tmp_path):
        f = tmp_path / "binary.py"
        f.write_bytes(b"\xff\xfe AKIAJX7LKQHMBQWRFP2A\n")
        # Should not raise; may or may not find the key depending on decode
        result = scan_file(str(f))
        assert isinstance(result, list)

    def test_correct_filepath_in_finding(self, tmp_path):
        f = tmp_path / "keys.py"
        f.write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")
        findings = scan_file(str(f))
        assert findings
        assert findings[0].file == str(f)


# ── scan_directory ────────────────────────────────────────────────────────────

class TestScanDirectory:
    def test_finds_secrets_recursively(self, tmp_path):
        sub = tmp_path / "sub"
        sub.mkdir()
        (sub / "config.py").write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")
        findings = scan_directory(str(tmp_path))
        assert any(fi.secret_type == "AWS Access Key" for fi in findings)

    def test_skips_node_modules(self, tmp_path):
        nm = tmp_path / "node_modules" / "pkg"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")
        findings = scan_directory(str(tmp_path))
        assert not any("node_modules" in fi.file for fi in findings)

    def test_skips_pycache(self, tmp_path):
        pc = tmp_path / "__pycache__"
        pc.mkdir()
        (pc / "module.pyc").write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")
        findings = scan_directory(str(tmp_path))
        assert not any("__pycache__" in fi.file for fi in findings)

    def test_skips_dot_git_dir(self, tmp_path):
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "config").write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")
        findings = scan_directory(str(tmp_path))
        assert not any(".git" in fi.file for fi in findings)

    def test_skips_venv(self, tmp_path):
        venv = tmp_path / ".venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "site.py").write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")
        findings = scan_directory(str(tmp_path))
        assert not any(".venv" in fi.file for fi in findings)

    def test_empty_directory_returns_empty(self, tmp_path):
        assert scan_directory(str(tmp_path)) == []

    def test_only_skippable_files_returns_empty(self, tmp_path):
        (tmp_path / "img.jpg").write_bytes(b"\xff\xd8\xff")
        assert scan_directory(str(tmp_path)) == []

    def test_multiple_files_with_secrets(self, tmp_path):
        (tmp_path / "a.py").write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("ghp_mNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvW\n", encoding="utf-8")
        findings = scan_directory(str(tmp_path))
        types = {fi.secret_type for fi in findings}
        assert "AWS Access Key" in types
        assert "GitHub Token" in types


# ── _run_git ──────────────────────────────────────────────────────────────────

class TestRunGit:
    def test_nonzero_returncode_returns_empty_string(self, tmp_path):
        result = _run_git(["rev-list", "--max-count=1", "HEAD"], cwd=str(tmp_path))
        assert result == ""

    def test_valid_command_returns_output(self, tmp_path):
        subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
        output = _run_git(["rev-parse", "--git-dir"], cwd=str(tmp_path))
        assert ".git" in output


# ── scan_git_history ──────────────────────────────────────────────────────────

class TestScanGitHistory:
    def _make_repo(self, tmp_path: Path) -> Path:
        repo = tmp_path / "repo"
        repo.mkdir()
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True, capture_output=True)
        return repo

    def test_no_dot_git_returns_empty(self, tmp_path):
        plain = tmp_path / "plain"
        plain.mkdir()
        assert scan_git_history(str(plain)) == []

    def test_empty_repo_no_commits_returns_empty(self, tmp_path):
        repo = self._make_repo(tmp_path)
        result = scan_git_history(str(repo))
        assert result == []

    def test_finds_secret_in_history(self, tmp_path):
        repo = self._make_repo(tmp_path)
        (repo / "app.py").write_text("TOKEN='ghp_mNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvW'\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "add secret"], cwd=repo, check=True, capture_output=True)
        findings = scan_git_history(str(repo), max_commits=10)
        assert any(fi.secret_type == "GitHub Token" for fi in findings)

    def test_findings_have_source_history(self, tmp_path):
        repo = self._make_repo(tmp_path)
        (repo / "app.py").write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "secret"], cwd=repo, check=True, capture_output=True)
        findings = scan_git_history(str(repo))
        assert all(fi.source == "history" for fi in findings)

    def test_max_commits_limits_scan(self, tmp_path):
        repo = self._make_repo(tmp_path)
        # Create 5 commits
        for i in range(5):
            f = repo / f"file{i}.py"
            f.write_text(f"# commit {i}\n", encoding="utf-8")
            subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
            subprocess.run(["git", "commit", "-m", f"c{i}"], cwd=repo, check=True, capture_output=True)
        # Scan only 2 commits — should not crash and return list
        result = scan_git_history(str(repo), max_commits=2)
        assert isinstance(result, list)

    def test_skips_image_extensions_in_history(self, tmp_path):
        repo = self._make_repo(tmp_path)
        (repo / "photo.jpg").write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "img"], cwd=repo, check=True, capture_output=True)
        findings = scan_git_history(str(repo))
        assert not any(fi.file.endswith(".jpg") for fi in findings)

    def test_virtual_path_contains_commit_hash(self, tmp_path):
        repo = self._make_repo(tmp_path)
        (repo / "cfg.py").write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "secret"], cwd=repo, check=True, capture_output=True)
        findings = scan_git_history(str(repo))
        assert any(fi.file.startswith("history/") for fi in findings)

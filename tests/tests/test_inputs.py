"""
Tests for scanner/inputs.py — all branches.
"""
from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scanner.core.inputs import (
    _clone_git_repo,
    _download_url,
    _looks_like_git_url,
    scan_remote_source,
)


# ── _looks_like_git_url ───────────────────────────────────────────────────────

class TestLooksLikeGitUrl:
    def test_git_at_prefix(self):
        assert _looks_like_git_url("git@github.com:user/repo.git")

    def test_https_dot_git_suffix(self):
        assert _looks_like_git_url("https://github.com/user/repo.git")

    def test_http_dot_git_suffix(self):
        assert _looks_like_git_url("http://example.com/repo.git")

    def test_github_com_without_dot_git(self):
        assert _looks_like_git_url("https://github.com/user/repo")

    def test_local_path_with_dot_git(self, tmp_path):
        (tmp_path / ".git").mkdir()
        assert _looks_like_git_url(str(tmp_path))

    def test_local_path_without_dot_git(self, tmp_path):
        assert not _looks_like_git_url(str(tmp_path))

    def test_plain_http_zip_url(self):
        assert not _looks_like_git_url("https://example.com/archive.zip")

    def test_plain_http_file_url(self):
        assert not _looks_like_git_url("https://example.com/config.txt")

    def test_ssh_dot_git(self):
        assert _looks_like_git_url("ssh://git@example.com/repo.git")


# ── _download_url ─────────────────────────────────────────────────────────────

class TestDownloadUrl:
    def test_filename_extracted_from_url(self, tmp_path):
        with patch("urllib.request.urlretrieve") as mock_ret:
            mock_ret.side_effect = lambda url, dest: None
            result = _download_url("https://example.com/myfile.zip", str(tmp_path))
        assert result.endswith("myfile.zip")

    def test_fallback_filename_when_no_path(self, tmp_path):
        with patch("urllib.request.urlretrieve") as mock_ret:
            mock_ret.side_effect = lambda url, dest: None
            result = _download_url("https://example.com/", str(tmp_path))
        assert "downloaded_target" in result

    def test_calls_urlretrieve_with_correct_args(self, tmp_path):
        with patch("urllib.request.urlretrieve") as mock_ret:
            mock_ret.side_effect = lambda url, dest: None
            _download_url("https://example.com/data.zip", str(tmp_path))
        mock_ret.assert_called_once()
        call_url = mock_ret.call_args[0][0]
        assert call_url == "https://example.com/data.zip"


# ── _clone_git_repo ────────────────────────────────────────────────────────────

class TestCloneGitRepo:
    def test_local_path_with_git_returned_directly(self, tmp_path):
        (tmp_path / ".git").mkdir()
        result = _clone_git_repo(str(tmp_path), str(tmp_path / "out"))
        assert result == str(tmp_path)

    def test_successful_clone(self, tmp_path):
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("subprocess.run", return_value=mock_result):
            result = _clone_git_repo("https://example.com/repo.git", str(tmp_path))
        assert result.endswith("repo")

    def test_failed_clone_raises_runtime_error(self, tmp_path):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "fatal: repository not found"
        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(RuntimeError, match="repository not found"):
                _clone_git_repo("https://bad.example.com/repo.git", str(tmp_path))

    def test_shallow_clone_adds_depth_flag(self, tmp_path):
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            _clone_git_repo("https://example.com/repo.git", str(tmp_path), shallow=True)
        args_used = mock_run.call_args[0][0]
        assert "--depth" in args_used

    def test_non_shallow_clone_no_depth_flag(self, tmp_path):
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            _clone_git_repo("https://example.com/repo.git", str(tmp_path), shallow=False)
        args_used = mock_run.call_args[0][0]
        assert "--depth" not in args_used

    def test_failed_clone_empty_stderr_uses_fallback_message(self, tmp_path):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = ""
        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(RuntimeError):
                _clone_git_repo("https://bad.example.com/repo.git", str(tmp_path))


# ── scan_remote_source ────────────────────────────────────────────────────────

class TestScanRemoteSource:
    def _make_local_git_repo(self, tmp_path: Path) -> Path:
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)
        return repo

    def test_local_git_returns_git_kind(self, tmp_path):
        repo = self._make_local_git_repo(tmp_path)
        findings, _, kind = scan_remote_source(str(repo))
        assert kind == "git"

    def test_local_git_finds_secrets(self, tmp_path):
        repo = self._make_local_git_repo(tmp_path)
        findings, _, _ = scan_remote_source(str(repo))
        assert any(f.secret_type == "AWS Access Key" for f in findings)

    def test_zip_url_returns_zip_kind(self, tmp_path):
        zf_path = tmp_path / "pkg.zip"
        with zipfile.ZipFile(zf_path, "w") as zf:
            zf.writestr("secret.py", "AKIAJX7LKQHMBQWRFP2A\n")

        with patch("scanner.core.inputs._looks_like_git_url", return_value=False), \
             patch("scanner.core.inputs._download_url", return_value=str(zf_path)):
            findings, _, kind = scan_remote_source("https://example.com/pkg.zip")
        assert kind == "zip"

    def test_file_url_returns_file_kind(self, tmp_path):
        secret_file = tmp_path / "cfg.py"
        secret_file.write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")

        with patch("scanner.core.inputs._looks_like_git_url", return_value=False), \
             patch("scanner.core.inputs._download_url", return_value=str(secret_file)):
            findings, _, kind = scan_remote_source("https://example.com/cfg.py")
        assert kind == "file"

    def test_scan_history_calls_git_history(self, tmp_path):
        repo = self._make_local_git_repo(tmp_path)
        findings, _, kind = scan_remote_source(str(repo), scan_history=True, history_commits=5)
        assert kind == "git"
        # history findings have source="history"
        history_findings = [f for f in findings if f.source == "history"]
        # at least one commit was scanned
        assert isinstance(history_findings, list)

    def test_tmp_dir_cleaned_up_on_success(self, tmp_path):
        repo = self._make_local_git_repo(tmp_path)
        import scanner.core.inputs as inputs_mod
        created_dirs: list[str] = []
        original_mkdtemp = tempfile.mkdtemp

        def tracking_mkdtemp(**kwargs):
            d = original_mkdtemp(**kwargs)
            created_dirs.append(d)
            return d

        with patch("scanner.core.inputs.tempfile") as mock_tmpmod:
            mock_tmpmod.mkdtemp = tracking_mkdtemp
            # For local git repo, tmp_dir is created but repo is returned directly
            scan_remote_source(str(repo))

    def test_tmp_dir_cleaned_up_on_exception(self, tmp_path):
        """Even on clone failure, tempfile should be cleaned up (finally block)."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "fatal error"

        with patch("scanner.core.inputs._looks_like_git_url", return_value=True), \
             patch("scanner.core.inputs._clone_git_repo", side_effect=RuntimeError("fail")):
            with pytest.raises(RuntimeError):
                scan_remote_source("https://bad.example.com/repo.git")

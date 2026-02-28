"""
Tests for scanner/runner.py — all branches.
"""
from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

from scanner.runner import run_scan


# ── error handling ─────────────────────────────────────────────────────────────

class TestRunScanErrors:
    def test_no_args_raises_value_error(self):
        with pytest.raises(ValueError, match="Provide either"):
            run_scan()

    def test_both_args_raises_value_error(self):
        with pytest.raises(ValueError, match="not both"):
            run_scan(target="some/path", url="https://example.com/repo.git")

    def test_nonexistent_path_raises_file_not_found(self):
        with pytest.raises(FileNotFoundError, match="does not exist"):
            run_scan(target="/nonexistent/path/file.py")


# ── local file scan ────────────────────────────────────────────────────────────

class TestRunScanFile:
    def test_scans_file_with_secret(self, tmp_path):
        f = tmp_path / "config.py"
        f.write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")
        findings = run_scan(target=str(f))
        assert any(fi.secret_type == "AWS Access Key" for fi in findings)

    def test_scans_clean_file_returns_empty(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("print('hello world')\n", encoding="utf-8")
        assert run_scan(target=str(f)) == []

    def test_min_severity_filter_applied(self, tmp_path):
        f = tmp_path / "config.py"
        f.write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")
        all_findings = run_scan(target=str(f), min_severity="LOW")
        high_only = run_scan(target=str(f), min_severity="CRITICAL")
        # CRITICAL filter may return fewer results
        assert len(high_only) <= len(all_findings)


# ── local directory scan ───────────────────────────────────────────────────────

class TestRunScanDirectory:
    def test_scans_directory(self, tmp_path):
        (tmp_path / "a.py").write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")
        findings = run_scan(target=str(tmp_path))
        assert any(fi.secret_type == "AWS Access Key" for fi in findings)

    def test_empty_directory_returns_empty(self, tmp_path):
        assert run_scan(target=str(tmp_path)) == []

    def test_scan_history_on_git_repo(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)
        findings = run_scan(target=str(repo), scan_history=True, history_commits=5)
        assert isinstance(findings, list)

    def test_scan_history_on_non_git_dir_no_crash(self, tmp_path):
        (tmp_path / "clean.py").write_text("print('ok')\n", encoding="utf-8")
        # No .git → history scan skipped, no crash
        findings = run_scan(target=str(tmp_path), scan_history=True)
        assert isinstance(findings, list)


# ── zip scan ───────────────────────────────────────────────────────────────────

class TestRunScanZip:
    def _make_zip(self, tmp_path: Path, files: dict) -> Path:
        zf_path = tmp_path / "archive.zip"
        with zipfile.ZipFile(zf_path, "w") as zf:
            for name, content in files.items():
                zf.writestr(name, content)
        return zf_path

    def test_scans_zip_file(self, tmp_path):
        zf = self._make_zip(tmp_path, {"config.py": "AKIAJX7LKQHMBQWRFP2A\n"})
        findings = run_scan(target=str(zf))
        assert any(fi.secret_type == "AWS Access Key" for fi in findings)

    def test_empty_zip_returns_empty(self, tmp_path):
        zf = self._make_zip(tmp_path, {})
        assert run_scan(target=str(zf)) == []


# ── URL scan ───────────────────────────────────────────────────────────────────

class TestRunScanUrl:
    def test_url_scan_delegates_to_scan_remote_source(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.py").write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")
        subprocess.run(["git", "init"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.email", "t@t.com"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "add", "."], cwd=repo, check=True, capture_output=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=repo, check=True, capture_output=True)
        findings = run_scan(url=str(repo))
        assert any(fi.secret_type == "AWS Access Key" for fi in findings)

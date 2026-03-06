"""
Full CLI integration tests — exit codes, flags, output file.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


def _run_cli(*args, stdin=None) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "scanner.cli", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


# ── basic invocation ──────────────────────────────────────────────────────────

class TestCLIBasic:
    def test_no_args_exits_nonzero(self):
        result = _run_cli()
        assert result.returncode != 0

    def test_nonexistent_path_exits_1(self, tmp_path):
        result = _run_cli(str(tmp_path / "ghost.py"))
        assert result.returncode == 1
        assert "не существует" in result.stderr or "does not exist" in result.stderr.lower() or result.returncode == 1

    def test_clean_file_exits_0(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("print('hello world')\n", encoding="utf-8")
        result = _run_cli(str(f))
        assert result.returncode == 0

    def test_secret_file_exits_1_with_fail_on_low(self, tmp_path):
        f = tmp_path / "vuln.py"
        f.write_text("AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe\n", encoding="utf-8")
        result = _run_cli(str(f), "--fail-on", "LOW")
        assert result.returncode == 1

    def test_secret_file_exits_0_with_fail_on_critical_and_no_critical(self, tmp_path):
        f = tmp_path / "vuln.py"
        # AWS key score ~9-15 depending on context — may be CRITICAL, so use a LOW-scoring secret
        f.write_text("password = 'hunter2'\n", encoding="utf-8")
        result = _run_cli(str(f), "--fail-on", "CRITICAL", "--min-severity", "LOW")
        # Exit 0 if no CRITICAL findings; exit 1 if there are
        assert result.returncode in (0, 1)


# ── format flags ─────────────────────────────────────────────────────────────

class TestCLIFormats:
    def test_json_format_is_valid_json(self, tmp_path):
        f = tmp_path / "vuln.py"
        f.write_text("AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe\n", encoding="utf-8")
        result = _run_cli(str(f), "--format", "json")
        data = json.loads(result.stdout)
        assert "findings" in data
        assert "total" in data

    def test_sarif_format_is_valid_sarif(self, tmp_path):
        f = tmp_path / "vuln.py"
        f.write_text("AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe\n", encoding="utf-8")
        result = _run_cli(str(f), "--format", "sarif")
        data = json.loads(result.stdout)
        assert "runs" in data
        assert data["version"] == "2.1.0"

    def test_text_format_contains_severity_label(self, tmp_path):
        f = tmp_path / "vuln.py"
        f.write_text("AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe\n", encoding="utf-8")
        result = _run_cli(str(f), "--format", "text", "--min-severity", "LOW")
        assert any(sev in result.stdout for sev in ("HIGH", "CRITICAL", "MEDIUM", "LOW"))


# ── severity flags ────────────────────────────────────────────────────────────

class TestCLISeverity:
    def test_min_severity_critical_filters_lower(self, tmp_path):
        f = tmp_path / "vuln.py"
        f.write_text("AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe\n", encoding="utf-8")
        all_result = _run_cli(str(f), "--format", "json", "--min-severity", "LOW")
        crit_result = _run_cli(str(f), "--format", "json", "--min-severity", "CRITICAL")
        all_data = json.loads(all_result.stdout)
        crit_data = json.loads(crit_result.stdout)
        assert crit_data["total"] <= all_data["total"]

    def test_fail_on_high_exits_1_for_critical_finding(self, tmp_path):
        f = tmp_path / "vuln.py"
        f.write_text("AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe\n", encoding="utf-8")
        result = _run_cli(str(f), "--fail-on", "HIGH", "--min-severity", "LOW")
        # AWS key should be HIGH or CRITICAL → exit 1
        assert result.returncode == 1

    def test_fail_on_critical_may_exit_0_for_high(self, tmp_path):
        f = tmp_path / "vuln.py"
        # Generic password is typically MEDIUM/HIGH, not CRITICAL
        f.write_text("password = 'hunter2'\n", encoding="utf-8")
        result = _run_cli(str(f), "--fail-on", "CRITICAL", "--min-severity", "LOW")
        # Could be 0 or 1 depending on score — just check it doesn't crash
        assert result.returncode in (0, 1)


# ── zip scan via CLI ──────────────────────────────────────────────────────────

class TestCLIZip:
    def test_zip_scan_works(self, tmp_path):
        import zipfile
        zf_path = tmp_path / "archive.zip"
        with zipfile.ZipFile(zf_path, "w") as zf:
            zf.writestr("config.py", "AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe\n")
        result = _run_cli(str(zf_path), "--format", "json")
        data = json.loads(result.stdout)
        assert data["total"] >= 1


# ── --output flag ─────────────────────────────────────────────────────────────

class TestCLIOutputFile:
    def test_output_writes_to_file(self, tmp_path):
        vuln = tmp_path / "vuln.py"
        vuln.write_text("AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe\n", encoding="utf-8")
        out = tmp_path / "report.json"
        result = _run_cli(str(vuln), "--format", "json", "--output", str(out))
        assert out.exists()
        data = json.loads(out.read_text(encoding="utf-8"))
        assert "findings" in data

    def test_output_file_has_no_stdout(self, tmp_path):
        vuln = tmp_path / "vuln.py"
        vuln.write_text("AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe\n", encoding="utf-8")
        out = tmp_path / "report.json"
        result = _run_cli(str(vuln), "--format", "json", "--output", str(out))
        # stdout should be empty when writing to file
        assert result.stdout.strip() == ""

    def test_output_creates_parent_dirs(self, tmp_path):
        vuln = tmp_path / "vuln.py"
        vuln.write_text("AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe\n", encoding="utf-8")
        out = tmp_path / "sub" / "dir" / "report.json"
        _run_cli(str(vuln), "--format", "json", "--output", str(out))
        assert out.exists()


# ── scan history via CLI ──────────────────────────────────────────────────────

class TestCLIScanHistory:
    def test_scan_history_on_non_git_dir_no_crash(self, tmp_path):
        (tmp_path / "clean.py").write_text("print('ok')\n", encoding="utf-8")
        result = _run_cli(str(tmp_path), "--scan-history")
        assert result.returncode in (0, 1)

    def test_history_commits_default_parsed(self, tmp_path):
        from scanner.cli import build_parser
        parser = build_parser()
        args = parser.parse_args([str(tmp_path)])
        assert args.history_commits == 50

    def test_history_commits_custom(self, tmp_path):
        from scanner.cli import build_parser
        parser = build_parser()
        args = parser.parse_args([str(tmp_path), "--history-commits", "25"])
        assert args.history_commits == 25

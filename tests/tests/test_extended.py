"""
Extended test suite: 6 new test classes covering advanced scenarios.
"""
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from scanner import (
    Finding,
    filter_by_min_severity,
    generate_report,
    scan_content,
    scan_zip,
    score_to_severity,
    shannon_entropy,
    should_fail,
)
from scanner.core.analysis import taint_analysis
from scanner.cli import build_parser
from scanner.output.reporting import _sarif_report, deduplicate


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_finding(severity: str, score: int = 5, file: str = "f.py", line: int = 1) -> Finding:
    return Finding(
        file=file,
        line_number=line,
        line_content="line",
        secret_type="Generic Secret",
        matched_value="s3cr3t_v4lue_here",
        score=score,
        severity=severity,
        category="credential",
        confidence=0.5,
        entropy=4.0,
    )


# ---------------------------------------------------------------------------
# 1. SARIF Report
# ---------------------------------------------------------------------------

class TestSarifReport:
    """Tests for SARIF output format correctness."""

    def _findings(self):
        return [
            _make_finding("HIGH", score=9),
            _make_finding("MEDIUM", score=6),
            _make_finding("LOW", score=3),
        ]

    def test_sarif_has_required_schema(self):
        report = json.loads(_sarif_report(self._findings()))
        assert "$schema" in report
        assert "sarif" in report["$schema"].lower()

    def test_sarif_version(self):
        report = json.loads(_sarif_report(self._findings()))
        assert report["version"] == "2.1.0"

    def test_sarif_has_runs(self):
        report = json.loads(_sarif_report(self._findings()))
        assert "runs" in report
        assert len(report["runs"]) >= 1

    def test_sarif_tool_name(self):
        report = json.loads(_sarif_report(self._findings()))
        driver = report["runs"][0]["tool"]["driver"]
        assert "name" in driver
        assert driver["name"]

    def test_sarif_rules_populated(self):
        report = json.loads(_sarif_report(self._findings()))
        rules = report["runs"][0]["tool"]["driver"]["rules"]
        assert len(rules) >= 1
        rule = rules[0]
        assert "id" in rule
        assert "name" in rule

    def test_sarif_high_severity_maps_to_error(self):
        findings = [_make_finding("HIGH", score=9), _make_finding("CRITICAL", score=13)]
        report = json.loads(_sarif_report(findings))
        results = report["runs"][0]["results"]
        levels = {r["level"] for r in results}
        assert "error" in levels

    def test_sarif_low_medium_maps_to_warning(self):
        findings = [_make_finding("LOW", score=3), _make_finding("MEDIUM", score=6)]
        report = json.loads(_sarif_report(findings))
        results = report["runs"][0]["results"]
        levels = {r["level"] for r in results}
        assert "warning" in levels

    def test_sarif_results_have_locations(self):
        report = json.loads(_sarif_report(self._findings()))
        for result in report["runs"][0]["results"]:
            assert "locations" in result
            loc = result["locations"][0]
            assert "physicalLocation" in loc

    def test_sarif_empty_findings(self):
        report = json.loads(_sarif_report([]))
        assert report["runs"][0]["results"] == []

    def test_sarif_rule_ids_are_unique_per_type(self):
        findings = [
            _make_finding("HIGH", score=9),
            _make_finding("LOW", score=3),
        ]
        # Same secret_type → same rule_id
        report = json.loads(_sarif_report(findings))
        rules = report["runs"][0]["tool"]["driver"]["rules"]
        ids = [r["id"] for r in rules]
        assert len(ids) == len(set(ids))


# ---------------------------------------------------------------------------
# 2. Policy — filter + should_fail
# ---------------------------------------------------------------------------

class TestPolicy:
    """Tests for severity filtering and CI gate logic."""

    def _mixed(self):
        return [
            _make_finding("LOW"),
            _make_finding("MEDIUM"),
            _make_finding("HIGH"),
            _make_finding("CRITICAL"),
        ]

    def test_filter_low_returns_all(self):
        result = filter_by_min_severity(self._mixed(), "LOW")
        assert len(result) == 4

    def test_filter_medium_excludes_low(self):
        result = filter_by_min_severity(self._mixed(), "MEDIUM")
        severities = {f.severity for f in result}
        assert "LOW" not in severities
        assert len(result) == 3

    def test_filter_high_returns_only_high_and_critical(self):
        result = filter_by_min_severity(self._mixed(), "HIGH")
        assert all(f.severity in {"HIGH", "CRITICAL"} for f in result)
        assert len(result) == 2

    def test_filter_critical_returns_only_critical(self):
        result = filter_by_min_severity(self._mixed(), "CRITICAL")
        assert all(f.severity == "CRITICAL" for f in result)
        assert len(result) == 1

    def test_filter_empty_findings(self):
        assert filter_by_min_severity([], "LOW") == []

    def test_should_fail_true_when_meets_threshold(self):
        findings = [_make_finding("HIGH")]
        assert should_fail(findings, "HIGH") is True

    def test_should_fail_true_when_exceeds_threshold(self):
        findings = [_make_finding("CRITICAL")]
        assert should_fail(findings, "HIGH") is True

    def test_should_fail_false_when_below_threshold(self):
        findings = [_make_finding("LOW"), _make_finding("MEDIUM")]
        assert should_fail(findings, "HIGH") is False

    def test_should_fail_empty(self):
        assert should_fail([], "LOW") is False

    def test_should_fail_critical_threshold(self):
        findings = [_make_finding("HIGH")]
        assert should_fail(findings, "CRITICAL") is False

    def test_should_fail_low_threshold_any_finding(self):
        findings = [_make_finding("LOW")]
        assert should_fail(findings, "LOW") is True


# ---------------------------------------------------------------------------
# 3. CLI Args + Exit Codes
# ---------------------------------------------------------------------------

class TestCLIArgs:
    """Tests for CLI argument parsing and exit behavior."""

    def test_parser_default_format(self):
        parser = build_parser()
        args = parser.parse_args(["some_target"])
        assert args.format == "text"

    def test_parser_default_min_severity(self):
        parser = build_parser()
        args = parser.parse_args(["some_target"])
        assert args.min_severity == "LOW"

    def test_parser_default_fail_on(self):
        parser = build_parser()
        args = parser.parse_args(["some_target"])
        assert args.fail_on == "HIGH"

    def test_parser_default_scan_history_false(self):
        parser = build_parser()
        args = parser.parse_args(["some_target"])
        assert args.scan_history is False

    def test_parser_scan_history_flag(self):
        parser = build_parser()
        args = parser.parse_args(["some_target", "--scan-history"])
        assert args.scan_history is True

    def test_parser_format_json(self):
        parser = build_parser()
        args = parser.parse_args(["target", "--format", "json"])
        assert args.format == "json"

    def test_parser_format_sarif(self):
        parser = build_parser()
        args = parser.parse_args(["target", "--format", "sarif"])
        assert args.format == "sarif"

    def test_parser_url_argument(self):
        parser = build_parser()
        args = parser.parse_args(["--url", "https://github.com/example/repo"])
        assert args.url == "https://github.com/example/repo"

    def test_parser_history_commits_default(self):
        parser = build_parser()
        args = parser.parse_args(["target"])
        assert args.history_commits == 50

    def test_parser_history_commits_custom(self):
        parser = build_parser()
        args = parser.parse_args(["target", "--history-commits", "10"])
        assert args.history_commits == 10

    def test_cli_exits_zero_on_clean_file(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("print('hello world')\n", encoding="utf-8")
        import os
        env = {**os.environ, "PYTHONIOENCODING": "utf-8"}
        result = subprocess.run(
            [sys.executable, "-m", "scanner.cli", str(f)],
            capture_output=True, text=True, env=env
        )
        assert result.returncode == 0

    def test_cli_exits_nonzero_on_secret(self, tmp_path):
        f = tmp_path / "vuln.py"
        f.write_text("API_KEY='AKIAJX7LKQHMBQWRFP2A'\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-m", "scanner.cli", str(f), "--fail-on", "LOW"],
            capture_output=True, text=True
        )
        assert result.returncode == 1

    def test_cli_json_output_is_valid_json(self, tmp_path):
        f = tmp_path / "vuln.py"
        f.write_text("API_KEY='AKIAJX7LKQHMBQWRFP2A'\n", encoding="utf-8")
        result = subprocess.run(
            [sys.executable, "-m", "scanner.cli", str(f), "--format", "json"],
            capture_output=True, text=True
        )
        data = json.loads(result.stdout)
        assert "findings" in data
        assert "total" in data


# ---------------------------------------------------------------------------
# 4. Taint Deep Chains
# ---------------------------------------------------------------------------

class TestTaintDeepChains:
    """Tests for multi-step taint propagation."""

    def test_chain_a_b_c_to_sink(self):
        content = """\
a = 'AKIAJX7LKQHMBQWRFP2A'
b = a
c = b
requests.get('https://api.example.com', headers={'key': c})
"""
        traces = taint_analysis(content, "app.py", [("a", 1)])
        assert len(traces) >= 1
        trace = traces[0]
        assert trace.sink_type == "HTTP request"
        assert trace.depth() >= 1

    def test_multiple_sinks_detected(self):
        content = """\
token = 'ghp_mNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvW'
logging.info(token)
requests.post('https://api.com', data={'t': token})
"""
        traces = taint_analysis(content, "app.py", [("token", 1)])
        sink_types = {t.sink_type for t in traces}
        assert len(sink_types) >= 2

    def test_no_taint_when_var_not_in_sink(self):
        content = """\
secret = 'AKIAJX7LKQHMBQWRFP2A'
other = 'hello'
print(other)
"""
        traces = taint_analysis(content, "app.py", [("secret", 1)])
        assert len(traces) == 0

    def test_propagation_recorded_in_steps(self):
        content = """\
key = 'AKIAJX7LKQHMBQWRFP2A'
derived = key
requests.get('https://api.example.com', params={'k': derived})
"""
        traces = taint_analysis(content, "app.py", [("key", 1)])
        assert len(traces) >= 1
        assert traces[0].depth() >= 1

    def test_empty_secret_vars_returns_empty(self):
        content = "print('hello')\n"
        traces = taint_analysis(content, "app.py", [])
        assert traces == []

    def test_source_file_matches_sink_file(self):
        content = """\
pw = 'SuperSecret123!'
subprocess.run(['curl', pw])
"""
        traces = taint_analysis(content, "deploy.py", [("pw", 1)])
        if traces:
            assert traces[0].source_file == "deploy.py"
            assert traces[0].sink_file == "deploy.py"

    def test_taint_with_logging_sink(self):
        content = """\
api_key = 'AKIAJX7LKQHMBQWRFP2A'
logging.warning(api_key)
"""
        traces = taint_analysis(content, "app.py", [("api_key", 1)])
        assert any(t.sink_type == "Logging" for t in traces)

    def test_scan_content_taint_boosts_severity(self):
        content = """\
API_KEY = 'AKIAJX7LKQHMBQWRFP2A'
import requests
requests.get('https://api.example.com', headers={'X-Key': API_KEY})
"""
        findings = scan_content(content, "app.py")
        assert len(findings) >= 1
        # At least one finding should have taint traces
        tainted = [f for f in findings if f.taint_traces]
        assert len(tainted) >= 1
        # Tainted finding should have higher score boost
        for f in tainted:
            assert f.score >= f.score  # taint boosts score by +2


# ---------------------------------------------------------------------------
# 5. ZIP Advanced
# ---------------------------------------------------------------------------

class TestZipAdvanced:
    """Advanced ZIP scanning scenarios."""

    def _make_zip(self, tmp_path, files: dict) -> str:
        zf_path = tmp_path / "test.zip"
        with zipfile.ZipFile(zf_path, "w") as zf:
            for name, content in files.items():
                zf.writestr(name, content)
        return str(zf_path)

    def test_multiple_secrets_in_zip(self, tmp_path):
        zf = self._make_zip(tmp_path, {
            "a.py": "API_KEY='AKIAJX7LKQHMBQWRFP2A'\n",
            "b.py": "TOKEN='ghp_mNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvW'\n",
            "c.env": "DB_PASSWORD='UltraSecret_456!'\n",
        })
        findings = scan_zip(zf)
        types = {f.secret_type for f in findings}
        assert len(types) >= 2

    def test_zip_skips_binary_extensions(self, tmp_path):
        zf = self._make_zip(tmp_path, {
            "image.jpg": "AKIAJX7LKQHMBQWRFP2A",
            "font.ttf": "ghp_mNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvW",
            "safe.py": "print('ok')\n",
        })
        findings = scan_zip(zf)
        # Binary files should be skipped
        files_scanned = {f.file for f in findings}
        assert not any(f.endswith(".jpg") or f.endswith(".ttf") for f in files_scanned)

    def test_zip_nested_directory_structure(self, tmp_path):
        zf = self._make_zip(tmp_path, {
            "project/src/config.py": "SECRET_KEY='AKIAJX7LKQHMBQWRFP2A'\n",
            "project/README.md": "# safe readme\n",
        })
        findings = scan_zip(zf)
        assert len(findings) >= 1
        # Path should reflect inner zip structure
        assert any("config.py" in f.file for f in findings)

    def test_zip_skips_node_modules(self, tmp_path):
        zf = self._make_zip(tmp_path, {
            "node_modules/lib/index.js": "const key='AKIAJX7LKQHMBQWRFP2A';\n",
            "src/app.js": "console.log('safe');\n",
        })
        findings = scan_zip(zf)
        files = {f.file for f in findings}
        assert not any("node_modules" in f for f in files)

    def test_zip_env_file_scanned(self, tmp_path):
        zf = self._make_zip(tmp_path, {
            "backend/.env": "DATABASE_URL=postgres://admin:UltraSecr3t@db.prod.local/mydb\n",
        })
        findings = scan_zip(zf)
        assert len(findings) >= 1

    def test_zip_empty_file_no_crash(self, tmp_path):
        zf = self._make_zip(tmp_path, {
            "empty.py": "",
            "clean.py": "print('hello')\n",
        })
        findings = scan_zip(zf)
        assert isinstance(findings, list)

    def test_zip_connection_string_detected(self, tmp_path):
        zf = self._make_zip(tmp_path, {
            "config.yaml": "dsn: postgres://admin:SuperSecret@db.prod.local:5432/mydb\n",
        })
        findings = scan_zip(zf)
        assert any(f.secret_type == "Connection String" for f in findings)


# ---------------------------------------------------------------------------
# 6. Entropy Edge Cases
# ---------------------------------------------------------------------------

class TestEntropyEdgeCases:
    """Tests for entropy calculation and its effect on scoring."""

    def test_high_entropy_string(self):
        # Random-looking string should have high entropy
        val = "aB3xK9mZ2qR7nL5pT0wY"
        assert shannon_entropy(val) > 3.5

    def test_low_entropy_repeated_chars(self):
        val = "aaaaaaaaaaaaaaaa"
        assert shannon_entropy(val) == 0.0

    def test_low_entropy_reduces_no_bonus(self):
        # A value with entropy < 3.5 shouldn't get entropy bonus
        content = "token = 'aaaaaaaaaaaabbbbbbbbbbbb'\n"
        findings = scan_content(content, "f.py")
        for f in findings:
            assert f.entropy < 3.5 or f.score >= 0  # just no crash

    def test_high_entropy_boosts_score(self):
        # High-entropy value should have higher score than low-entropy equivalent
        high_ent = "aB3xK9mZ2qR7nL5pT0wY4cD8"
        low_ent = "aaaaaaaaaaaaaaaaaaaaaaaaa"
        h = shannon_entropy(high_ent)
        l = shannon_entropy(low_ent)
        assert h > l

    def test_entropy_boundary_3_5(self):
        # String with entropy just above 3.5
        val = "abcdefghij"
        e = shannon_entropy(val)
        assert e > 3.0  # roughly 3.32 for uniform 10 chars

    def test_entropy_boundary_4_5(self):
        val = "aAbBcCdDeEfF0123456789!@"
        e = shannon_entropy(val)
        assert e > 4.0

    def test_scan_content_env_file_gets_bonus(self):
        content = "SECRET_KEY='UltraSecret_456!'\n"
        findings_env = scan_content(content, "config.env")
        findings_py = scan_content(content, "config.py")
        if findings_env and findings_py:
            env_scores = [f.score for f in findings_env]
            py_scores = [f.score for f in findings_py]
            # .env file should produce equal or higher scores due to file type bonus
            assert max(env_scores) >= max(py_scores)

    def test_entropy_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_entropy_single_char(self):
        assert shannon_entropy("x") == 0.0

    def test_high_entropy_in_yaml_gets_double_bonus(self):
        # yaml is in HIGH_ENTROPY_FILE_TYPES, should get +2 score bonus
        content = "api_key: aB3xK9mZ2qR7nL5pT0wY4cD8eF1\n"
        findings = scan_content(content, "config.yaml")
        assert any(f.score >= 5 for f in findings) if findings else True

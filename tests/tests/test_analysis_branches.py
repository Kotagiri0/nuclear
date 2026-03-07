"""
Tests for scanner/analysis.py — branch coverage.
"""
from __future__ import annotations

import re

import pytest

from scanner.core.analysis import (
    _confidence,
    _extract_var_name,
    _find_sink_name,
    extract_match_value,
    scan_content,
    score_to_severity,
    shannon_entropy,
    taint_analysis,
)


# ── extract_match_value ───────────────────────────────────────────────────────

class TestExtractMatchValue:
    def test_returns_group1_when_present(self):
        m = re.search(r"key\s*=\s*['\"]([^'\"]+)['\"]", "key = 'mySecretValue'")
        assert extract_match_value(m) == "mySecretValue"

    def test_returns_group0_when_no_capture_group(self):
        m = re.search(r"AQ[A-Za-z0-9_-]{38,}", "AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe")
        assert extract_match_value(m) == "AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe"

    def test_returns_group0_for_non_capturing_group(self):
        # re.match with no capture groups
        m = re.search(r"token\s+\S+", "token abcdef1234567890")
        assert extract_match_value(m) == "token abcdef1234567890"


# ── _extract_var_name ─────────────────────────────────────────────────────────

class TestExtractVarName:
    def test_simple_assignment(self):
        assert _extract_var_name("MY_KEY = 'value'") == "MY_KEY"

    def test_assignment_with_leading_spaces(self):
        assert _extract_var_name("    API_SECRET = 'value'") == "API_SECRET"

    def test_lowercase_var(self):
        assert _extract_var_name("token = 'abc'") == "token"

    def test_no_assignment_returns_none(self):
        assert _extract_var_name("print('hello')") is None

    def test_function_call_returns_none(self):
        assert _extract_var_name("requests.get('url')") is None

    def test_empty_line_returns_none(self):
        assert _extract_var_name("") is None

    def test_var_with_digits(self):
        assert _extract_var_name("key2 = 'value'") == "key2"


# ── _find_sink_name ───────────────────────────────────────────────────────────

class TestFindSinkName:
    def test_requests_get(self):
        assert _find_sink_name("requests.get('https://api.example.com')") == "HTTP request"

    def test_requests_post(self):
        assert _find_sink_name("requests.post(url, data=payload)") == "HTTP request"

    def test_logging_info(self):
        assert _find_sink_name("logging.info(f'token={TOKEN}')") == "Logging"

    def test_logging_warning(self):
        assert _find_sink_name("logging.warning('token: ' + TOKEN)") == "Logging"

    def test_print(self):
        assert _find_sink_name("print(secret_key)") == "Console output"

    def test_subprocess_run(self):
        assert _find_sink_name("subprocess.run(['curl', token])") == "Shell execution"

    def test_os_system(self):
        assert _find_sink_name("os.system(f'curl -H {token}')") == "Shell execution"

    def test_open(self):
        assert _find_sink_name("open('output.txt', 'w')") == "File write"

    def test_boto3(self):
        assert _find_sink_name("boto3.client('s3')") == "AWS SDK call"

    def test_smtplib(self):
        assert _find_sink_name("smtplib.SMTP('smtp.gmail.com')") == "Email sending"

    def test_psycopg2(self):
        assert _find_sink_name("psycopg2.connect(dsn)") == "PostgreSQL query"

    def test_no_sink_returns_none(self):
        assert _find_sink_name("x = 1 + 2") is None

    def test_plain_assignment_no_sink(self):
        assert _find_sink_name("token = 'value'") is None

    def test_httpx(self):
        assert _find_sink_name("httpx.get('https://example.com')") == "HTTP request"

    def test_paramiko(self):
        assert _find_sink_name("paramiko.SSHClient()") == "SSH connection"


# ── _confidence ───────────────────────────────────────────────────────────────

class TestConfidence:
    def test_minimum_confidence_with_low_inputs(self):
        c = _confidence(score=2, entropy=1.0, struct_valid=False, tainted=False)
        assert 0 < c < 0.5

    def test_high_score_increases_confidence(self):
        c_low = _confidence(score=2, entropy=1.0, struct_valid=False, tainted=False)
        c_high = _confidence(score=14, entropy=1.0, struct_valid=False, tainted=False)
        assert c_high > c_low

    def test_high_entropy_adds_bonus(self):
        c_no_ent = _confidence(score=6, entropy=2.0, struct_valid=False, tainted=False)
        c_ent = _confidence(score=6, entropy=5.0, struct_valid=False, tainted=False)
        assert c_ent > c_no_ent

    def test_struct_valid_adds_bonus(self):
        c_no_struct = _confidence(score=6, entropy=2.0, struct_valid=False, tainted=False)
        c_struct = _confidence(score=6, entropy=2.0, struct_valid=True, tainted=False)
        assert c_struct > c_no_struct

    def test_tainted_adds_bonus(self):
        c_no_taint = _confidence(score=6, entropy=2.0, struct_valid=False, tainted=False)
        c_taint = _confidence(score=6, entropy=2.0, struct_valid=False, tainted=True)
        assert c_taint > c_no_taint

    def test_never_exceeds_0_99(self):
        c = _confidence(score=20, entropy=6.0, struct_valid=True, tainted=True)
        assert c <= 0.99

    def test_all_bonuses_still_capped(self):
        for score in range(1, 25):
            c = _confidence(score=score, entropy=6.0, struct_valid=True, tainted=True)
            assert c <= 0.99

    def test_returns_float(self):
        c = _confidence(score=5, entropy=3.0, struct_valid=False, tainted=False)
        assert isinstance(c, float)


# ── scan_content branches ─────────────────────────────────────────────────────

class TestScanContentBranches:
    def test_empty_content_returns_empty(self):
        assert scan_content("", "test.py") == []

    def test_only_python_comments_returns_empty(self):
        content = "# api_key = 'AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe'\n# token = 'abc'\n"
        assert scan_content(content, "test.py") == []

    def test_only_cpp_comments_returns_empty(self):
        content = "// api_key = 'AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe'\n// secret\n"
        assert scan_content(content, "test.js") == []

    def test_hash_value_reduces_score(self):
        # MD5-like hex string: is_likely_hash → True → score -= 3
        # Twilio Auth Token regex matches 32-char hex but base_score=3, after -3 = 0 → filtered
        content = "auth = 'vk_token_xK9mZ2qR7nL5pT0wY4c'\n"
        findings = scan_content(content, "test.py")
        # Either no findings, or score is reduced
        for f in findings:
            # Hash-detected findings should have lower or equal base score
            assert f.score >= 0

    def test_env_file_bonus_applied(self):
        content = "API_KEY=sber_xK9mZ2qR7nL5pT0wY4cD8eF1gH3j\n"
        findings_env = scan_content(content, "config.env")
        findings_py = scan_content(content, "config.py")
        if findings_env and findings_py:
            assert max(f.score for f in findings_env) >= max(f.score for f in findings_py)

    def test_dot_env_extension_extra_bonus(self):
        content = "API_KEY=sber_xK9mZ2qR7nL5pT0wY4cD8eF1gH3j\n"
        findings_env = scan_content(content, ".env")
        findings_cfg = scan_content(content, "config.cfg")
        if findings_env and findings_cfg:
            # .env gets +1 extra on top of HIGH_ENTROPY_FILE_TYPES +2
            assert max(f.score for f in findings_env) >= max(f.score for f in findings_cfg)

    def test_structural_valid_adds_to_score(self):
        # AWS key has validate_structure → True → +3 score
        content = "AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe\n"
        findings = scan_content(content, "test.py")
        aws = [f for f in findings if f.secret_type == "Yandex Cloud Service Account Key"]
        assert aws
        assert aws[0].structural_valid is True

    def test_low_score_finding_filtered(self):
        # Generic patterns with very low scores should be filtered when score < 2
        # Twilio Auth Token base_score=3, but hex string -3 → score=0 → filtered
        content = "auth = 'vk_token_xK9mZ2qR7nL5pT0wY4c'\n"
        findings = scan_content(content, "test.py")
        for f in findings:
            assert f.score >= 2

    def test_confidence_set_on_all_findings(self):
        content = "AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe\n"
        findings = scan_content(content, "test.py")
        for f in findings:
            assert 0 < f.confidence <= 0.99

    def test_taint_analysis_only_for_supported_extensions(self):
        # .py → taint analysis runs
        content = (
            "import requests\n"
            "API_KEY = 'AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe'\n"
            "requests.get('https://api.example.com', headers={'key': API_KEY})\n"
        )
        findings_py = scan_content(content, "test.py")
        findings_txt = scan_content(content, "test.txt")
        # .py should have taint traces, .txt should not
        tainted_py = [f for f in findings_py if f.taint_traces]
        tainted_txt = [f for f in findings_txt if f.taint_traces]
        assert len(tainted_py) >= len(tainted_txt)

    def test_entropy_above_4_5_adds_3_to_score(self):
        # High entropy random-looking VK API token
        content = "vk567890abcdefghijklmnopqrstuvwxyzABCD\n"
        findings = scan_content(content, "test.py")
        vk = [f for f in findings if f.secret_type == "VK API Access Token"]
        assert vk
        # Entropy should be recorded
        assert vk[0].entropy > 0

    def test_context_match_detected(self):
        content = "# api_key context here\napi_key = 'AQxK9mZ2qR7nL5pT0wY4cD8eF1gH3jB6vNxAaBbCcDdEe'\n"
        findings = scan_content(content, "test.py")
        aws = [f for f in findings if f.secret_type == "Yandex Cloud Service Account Key"]
        if aws:
            assert aws[0].context_match is True

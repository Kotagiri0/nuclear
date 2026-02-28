import os
import zipfile
import tempfile
import pytest
from secret_scanner import (
    shannon_entropy,
    is_likely_hash,
    is_false_positive,
    has_context,
    validate_structure,
    score_to_severity,
    scan_content,
    scan_zip,
    taint_analysis,
    generate_report,
    Finding,
    TaintTrace,
    TaintStep,
)


class TestShannonEntropy:
    def test_empty_string(self):
        assert shannon_entropy("") == 0.0

    def test_single_char(self):
        assert shannon_entropy("aaaa") == 0.0

    def test_high_entropy(self):
        assert shannon_entropy("kJH78sdKJH9823kjsdKJHsdkj23==") > 3.5

    def test_low_entropy(self):
        assert shannon_entropy("aaaaaabbbbb") < 2.0

    def test_known_value(self):
        assert abs(shannon_entropy("ab") - 1.0) < 0.01


class TestIsLikelyHash:
    def test_md5(self):
        assert is_likely_hash("d41d8cd98f00b204e9800998ecf8427e")

    def test_sha1(self):
        assert is_likely_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709")

    def test_sha256(self):
        assert is_likely_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    def test_not_hash(self):
        assert not is_likely_hash("AKIAJX7LKQHMBQWRFP2A")

    def test_uppercase_md5(self):
        assert is_likely_hash("D41D8CD98F00B204E9800998ECF8427E")


class TestIsFalsePositive:
    def test_example_keyword(self):
        assert is_false_positive("this_is_example_key")

    def test_test_keyword(self):
        assert is_false_positive("test_api_key_value")

    def test_xxxx(self):
        assert is_false_positive("xxxxxxxxxxxxxxxxxxxx")

    def test_placeholder(self):
        assert is_false_positive("your_key_here")

    def test_low_char_diversity(self):
        assert is_false_positive("aaabbbccc")

    def test_real_looking_key(self):
        assert not is_false_positive("kJH78sdKJH9823kjsdKJHsdkj23Rz")


class TestHasContext:
    def test_finds_api_key(self):
        lines = ["some code", "api_key = 'secret'", "other code"]
        assert has_context(lines, 1)

    def test_finds_password(self):
        lines = ["password = 'hunter2'"]
        assert has_context(lines, 0)

    def test_no_context(self):
        lines = ["print('hello world')", "x = 1 + 2"]
        assert not has_context(lines, 0)

    def test_context_in_surrounding_lines(self):
        lines = ["secret:", "'kJH78sdKJH9823kjsdKJH'", "other"]
        assert has_context(lines, 1)


class TestValidateStructure:
    def test_valid_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        assert validate_structure("JWT Token", jwt)

    def test_invalid_jwt(self):
        assert not validate_structure("JWT Token", "notajwt")

    def test_valid_aws_key(self):
        assert validate_structure("AWS Access Key", "AKIAIOSFODNN7EXAMPLE")

    def test_invalid_aws_key(self):
        assert not validate_structure("AWS Access Key", "BKIAIOSFODNN7EXAMPLE")

    def test_private_key(self):
        assert validate_structure("Private Key", "-----BEGIN RSA PRIVATE KEY-----")

    def test_unknown_type(self):
        assert not validate_structure("Unknown Type", "somevalue")


class TestScoreToSeverity:
    def test_critical(self):
        assert score_to_severity(12) == "CRITICAL"
        assert score_to_severity(15) == "CRITICAL"

    def test_high(self):
        assert score_to_severity(8) == "HIGH"
        assert score_to_severity(11) == "HIGH"

    def test_medium(self):
        assert score_to_severity(5) == "MEDIUM"
        assert score_to_severity(7) == "MEDIUM"

    def test_low(self):
        assert score_to_severity(1) == "LOW"
        assert score_to_severity(4) == "LOW"


class TestTaintAnalysis:
    def test_direct_sink(self):
        content = (
            "import requests\n"
            "API_KEY = 'AKIAJX7LKQHMBQWRFP2A'\n"
            "requests.get('https://api.com', headers={'key': API_KEY})\n"
        )
        traces = taint_analysis(content, "test.py", [("API_KEY", 2)])
        assert len(traces) > 0
        assert traces[0].sink_type == "HTTP request"
        assert traces[0].source_variable == "API_KEY"

    def test_propagation_chain(self):
        content = (
            "import requests\n"
            "SECRET = 'kJH78sdKJH9823kjsdKJHsdkj23Rz'\n"
            "headers = {'Authorization': SECRET}\n"
            "requests.post('https://api.com', headers=headers)\n"
        )
        traces = taint_analysis(content, "test.py", [("SECRET", 2)])
        assert len(traces) > 0
        assert any(len(t.steps) > 0 for t in traces)

    def test_logging_sink(self):
        content = (
            "import logging\n"
            "TOKEN = 'ghp_mNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvW'\n"
            "logging.info(f'token={TOKEN}')\n"
        )
        traces = taint_analysis(content, "test.py", [("TOKEN", 2)])
        assert any(t.sink_type == "Logging" for t in traces)

    def test_no_sink(self):
        content = (
            "API_KEY = 'AKIAJX7LKQHMBQWRFP2A'\n"
            "x = API_KEY.upper()\n"
        )
        traces = taint_analysis(content, "test.py", [("API_KEY", 1)])
        assert len(traces) == 0

    def test_empty_vars(self):
        content = "requests.get('https://api.com')\n"
        traces = taint_analysis(content, "test.py", [])
        assert traces == []

    def test_taint_depth(self):
        content = (
            "import requests\n"
            "RAW = 'AKIAJX7LKQHMBQWRFP2A'\n"
            "KEY = RAW\n"
            "AUTH = KEY\n"
            "requests.post('https://api.com', headers={'key': AUTH})\n"
        )
        traces = taint_analysis(content, "test.py", [("RAW", 2)])
        assert len(traces) > 0
        assert max(t.depth() for t in traces) >= 2

    def test_sink_file_matches_source(self):
        content = (
            "import requests\n"
            "TOKEN = 'ghp_mNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvW'\n"
            "requests.get('https://api.com', params={'t': TOKEN})\n"
        )
        traces = taint_analysis(content, "myfile.py", [("TOKEN", 2)])
        for t in traces:
            assert t.source_file == "myfile.py"
            assert t.sink_file == "myfile.py"


class TestScanContent:
    def test_finds_aws_key(self):
        content = "AKIAJX7LKQHMBQWRFP2A\n"
        findings = scan_content(content, "test.py")
        assert any(f.secret_type == "AWS Access Key" for f in findings)

    def test_finds_github_token(self):
        content = "ghp_mNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvW\n"
        findings = scan_content(content, "config.py")
        assert any(f.secret_type == "GitHub Token" for f in findings)

    def test_skips_comments(self):
        content = "# ключ_api = \"ghp_mNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvW\"\n"
        assert len(scan_content(content, "test.py")) == 0

    def test_finds_jwt(self):
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        findings = scan_content(f"Authorization: Bearer {jwt}\n", "config.yaml")
        assert len(findings) > 0

    def test_env_file_bonus(self):
        content = 'STRIPE_KEY="sk_live_abcdefghijklmnopqrstuvwx"\n'
        fe = scan_content(content, ".env")
        fp = scan_content(content, "config.py")
        se = [f.score for f in fe]
        sp = [f.score for f in fp]
        if se and sp:
            assert max(se) >= max(sp)

    def test_false_positive_filtered(self):
        findings = scan_content('api_key = "example_key_placeholder"\n', "test.py")
        assert all("example" not in f.matched_value.lower() for f in findings)

    def test_private_key_detection(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpA==\n-----END RSA PRIVATE KEY-----\n"
        findings = scan_content(content, "key.pem")
        assert any(f.secret_type == "Private Key" for f in findings)

    def test_generic_secret(self):
        assert len(scan_content("password = 'SuperSecret123!'\n", "settings.py")) > 0

    def test_correct_line_number(self):
        content = "import os\napi_key = 'AKIAJX7LKQHMBQWRFP2A'\n"
        aws = [f for f in scan_content(content, "test.py") if f.secret_type == "AWS Access Key"]
        if aws:
            assert aws[0].line_number == 2

    def test_taint_attached_to_finding(self):
        content = (
            "import requests\n"
            "API_KEY = 'AKIAJX7LKQHMBQWRFP2A'\n"
            "requests.get('https://api.com', headers={'key': API_KEY})\n"
        )
        findings = scan_content(content, "test.py")
        aws = [f for f in findings if f.secret_type == "AWS Access Key"]
        assert aws
        assert len(aws[0].taint_traces) > 0

    def test_taint_boosts_score(self):
        plain = "API_KEY = 'AKIAJX7LKQHMBQWRFP2A'\n"
        with_sink = (
            "import requests\n"
            "API_KEY = 'AKIAJX7LKQHMBQWRFP2A'\n"
            "requests.get('https://api.com', params={'k': API_KEY})\n"
        )
        plain_f = [f for f in scan_content(plain, "test.py") if f.secret_type == "AWS Access Key"]
        sink_f = [f for f in scan_content(with_sink, "test.py") if f.secret_type == "AWS Access Key"]
        if plain_f and sink_f:
            assert sink_f[0].score > plain_f[0].score


class TestScanZip:
    def _make_zip(self, files: dict) -> str:
        tmp = tempfile.mktemp(suffix=".zip")
        with zipfile.ZipFile(tmp, "w") as zf:
            for name, content in files.items():
                zf.writestr(name, content)
        return tmp

    def test_basic_zip_scan(self):
        path = self._make_zip({"config.py": "AKIAJX7LKQHMBQWRFP2A\n"})
        try:
            findings = scan_zip(path)
            assert any(f.secret_type == "AWS Access Key" for f in findings)
        finally:
            os.unlink(path)

    def test_zip_preserves_inner_path(self):
        path = self._make_zip({"subdir/secrets.py": "AKIAJX7LKQHMBQWRFP2A\n"})
        try:
            findings = scan_zip(path)
            assert any(f.file == "subdir/secrets.py" for f in findings)
        finally:
            os.unlink(path)

    def test_zip_skips_images(self):
        path = self._make_zip({
            "photo.jpg": b"\xff\xd8\xff".decode("latin-1"),
            "code.py": "AKIAJX7LKQHMBQWRFP2A\n",
        })
        try:
            findings = scan_zip(path)
            assert all(f.file != "photo.jpg" for f in findings)
        finally:
            os.unlink(path)

    def test_zip_skips_node_modules(self):
        path = self._make_zip({
            "node_modules/pkg/index.js": "AKIAJX7LKQHMBQWRFP2A\n",
            "app.py": "AKIAJX7LKQHMBQWRFP2A\n",
        })
        try:
            findings = scan_zip(path)
            assert not any("node_modules" in f.file for f in findings)
        finally:
            os.unlink(path)

    def test_zip_multiple_files(self):
        path = self._make_zip({
            "api.py": "AKIAJX7LKQHMBQWRFP2A\n",
            ".env": "STRIPE_KEY=sk_live_abcdefghijklmnopqrstuvwx\n",
            "auth.py": "ghp_mNpQrStUvWxYzAbCdEfGhIjKlMnOpQrStUvW\n",
        })
        try:
            findings = scan_zip(path)
            found_files = {f.file for f in findings}
            assert len(found_files) >= 2
        finally:
            os.unlink(path)

    def test_empty_zip(self):
        path = self._make_zip({})
        try:
            assert scan_zip(path) == []
        finally:
            os.unlink(path)

    def test_zip_with_taint(self):
        content = (
            "import requests\n"
            "API_KEY = 'AKIAJX7LKQHMBQWRFP2A'\n"
            "requests.get('https://api.com', params={'k': API_KEY})\n"
        )
        path = self._make_zip({"service.py": content})
        try:
            findings = scan_zip(path)
            aws = [f for f in findings if f.secret_type == "AWS Access Key"]
            assert aws and len(aws[0].taint_traces) > 0
        finally:
            os.unlink(path)


class TestGenerateReport:
    def _make_finding(self, severity="HIGH", score=8):
        return Finding(
            file="test.py",
            line_number=1,
            line_content='api_key = "secret"',
            secret_type="Generic API Key",
            matched_value="secretvalue123456789",
            score=score,
            severity=severity,
        )

    def _make_finding_with_taint(self):
        f = self._make_finding("CRITICAL", 14)
        f.taint_traces = [
            TaintTrace(
                source_variable="API_KEY",
                source_file="test.py",
                source_line=1,
                sink_type="HTTP request",
                sink_file="test.py",
                sink_line=5,
                sink_content="requests.get(url, headers={'key': API_KEY})",
                steps=[
                    TaintStep("test.py", 3, "headers = {'key': API_KEY}", "headers", "propagated from API_KEY")
                ],
            )
        ]
        return f

    def test_empty_findings(self):
        assert "Секреты не найдены" in generate_report([])

    def test_text_report_contains_severity(self):
        assert "HIGH" in generate_report([self._make_finding("HIGH", 8)], "text")

    def test_text_report_contains_filename(self):
        assert "test.py" in generate_report([self._make_finding()], "text")

    def test_json_report_structure(self):
        import json
        data = json.loads(generate_report([self._make_finding()], "json"))
        assert "total" in data and data["total"] == 1

    def test_deduplication(self):
        f1 = self._make_finding()
        f2 = self._make_finding()
        assert generate_report([f1, f2], "text").count("test.py:1") == 1

    def test_sorted_by_score(self):
        import json
        f_low = self._make_finding("LOW", 2)
        f_crit = self._make_finding("CRITICAL", 14)
        data = json.loads(generate_report([f_low, f_crit], "json"))
        scores = [i["score"] for i in data["findings"]]
        assert scores == sorted(scores, reverse=True)

    def test_taint_in_json_report(self):
        import json
        f = self._make_finding_with_taint()
        data = json.loads(generate_report([f], "json"))
        traces = data["findings"][0]["taint_traces"]
        assert len(traces) == 1
        assert traces[0]["sink_type"] == "HTTP request"
        assert traces[0]["depth"] == 1

    def test_taint_in_text_report(self):
        f = self._make_finding_with_taint()
        report = generate_report([f], "text")
        assert "Taint trace" in report
        assert "HTTP request" in report
        assert "API_KEY" in report

    def test_taint_steps_in_json(self):
        import json
        f = self._make_finding_with_taint()
        data = json.loads(generate_report([f], "json"))
        steps = data["findings"][0]["taint_traces"][0]["steps"]
        assert len(steps) == 1
        assert steps[0]["variable"] == "headers"

    def test_taint_warning_in_summary(self):
        f = self._make_finding_with_taint()
        report = generate_report([f], "text")
        assert "dangerous sinks" in report

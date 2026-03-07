"""Extended tests for the web API — scanning, recommendations, edge cases."""
from __future__ import annotations

import json
import threading
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

import pytest

from scanner.web.app import (
    _Handler,
    _build_summary,
    _normalize_globs,
    _parse_bool,
    _parse_scan_request,
)
from scanner.core.analysis import Finding


# ── Helpers ───────────────────────────────────────────────────────────────────

def _start_server(default_target: str = ".") -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.default_target = default_target  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _request_json(base_url: str, payload: dict) -> tuple[int, dict]:
    req = Request(
        f"{base_url}/api/scan",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def _get(base_url: str, path: str) -> tuple[int, str]:
    try:
        with urlopen(f"{base_url}{path}", timeout=10) as resp:
            return resp.status, resp.read().decode("utf-8")
    except HTTPError as exc:
        return exc.code, exc.read().decode("utf-8")


# ── _build_summary ────────────────────────────────────────────────────────────

class TestBuildSummary:
    def test_empty_list(self):
        summary = _build_summary([])
        assert summary == {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    def test_counts_by_severity(self):
        findings = [
            type("F", (), {"severity": "CRITICAL"})(),
            type("F", (), {"severity": "CRITICAL"})(),
            type("F", (), {"severity": "HIGH"})(),
        ]
        summary = _build_summary(findings)
        assert summary["CRITICAL"] == 2
        assert summary["HIGH"] == 1
        assert summary["MEDIUM"] == 0


# ── _normalize_globs ──────────────────────────────────────────────────────────

class TestNormalizeGlobs:
    def test_none_returns_none(self):
        assert _normalize_globs(None, "test") is None

    def test_string_returns_list(self):
        result = _normalize_globs("*.py", "test")
        assert result == ["*.py"]

    def test_list_returns_list(self):
        result = _normalize_globs(["*.py", "*.js"], "test")
        assert result == ["*.py", "*.js"]

    def test_empty_string_raises(self):
        with pytest.raises(ValueError, match="не может быть пустой"):
            _normalize_globs("  ", "test")

    def test_non_string_element_raises(self):
        with pytest.raises(ValueError):
            _normalize_globs([123], "test")

    def test_integer_raises(self):
        with pytest.raises(ValueError):
            _normalize_globs(42, "test")


# ── _parse_bool ───────────────────────────────────────────────────────────────

class TestParseBool:
    def test_none_returns_default(self):
        assert _parse_bool(None, "f", default=True) is True
        assert _parse_bool(None, "f", default=False) is False

    def test_bool_passthrough(self):
        assert _parse_bool(True, "f") is True
        assert _parse_bool(False, "f") is False

    def test_int_converted(self):
        assert _parse_bool(1, "f") is True
        assert _parse_bool(0, "f") is False

    def test_string_true_variants(self):
        for val in ("1", "true", "True", "yes", "on"):
            assert _parse_bool(val, "f") is True

    def test_string_false_variants(self):
        for val in ("0", "false", "False", "no", "off", ""):
            assert _parse_bool(val, "f") is False

    def test_invalid_string_raises(self):
        with pytest.raises(ValueError):
            _parse_bool("sometimes", "f")


# ── _parse_scan_request ───────────────────────────────────────────────────────

class TestParseScanRequest:
    def test_empty_request_uses_default_target(self):
        result = _parse_scan_request({}, "/tmp/default")
        assert result["target"] == "/tmp/default"
        assert result["url"] is None

    def test_target_overrides_default(self):
        result = _parse_scan_request({"target": "/other"}, "/tmp/default")
        assert result["target"] == "/other"

    def test_url_provided(self):
        result = _parse_scan_request({"url": "https://github.com/repo.git"}, "/tmp")
        assert result["url"] == "https://github.com/repo.git"
        assert result["target"] is None

    def test_both_target_and_url_raises(self):
        with pytest.raises(ValueError, match="target или url"):
            _parse_scan_request({"target": "/foo", "url": "https://bar"}, "/tmp")

    def test_invalid_severity_raises(self):
        with pytest.raises(ValueError, match="min_severity"):
            _parse_scan_request({"min_severity": "URGENT"}, "/tmp")

    def test_history_commits_out_of_range_raises(self):
        with pytest.raises(ValueError, match="history_commits"):
            _parse_scan_request({"history_commits": 0}, "/tmp")

    def test_non_dict_payload_raises(self):
        with pytest.raises(ValueError, match="объектом"):
            _parse_scan_request("not-a-dict", "/tmp")

    def test_defaults(self):
        result = _parse_scan_request({}, "/tmp")
        assert result["min_severity"] == "LOW"
        assert result["scan_history"] is False
        assert result["history_commits"] == 50
        assert result["include_recommendations"] is False
        assert result["exclude"] is None
        assert result["include"] is None


# ── Web API Integration ───────────────────────────────────────────────────────

class TestWebAPIIntegration:
    def test_scan_finds_secrets_in_vulnerable_file(self, tmp_path):
        vuln = tmp_path / "app.py"
        vuln.write_text('password = "SuperSecretP@ssw0rd123!"\n', encoding="utf-8")

        server, thread = _start_server(default_target=str(tmp_path))
        port = server.server_address[1]
        base_url = f"http://127.0.0.1:{port}"
        try:
            status, body = _request_json(base_url, {"target": str(tmp_path)})
            assert status == 200
            assert body["total"] >= 1
            assert any(f["type"] == "Generic Secret" for f in body["findings"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_scan_with_recommendations_includes_recommendation_field(self, tmp_path):
        vuln = tmp_path / "app.py"
        vuln.write_text('API_KEY = "AKIAJX7LKQHMBQWRFP2A"\n', encoding="utf-8")

        server, thread = _start_server(default_target=str(tmp_path))
        port = server.server_address[1]
        base_url = f"http://127.0.0.1:{port}"
        try:
            status, body = _request_json(base_url, {
                "target": str(tmp_path),
                "recommendations": True,
            })
            assert status == 200
            assert body["total"] >= 1
            finding = body["findings"][0]
            assert "recommendation" in finding
            assert "title" in finding["recommendation"]
            assert "description" in finding["recommendation"]
            assert "priority" in finding["recommendation"]
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_scan_without_recommendations_excludes_field(self, tmp_path):
        vuln = tmp_path / "app.py"
        vuln.write_text('API_KEY = "AKIAJX7LKQHMBQWRFP2A"\n', encoding="utf-8")

        server, thread = _start_server(default_target=str(tmp_path))
        port = server.server_address[1]
        base_url = f"http://127.0.0.1:{port}"
        try:
            status, body = _request_json(base_url, {
                "target": str(tmp_path),
                "recommendations": False,
            })
            assert status == 200
            assert body["total"] >= 1
            assert "recommendation" not in body["findings"][0]
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_scan_returns_elapsed_ms(self, tmp_path):
        vuln = tmp_path / "clean.py"
        vuln.write_text("x = 42\n", encoding="utf-8")

        server, thread = _start_server(default_target=str(tmp_path))
        port = server.server_address[1]
        base_url = f"http://127.0.0.1:{port}"
        try:
            status, body = _request_json(base_url, {"target": str(tmp_path)})
            assert status == 200
            assert "elapsed_ms" in body
            assert isinstance(body["elapsed_ms"], int)
            assert body["elapsed_ms"] >= 0
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_scan_with_min_severity_filter(self, tmp_path):
        vuln = tmp_path / "app.py"
        vuln.write_text(
            'password = "weak_pass_123"\n'
            '-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----\n',
            encoding="utf-8",
        )

        server, thread = _start_server(default_target=str(tmp_path))
        port = server.server_address[1]
        base_url = f"http://127.0.0.1:{port}"
        try:
            status, body = _request_json(base_url, {
                "target": str(tmp_path),
                "min_severity": "CRITICAL",
            })
            assert status == 200
            for f in body["findings"]:
                assert f["severity"] == "CRITICAL"
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_404_on_unknown_path(self):
        server, thread = _start_server()
        port = server.server_address[1]
        base_url = f"http://127.0.0.1:{port}"
        try:
            status, _ = _get(base_url, "/nonexistent")
            assert status == 404
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_index_html_contains_form_elements(self):
        server, thread = _start_server()
        port = server.server_address[1]
        base_url = f"http://127.0.0.1:{port}"
        try:
            status, html = _get(base_url, "/")
            assert status == 200
            assert 'id="target"' in html
            assert 'id="url"' in html
            assert 'id="severity"' in html
            assert 'id="scan_btn"' in html
            assert 'id="recommendations"' in html
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_clean_project_returns_zero_findings(self, tmp_path):
        clean = tmp_path / "clean.py"
        clean.write_text("def hello():\n    return 'world'\n", encoding="utf-8")

        server, thread = _start_server(default_target=str(tmp_path))
        port = server.server_address[1]
        base_url = f"http://127.0.0.1:{port}"
        try:
            status, body = _request_json(base_url, {"target": str(tmp_path)})
            assert status == 200
            assert body["total"] == 0
            assert body["findings"] == []
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_empty_json_body_uses_default_target(self, tmp_path):
        vuln = tmp_path / "vuln.py"
        vuln.write_text('password = "SuperSecretP@ssw0rd123!"\n', encoding="utf-8")

        server, thread = _start_server(default_target=str(tmp_path))
        port = server.server_address[1]
        base_url = f"http://127.0.0.1:{port}"
        try:
            status, body = _request_json(base_url, {})
            assert status == 200
            assert body["total"] >= 1
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


# ── Demo project scan ─────────────────────────────────────────────────────────

class TestDemoProject:
    """Verify the demo_project is correctly set up for demonstrations."""

    DEMO_DIR = "demo_project"

    def test_demo_project_has_findings(self):
        from scanner.core.scanning import scan_directory
        from pathlib import Path

        demo = Path(__file__).resolve().parents[2] / self.DEMO_DIR
        if not demo.exists():
            pytest.skip("demo_project not found")

        findings = scan_directory(str(demo))
        assert len(findings) > 0, "demo_project should contain at least one secret"

    def test_demo_project_finds_critical_secrets(self):
        from scanner.core.scanning import scan_directory
        from pathlib import Path

        demo = Path(__file__).resolve().parents[2] / self.DEMO_DIR
        if not demo.exists():
            pytest.skip("demo_project not found")

        findings = scan_directory(str(demo))
        severities = {f.severity for f in findings}
        assert "CRITICAL" in severities, "demo_project should have CRITICAL findings"

    def test_demo_project_finds_private_key(self):
        from scanner.core.scanning import scan_directory
        from pathlib import Path

        demo = Path(__file__).resolve().parents[2] / self.DEMO_DIR
        if not demo.exists():
            pytest.skip("demo_project not found")

        findings = scan_directory(str(demo))
        types = {f.secret_type for f in findings}
        assert "Private Key" in types

    def test_demo_project_finds_generic_api_key(self):
        from scanner.core.scanning import scan_directory
        from pathlib import Path

        demo = Path(__file__).resolve().parents[2] / self.DEMO_DIR
        if not demo.exists():
            pytest.skip("demo_project not found")

        findings = scan_directory(str(demo))
        types = {f.secret_type for f in findings}
        assert "Generic API Key" in types or "Generic Secret" in types

    def test_demo_project_finds_jwt(self):
        from scanner.core.scanning import scan_directory
        from pathlib import Path

        demo = Path(__file__).resolve().parents[2] / self.DEMO_DIR
        if not demo.exists():
            pytest.skip("demo_project not found")

        findings = scan_directory(str(demo))
        types = {f.secret_type for f in findings}
        assert "JWT Token" in types

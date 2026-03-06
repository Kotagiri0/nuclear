"""Tests for local web server endpoints."""
from __future__ import annotations

import json
import threading
from http.server import ThreadingHTTPServer
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from scanner.web.app import _Handler


def _start_server(default_target: str = ".") -> tuple[ThreadingHTTPServer, threading.Thread]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.default_target = default_target  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _request_json(base_url: str, payload: dict, method: str = "POST") -> tuple[int, dict]:
    req = Request(
        f"{base_url}/api/scan",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urlopen(req, timeout=30) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_health_and_index_endpoints():
    server, thread = _start_server()
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"
    try:
        with urlopen(f"{base_url}/api/health", timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            assert resp.status == 200
            assert body["status"] == "ok"

        with urlopen(f"{base_url}/", timeout=10) as resp:
            html = resp.read().decode("utf-8")
            assert resp.status == 200
            assert "Nuclear Сканер Секретов" in html
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_scan_request_with_invalid_min_severity_returns_400(tmp_path):
    vuln = tmp_path / "vuln.py"
    vuln.write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")

    server, thread = _start_server(default_target=str(tmp_path))
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"
    try:
        status, body = _request_json(base_url, {"target": str(vuln), "min_severity": "URGENT"})
        assert status == 400
        assert "min_severity" in body["error"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_scan_request_with_invalid_history_commits_returns_400(tmp_path):
    vuln = tmp_path / "vuln.py"
    vuln.write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")

    server, thread = _start_server(default_target=str(tmp_path))
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"
    try:
        status, body = _request_json(base_url, {"target": str(vuln), "history_commits": "not-an-int"})
        assert status == 400
        assert "history_commits" in body["error"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_scan_request_with_invalid_boolean_returns_400(tmp_path):
    vuln = tmp_path / "vuln.py"
    vuln.write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")

    server, thread = _start_server(default_target=str(tmp_path))
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"
    try:
        status, body = _request_json(base_url, {"target": str(vuln), "scan_history": "sometimes"})
        assert status == 400
        assert "scan_history" in body["error"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_scan_request_with_both_target_and_url_returns_400(tmp_path):
    vuln = tmp_path / "vuln.py"
    vuln.write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")

    server, thread = _start_server(default_target=str(tmp_path))
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"
    try:
        status, body = _request_json(
            base_url,
            {"target": str(vuln), "url": "https://github.com/org/repo.git"},
        )
        assert status == 400
        assert "target или url" in body["error"]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def test_scan_request_runs_on_default_target(tmp_path):
    vuln = tmp_path / "vuln.py"
    vuln.write_text("AKIAJX7LKQHMBQWRFP2A\n", encoding="utf-8")

    server, thread = _start_server(default_target=str(tmp_path))
    port = server.server_address[1]
    base_url = f"http://127.0.0.1:{port}"
    try:
        status, body = _request_json(base_url, {"min_severity": "LOW"})
        assert status == 200
        assert body["total"] >= 1
        assert set(body["summary"]) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        assert isinstance(body["findings"], list)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

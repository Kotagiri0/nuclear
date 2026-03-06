from __future__ import annotations

import argparse
import json
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from scanner.core.runner import run_scan
from scanner.output.policy import SEVERITY_ORDER
from scanner.output.recommendations import get_recommendation

MAX_HISTORY_COMMITS = 5000
MAX_BODY_BYTES = 1_000_000
ALLOWED_SEVERITIES = tuple(SEVERITY_ORDER.keys())


def _build_summary(findings: list[Any]) -> dict[str, int]:
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        sev = getattr(finding, "severity", "LOW")
        summary[sev] = summary.get(sev, 0) + 1
    return summary


def _finding_to_dict(finding: Any, include_recommendations: bool) -> dict[str, Any]:
    item: dict[str, Any] = {
        "file": finding.file,
        "line": finding.line_number,
        "type": finding.secret_type,
        "severity": finding.severity,
        "score": finding.score,
        "confidence": finding.confidence,
        "category": finding.category,
        "value": finding.matched_value[:80],
        "line_content": finding.line_content.strip(),
    }
    if include_recommendations:
        rec = get_recommendation(finding.secret_type)
        item["recommendation"] = {
            "title": rec.title,
            "description": rec.description,
            "priority": rec.priority,
        }
    return item


def _normalize_globs(value: Any, field_name: str) -> list[str] | None:
    if value is None:
        return None
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            raise ValueError(f"Поле {field_name} не может быть пустой строкой")
        return [cleaned]
    if isinstance(value, list):
        items: list[str] = []
        for item in value:
            if not isinstance(item, str) or not item.strip():
                raise ValueError(f"Поле {field_name} должно быть строкой или списком непустых строк")
            items.append(item.strip())
        return items
    raise ValueError(f"Поле {field_name} должно быть строкой или списком непустых строк")


def _parse_bool(value: Any, field_name: str, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "on"}:
            return True
        if normalized in {"0", "false", "no", "off", ""}:
            return False
    raise ValueError(f"Поле {field_name} должно быть булевым значением")


def _parse_scan_request(payload: Any, default_target: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("JSON-запрос должен быть объектом")

    target = str(payload.get("target") or "").strip() or None
    url = str(payload.get("url") or "").strip() or None
    min_severity = str(payload.get("min_severity") or "LOW").upper()
    if min_severity not in ALLOWED_SEVERITIES:
        allowed = ", ".join(ALLOWED_SEVERITIES)
        raise ValueError(f"Некорректный min_severity. Допустимые значения: {allowed}")

    raw_history_commits = payload.get("history_commits", 50)
    try:
        history_commits = int(raw_history_commits)
    except (TypeError, ValueError):
        raise ValueError("history_commits должен быть целым числом") from None
    if not (1 <= history_commits <= MAX_HISTORY_COMMITS):
        raise ValueError(f"history_commits должен быть в диапазоне 1..{MAX_HISTORY_COMMITS}")

    scan_history = _parse_bool(payload.get("scan_history"), "scan_history")
    include_recommendations = _parse_bool(payload.get("recommendations"), "recommendations")
    exclude = _normalize_globs(payload.get("exclude"), "exclude")
    include = _normalize_globs(payload.get("include"), "include")

    if not target and not url:
        target = default_target
    if target and url:
        raise ValueError("Укажите только одно: target или url")

    return {
        "target": target,
        "url": url,
        "min_severity": min_severity,
        "scan_history": scan_history,
        "history_commits": history_commits,
        "include_recommendations": include_recommendations,
        "exclude": exclude,
        "include": include,
    }


def _render_index() -> bytes:
    html = """<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Nuclear Сканер Секретов</title>
  <style>
    :root {
      --bg: #f5f7fb;
      --panel: #ffffff;
      --border: #d5ddea;
      --text: #111827;
      --muted: #5b6475;
      --critical: #9f1239;
      --high: #b91c1c;
      --medium: #b45309;
      --low: #1d4ed8;
      --accent: #0f766e;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", "Arial", sans-serif;
      color: var(--text);
      background:
        radial-gradient(1200px 500px at 10% -10%, #dff7f0 0%, transparent 55%),
        radial-gradient(1000px 400px at 90% -20%, #e7eefc 0%, transparent 60%),
        var(--bg);
    }
    .wrap { max-width: 1100px; margin: 24px auto; padding: 0 16px; }
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 16px;
      margin-bottom: 14px;
    }
    h1 { margin: 0 0 12px; font-size: 24px; }
    .muted { color: var(--muted); font-size: 13px; margin-bottom: 14px; }
    #status { margin-bottom: 0; }
    .grid {
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
    }
    .field label {
      font-size: 13px;
      color: var(--muted);
      display: block;
      margin-bottom: 6px;
      font-weight: 600;
    }
    input, select {
      width: 100%;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px 10px;
      background: #fff;
      color: var(--text);
    }
    .checks {
      display: flex;
      gap: 16px;
      align-items: center;
      flex-wrap: wrap;
      margin-top: 10px;
    }
    .check-item {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 7px 12px;
      background: #f8fafc;
    }
    .check-item input {
      width: auto;
      margin: 0;
    }
    .check-item label {
      margin: 0;
      color: var(--text);
      font-size: 14px;
      font-weight: 500;
      user-select: none;
      cursor: pointer;
    }
    .actions {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-top: 14px;
      min-height: 40px;
    }
    button {
      border: none;
      border-radius: 8px;
      background: var(--accent);
      color: #fff;
      padding: 10px 14px;
      font-weight: 600;
      cursor: pointer;
    }
    button:hover { filter: brightness(0.95); }
    button:disabled { opacity: 0.6; cursor: wait; }
    .cards {
      display: grid;
      grid-template-columns: repeat(4, minmax(130px, 1fr));
      gap: 10px;
      margin-top: 12px;
    }
    .card {
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 10px;
      background: #fff;
    }
    .sev-critical { color: var(--critical); font-weight: 700; }
    .sev-high { color: var(--high); font-weight: 700; }
    .sev-medium { color: var(--medium); font-weight: 700; }
    .sev-low { color: var(--low); font-weight: 700; }
    table { width: 100%; border-collapse: collapse; font-size: 13px; }
    th, td { text-align: left; border-bottom: 1px solid var(--border); padding: 8px 6px; vertical-align: top; }
    th { background: #f8fafc; position: sticky; top: 0; }
    .scroll { overflow: auto; max-height: 58vh; }
    .err { color: #b91c1c; white-space: pre-wrap; }
    @media (max-width: 760px) {
      .cards { grid-template-columns: repeat(2, minmax(130px, 1fr)); }
      table { font-size: 12px; }
      .actions { align-items: flex-start; flex-direction: column; }
      .checks { gap: 10px; }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <div class="panel">
      <h1>Nuclear Сканер Секретов</h1>
      <div class="muted">Локальный детерминированный сканер. Без облачных вызовов. В отчёте: файл, строка, тип секрета и уровень риска.</div>
      <div class="grid">
        <div class="field">
          <label>Путь до цели (файл/папка/zip)</label>
          <input id="target" placeholder="." value="." />
        </div>
        <div class="field">
          <label>URL цели (необязательно)</label>
          <input id="url" placeholder="https://github.com/org/repo.git" />
        </div>
        <div class="field">
          <label>Минимальная критичность</label>
          <select id="severity">
            <option>LOW</option>
            <option>MEDIUM</option>
            <option>HIGH</option>
            <option>CRITICAL</option>
          </select>
        </div>
        <div class="field">
          <label>Коммитов из истории Git</label>
          <input id="history_commits" type="number" min="1" max="5000" value="50" />
        </div>
      </div>
      <div class="checks">
        <div class="check-item">
          <input id="scan_history" type="checkbox" />
          <label for="scan_history">Сканировать историю Git</label>
        </div>
        <div class="check-item">
          <input id="recommendations" type="checkbox" />
          <label for="recommendations">Добавить рекомендации</label>
        </div>
      </div>
      <div class="actions">
        <button id="scan_btn" onclick="startScan()">Запустить сканирование</button>
        <div id="status" class="muted"></div>
      </div>
    </div>

    <div class="panel">
      <div id="summary" class="muted">Сканирование ещё не запускалось.</div>
      <div class="cards">
        <div class="card"><div>CRITICAL</div><div id="c_critical" class="sev-critical">0</div></div>
        <div class="card"><div>HIGH</div><div id="c_high" class="sev-high">0</div></div>
        <div class="card"><div>MEDIUM</div><div id="c_medium" class="sev-medium">0</div></div>
        <div class="card"><div>LOW</div><div id="c_low" class="sev-low">0</div></div>
      </div>
    </div>

    <div class="panel">
      <div class="scroll">
        <table>
          <thead>
            <tr>
              <th>Критичность</th>
              <th>Тип</th>
              <th>Локация</th>
              <th>Значение</th>
              <th>Оценка</th>
              <th>Уверенность</th>
            </tr>
          </thead>
          <tbody id="rows"></tbody>
        </table>
      </div>
      <div id="err" class="err"></div>
    </div>
  </div>

  <script>
    function escapeHtml(s) {
      return String(s)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;");
    }

    function sevClass(sev) {
      if (sev === "CRITICAL") return "sev-critical";
      if (sev === "HIGH") return "sev-high";
      if (sev === "MEDIUM") return "sev-medium";
      return "sev-low";
    }

    async function startScan() {
      const btn = document.getElementById("scan_btn");
      const status = document.getElementById("status");
      const err = document.getElementById("err");
      err.textContent = "";
      btn.disabled = true;
      status.textContent = "Сканирование...";

      const payload = {
        target: document.getElementById("target").value.trim(),
        url: document.getElementById("url").value.trim(),
        min_severity: document.getElementById("severity").value,
        scan_history: document.getElementById("scan_history").checked,
        history_commits: Number(document.getElementById("history_commits").value || "50"),
        recommendations: document.getElementById("recommendations").checked
      };

      try {
        const res = await fetch("/api/scan", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (!res.ok) {
          throw new Error(data.error || ("Ошибка HTTP " + res.status));
        }
        renderResult(data);
      } catch (e) {
        err.textContent = String(e);
      } finally {
        status.textContent = "";
        btn.disabled = false;
      }
    }

    function renderResult(data) {
      const rows = document.getElementById("rows");
      rows.innerHTML = "";

      document.getElementById("summary").textContent =
        "Найдено: " + data.total + " | Время сканирования: " + data.elapsed_ms + " мс";
      document.getElementById("c_critical").textContent = data.summary.CRITICAL || 0;
      document.getElementById("c_high").textContent = data.summary.HIGH || 0;
      document.getElementById("c_medium").textContent = data.summary.MEDIUM || 0;
      document.getElementById("c_low").textContent = data.summary.LOW || 0;

      for (const f of data.findings) {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td class="${sevClass(f.severity)}">${escapeHtml(f.severity)}</td>
          <td>${escapeHtml(f.type)}</td>
          <td>${escapeHtml(f.file)}:${f.line}</td>
          <td>${escapeHtml(f.value)}</td>
          <td>${f.score}</td>
          <td>${f.confidence}</td>
        `;
        rows.appendChild(tr);
      }
    }
  </script>
</body>
</html>"""
    return html.encode("utf-8")


class _Handler(BaseHTTPRequestHandler):
    server_version = "NuclearWeb/0.1"

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path in {"/", "/index.html"}:
            body = _render_index()
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/api/health":
            self._json(HTTPStatus.OK, {"status": "ok"})
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "Не найдено"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/api/scan":
            self._json(HTTPStatus.NOT_FOUND, {"error": "Не найдено"})
            return

        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length < 0:
                raise ValueError
            if length > MAX_BODY_BYTES:
                self._json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "Слишком большой JSON-запрос"})
                return
            raw = self.rfile.read(length) if length > 0 else b"{}"
            payload = json.loads(raw.decode("utf-8"))
        except (ValueError, json.JSONDecodeError):
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Некорректный JSON в запросе"})
            return

        try:
            params = _parse_scan_request(payload, getattr(self.server, "default_target", "."))
        except ValueError as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        try:
            started = time.monotonic()
            findings = run_scan(
                target=params["target"],
                url=params["url"],
                min_severity=params["min_severity"],
                scan_history=params["scan_history"],
                history_commits=params["history_commits"],
                exclude=params["exclude"],
                include=params["include"],
            )
            elapsed_ms = int((time.monotonic() - started) * 1000)
        except Exception as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        findings.sort(key=lambda finding: (-finding.score, finding.file, finding.line_number))
        serialized = [_finding_to_dict(finding, params["include_recommendations"]) for finding in findings]
        self._json(
            HTTPStatus.OK,
            {
                "total": len(serialized),
                "summary": _build_summary(findings),
                "elapsed_ms": elapsed_ms,
                "findings": serialized,
            },
        )

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Запуск локального веб-интерфейса Nuclear Secret Scanner")
    parser.add_argument("--host", default="127.0.0.1", help="Хост (по умолчанию: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8765, help="Порт (по умолчанию: 8765)")
    parser.add_argument("--target", default=".", help="Цель по умолчанию для сканирования")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    server = ThreadingHTTPServer((args.host, args.port), _Handler)
    server.default_target = args.target  # type: ignore[attr-defined]
    print(f"Nuclear веб-интерфейс: http://{args.host}:{args.port}")
    print("Нажмите Ctrl+C для остановки.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

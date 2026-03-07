from __future__ import annotations

import argparse
import json
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from typing import Any
from urllib.parse import parse_qs, urlsplit

from scanner.core.runner import run_scan
from scanner.output.html_report import generate_html_report
from scanner.output.policy import SEVERITY_ORDER
from scanner.output.pdf_report import generate_pdf_report
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


def _is_ai_finding(finding: Any) -> bool:
    return (
        getattr(finding, "secret_type", None) == "AI Security"
        or getattr(finding, "category", None) == "ai_security"
        or (getattr(finding, "source", None) and str(finding.source).startswith("ai:"))
    )


def _finding_to_dict(finding: Any, include_recommendations: bool) -> dict[str, Any]:
    is_ai = _is_ai_finding(finding)
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
        "ai_detection": is_ai,
        "detector": "llm" if is_ai else "patterns",
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
    ai_security = _parse_bool(payload.get("ai_security"), "ai_security")
    exclude = _normalize_globs(payload.get("exclude"), "exclude")
    include = _normalize_globs(payload.get("include"), "include")

    if target and url:
        # Web UI keeps the default target pre-filled. If URL is explicitly set and
        # target equals that default value, prefer URL instead of raising a conflict.
        default_target_normalized = str(default_target).strip()
        if target in {".", "./"}:
            target = None
        elif default_target_normalized and target == default_target_normalized:
            target = None
        else:
            raise ValueError("Укажите только одно: target или url")
    if not target and not url:
        target = default_target

    return {
        "target": target,
        "url": url,
        "min_severity": min_severity,
        "scan_history": scan_history,
        "history_commits": history_commits,
        "include_recommendations": include_recommendations,
        "ai_security": ai_security,
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
      --bg-base: #f3f6ff;
      --bg-spot-a: #daf4eb;
      --bg-spot-b: #dce8ff;
      --panel: rgba(255, 255, 255, 0.88);
      --panel-strong: #ffffff;
      --border: #d1dced;
      --text: #0f172a;
      --muted: #5a667a;
      --accent: #0f766e;
      --accent-strong: #115e59;
      --critical: #b42318;
      --critical-bg: #fee4e2;
      --high: #d97706;
      --high-bg: #ffedd5;
      --medium: #b45309;
      --medium-bg: #fef3c7;
      --low: #1d4ed8;
      --low-bg: #dbeafe;
      --shadow: 0 16px 38px rgba(15, 23, 42, 0.12);
    }
    * {
      box-sizing: border-box;
    }
    body {
      margin: 0;
      min-height: 100vh;
      font-family: "Bahnschrift", "Trebuchet MS", "Segoe UI Variable", sans-serif;
      color: var(--text);
      background:
        radial-gradient(1200px 620px at 6% -18%, var(--bg-spot-a) 0%, rgba(218, 244, 235, 0) 62%),
        radial-gradient(980px 520px at 94% -22%, var(--bg-spot-b) 0%, rgba(220, 232, 255, 0) 58%),
        var(--bg-base);
      letter-spacing: 0.01em;
    }
    body::before {
      content: "";
      position: fixed;
      inset: 0;
      pointer-events: none;
      opacity: 0.24;
      background-image:
        linear-gradient(110deg, rgba(15, 118, 110, 0.06), transparent 26%),
        repeating-linear-gradient(
          0deg,
          rgba(15, 23, 42, 0.05) 0,
          rgba(15, 23, 42, 0.05) 1px,
          transparent 1px,
          transparent 11px
        );
    }
    .wrap {
      position: relative;
      z-index: 1;
      max-width: 1160px;
      margin: 30px auto 48px;
      padding: 0 18px;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 18px;
      padding: 18px;
      margin-bottom: 14px;
      box-shadow: var(--shadow);
      backdrop-filter: blur(5px);
      animation: panel-in 0.48s ease both;
    }
    .panel:nth-of-type(2) {
      animation-delay: 0.08s;
    }
    .panel:nth-of-type(3) {
      animation-delay: 0.16s;
    }
    .panel:nth-of-type(4) {
      animation-delay: 0.24s;
    }
    .hero {
      display: grid;
      gap: 18px;
      grid-template-columns: 1.3fr 1fr;
      overflow: hidden;
      position: relative;
      background:
        linear-gradient(130deg, rgba(16, 84, 121, 0.08), rgba(15, 118, 110, 0.04)),
        var(--panel-strong);
    }
    .hero::after {
      content: "";
      position: absolute;
      width: 420px;
      height: 420px;
      right: -180px;
      top: -230px;
      border-radius: 999px;
      background: radial-gradient(circle, rgba(15, 118, 110, 0.18), rgba(15, 118, 110, 0));
    }
    .eyebrow {
      display: inline-block;
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.16em;
      color: #0f4c6a;
      background: #dff4ff;
      border: 1px solid #bdd8ea;
      border-radius: 999px;
      padding: 6px 11px;
      margin-bottom: 10px;
    }
    h1 {
      margin: 0 0 8px;
      font-size: clamp(1.6rem, 3vw, 2.2rem);
      line-height: 1.18;
      max-width: 20ch;
    }
    .lead {
      margin: 0;
      color: var(--muted);
      font-size: 0.96rem;
      line-height: 1.42;
      max-width: 58ch;
    }
    .hero-metrics {
      display: grid;
      gap: 10px;
      align-content: center;
      justify-items: end;
      position: relative;
      z-index: 2;
    }
    .hero-chip {
      width: min(100%, 280px);
      border: 1px solid #cfe0f3;
      border-radius: 12px;
      padding: 12px 14px;
      background: #f8fbff;
    }
    .hero-chip span {
      display: block;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.09em;
      color: #61738a;
      margin-bottom: 3px;
    }
    .hero-chip strong {
      display: block;
      font-size: 14px;
      font-weight: 700;
      color: #11243b;
    }
    .muted {
      color: var(--muted);
      font-size: 13px;
      margin: 0;
    }
    .grid {
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(2, minmax(220px, 1fr));
    }
    .field label {
      display: block;
      margin-bottom: 7px;
      color: #46556d;
      font-size: 12px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.06em;
    }
    input,
    select {
      width: 100%;
      border: 1px solid #cdd9eb;
      border-radius: 11px;
      padding: 11px 12px;
      background: #ffffff;
      color: var(--text);
      font-family: inherit;
      font-size: 14px;
      transition: border-color 0.16s ease, box-shadow 0.16s ease, transform 0.16s ease;
    }
    input:focus,
    select:focus {
      border-color: #0e7490;
      outline: none;
      box-shadow: 0 0 0 3px rgba(14, 116, 144, 0.15);
      transform: translateY(-1px);
    }
    .checks {
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 12px;
    }
    .check-item {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      border: 1px solid #cad8e7;
      border-radius: 999px;
      padding: 8px 12px;
      background: #f8fbff;
      color: #1f2f46;
      cursor: pointer;
      user-select: none;
      transition: border-color 0.16s ease, transform 0.16s ease;
    }
    .check-item:hover {
      border-color: #8eb8da;
      transform: translateY(-1px);
    }
    .check-item input {
      width: auto;
      margin: 0;
    }
    .actions {
      display: flex;
      align-items: center;
      gap: 12px;
      margin-top: 14px;
      min-height: 42px;
    }
    button {
      border: 0;
      border-radius: 11px;
      background: linear-gradient(135deg, var(--accent), var(--accent-strong));
      color: #ffffff;
      padding: 11px 16px;
      font-weight: 700;
      font-size: 14px;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      letter-spacing: 0.01em;
      box-shadow: 0 10px 18px rgba(15, 118, 110, 0.26);
      transition: transform 0.16s ease, box-shadow 0.16s ease, filter 0.16s ease;
    }
    button:hover {
      transform: translateY(-1px);
      box-shadow: 0 12px 22px rgba(15, 118, 110, 0.3);
    }
    button:active {
      transform: translateY(0);
    }
    .button-secondary {
      background: #ffffff;
      color: #155e75;
      border: 1px solid #b7d2ea;
      box-shadow: none;
    }
    .button-secondary:hover {
      box-shadow: none;
      background: #f5fbff;
      border-color: #7fb7da;
    }
    .button-secondary:disabled {
      cursor: not-allowed;
      opacity: 0.55;
      background: #f8fbff;
      color: #8aa0b7;
      border-color: #d5dfeb;
    }
    button:disabled {
      opacity: 0.8;
      cursor: wait;
      filter: saturate(0.7);
    }
    .btn-loader {
      width: 14px;
      height: 14px;
      border: 2px solid rgba(255, 255, 255, 0.55);
      border-top-color: #ffffff;
      border-radius: 999px;
      display: none;
      animation: spin 0.65s linear infinite;
    }
    body.is-loading .btn-loader {
      display: inline-block;
    }
    .status.busy::before {
      content: "";
      display: inline-block;
      width: 8px;
      height: 8px;
      border-radius: 999px;
      background: #0e7490;
      margin-right: 7px;
      animation: pulse 0.9s ease-in-out infinite;
      vertical-align: middle;
    }
    .summary-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
    }
    .cards {
      display: grid;
      grid-template-columns: repeat(4, minmax(110px, 1fr));
      gap: 10px;
      margin-top: 12px;
    }
    .card {
      border-radius: 14px;
      border: 1px solid #d0dded;
      padding: 12px;
      background: #ffffff;
      min-height: 90px;
      display: flex;
      flex-direction: column;
      justify-content: center;
      gap: 6px;
    }
    .card-title {
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.1em;
      color: #6d7f96;
      font-weight: 700;
    }
    .card-value {
      font-size: 1.8rem;
      line-height: 1;
      font-weight: 800;
      font-family: "Consolas", "Lucida Console", monospace;
    }
    .sev-critical {
      color: var(--critical);
    }
    .sev-high {
      color: var(--high);
    }
    .sev-medium {
      color: var(--medium);
    }
    .sev-low {
      color: var(--low);
    }
    .results-head {
      margin-bottom: 10px;
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.11em;
      font-weight: 700;
      color: #6f8197;
    }
    .scroll {
      overflow: auto;
      max-height: 58vh;
      border: 1px solid #d4dfed;
      border-radius: 12px;
      background: #ffffff;
    }
    table {
      width: 100%;
      border-collapse: collapse;
      min-width: 760px;
      font-size: 13px;
    }
    th,
    td {
      text-align: left;
      padding: 10px 9px;
      border-bottom: 1px solid #e7edf6;
      vertical-align: top;
    }
    th {
      position: sticky;
      top: 0;
      background: #f7fbff;
      z-index: 1;
      font-size: 11px;
      letter-spacing: 0.1em;
      text-transform: uppercase;
      color: #5e6f86;
    }
    tbody tr:hover {
      background: #f8fbff;
    }
    .sev-badge {
      display: inline-block;
      min-width: 88px;
      text-align: center;
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 11px;
      font-weight: 800;
      letter-spacing: 0.06em;
    }
    .sev-badge.sev-critical {
      background: var(--critical-bg);
      color: var(--critical);
    }
    .sev-badge.sev-high {
      background: var(--high-bg);
      color: var(--high);
    }
    .sev-badge.sev-medium {
      background: var(--medium-bg);
      color: var(--medium);
    }
    .sev-badge.sev-low {
      background: var(--low-bg);
      color: var(--low);
    }
    .cell-file {
      font-family: "Consolas", "Lucida Console", monospace;
      color: #1a2e4a;
      word-break: break-word;
    }
    .cell-value {
      font-family: "Consolas", "Lucida Console", monospace;
      color: #2d3748;
      max-width: 280px;
      overflow-wrap: anywhere;
    }
    .empty-row td {
      text-align: center;
      color: #64748b;
      padding: 18px 10px;
    }
    .err {
      margin-top: 10px;
      padding: 9px 10px;
      border-radius: 10px;
      border: 1px solid #fecaca;
      background: #fff5f5;
      color: #b42318;
      white-space: pre-wrap;
      display: none;
    }
    .err.has-error {
      display: block;
    }
    @keyframes spin {
      to {
        transform: rotate(360deg);
      }
    }
    @keyframes pulse {
      0%,
      100% {
        opacity: 0.6;
      }
      50% {
        opacity: 1;
      }
    }
    @keyframes panel-in {
      from {
        opacity: 0;
        transform: translateY(14px);
      }
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }
    @media (max-width: 920px) {
      .hero {
        grid-template-columns: 1fr;
      }
      .hero-metrics {
        justify-items: start;
      }
      .grid {
        grid-template-columns: 1fr;
      }
      .cards {
        grid-template-columns: repeat(2, minmax(120px, 1fr));
      }
      .actions {
        flex-direction: column;
        align-items: flex-start;
      }
      .wrap {
        margin-top: 18px;
      }
    }
    @media (max-width: 520px) {
      body {
        font-size: 14px;
      }
      .panel {
        border-radius: 14px;
        padding: 14px;
      }
      .cards {
        grid-template-columns: 1fr 1fr;
      }
    }
  </style>
</head>
<body>
  <div class="wrap">
    <header class="panel hero">
      <div>
        <span class="eyebrow">Локальный аудит безопасности</span>
        <h1>Nuclear Сканер Секретов</h1>
        <p class="lead">Детерминированное локальное сканирование секретов без облачных вызовов. Отчет показывает уровень риска, тип секрета и точную локацию в коде.</p>
      </div>
      <div class="hero-metrics">
        <div class="hero-chip">
          <span>Эндпоинт</span>
          <strong>/api/scan</strong>
        </div>
        <div class="hero-chip">
          <span>Источник</span>
          <strong>Папка, файл, zip или git URL</strong>
        </div>
        <div class="hero-chip">
          <span>Git-история</span>
          <strong>До 5000 коммитов за запуск</strong>
        </div>
      </div>
    </header>

    <section class="panel">
      <div class="grid">
        <div class="field">
          <label for="target">Путь к цели (файл/папка/zip)</label>
          <input id="target" placeholder="." value="." />
        </div>
        <div class="field">
          <label for="url">URL цели (необязательно)</label>
          <input id="url" placeholder="https://github.com/org/repo.git" />
        </div>
        <div class="field">
          <label for="severity">Минимальная критичность</label>
          <select id="severity">
            <option>LOW</option>
            <option>MEDIUM</option>
            <option>HIGH</option>
            <option>CRITICAL</option>
          </select>
        </div>
        <div class="field">
          <label for="history_commits">Коммитов из истории Git</label>
          <input id="history_commits" type="number" min="1" max="5000" value="50" />
        </div>
      </div>

      <div class="checks">
        <label class="check-item" for="scan_history">
          <input id="scan_history" type="checkbox" />
          <span>Сканировать историю Git</span>
        </label>
        <label class="check-item" for="recommendations">
          <input id="recommendations" type="checkbox" />
          <span>Добавить рекомендации</span>
        </label>
        <label class="check-item" for="ai_security">
          <input id="ai_security" type="checkbox" />
          <span>Сканировать с LLM (требует NUCLEAR_NVIDIA_API_KEY в .env)</span>
        </label>
      </div>

      <div class="actions">
        <button id="scan_btn" onclick="startScan()">
          <span>Запустить сканирование</span>
          <span class="btn-loader" aria-hidden="true"></span>
        </button>
        <button id="export_html_btn" class="button-secondary" onclick="exportResult('html')" disabled>
          <span>Экспорт в HTML</span>
        </button>
        <button id="export_pdf_btn" class="button-secondary" onclick="exportResult('pdf')" disabled>
          <span>Экспорт в PDF</span>
        </button>
        <p id="status" class="status muted"></p>
      </div>
    </section>

    <section class="panel">
      <div class="summary-head">
        <p id="summary" class="muted">Сканирование еще не запускалось.</p>
      </div>
      <div class="cards">
        <div class="card">
          <div class="card-title">Критический</div>
          <div id="c_critical" class="card-value sev-critical">0</div>
        </div>
        <div class="card">
          <div class="card-title">Высокий</div>
          <div id="c_high" class="card-value sev-high">0</div>
        </div>
        <div class="card">
          <div class="card-title">Средний</div>
          <div id="c_medium" class="card-value sev-medium">0</div>
        </div>
        <div class="card">
          <div class="card-title">Низкий</div>
          <div id="c_low" class="card-value sev-low">0</div>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="results-head">Найденные совпадения</div>
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
    </section>
  </div>

  <script>
    function escapeHtml(s) {
      return String(s)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;");
    }

    function sevClass(sev) {
      if (sev === "CRITICAL") return "sev-critical";
      if (sev === "HIGH") return "sev-high";
      if (sev === "MEDIUM") return "sev-medium";
      return "sev-low";
    }

    function setLoading(isLoading) {
      const btn = document.getElementById("scan_btn");
      const status = document.getElementById("status");
      btn.disabled = isLoading;
      document.body.classList.toggle("is-loading", isLoading);
      if (isLoading) {
        status.classList.add("busy");
        status.textContent = "Сканирование запущено...";
      } else {
        status.classList.remove("busy");
        status.textContent = "";
      }
    }

    function syncHistoryState() {
      const historyToggle = document.getElementById("scan_history");
      const commitsInput = document.getElementById("history_commits");
      commitsInput.disabled = !historyToggle.checked;
      commitsInput.style.opacity = historyToggle.checked ? "1" : "0.6";
    }

    function setExportEnabled(enabled) {
      document.getElementById("export_html_btn").disabled = !enabled;
      document.getElementById("export_pdf_btn").disabled = !enabled;
    }

    async function exportResult(format) {
      const err = document.getElementById("err");
      err.textContent = "";
      err.classList.remove("has-error");

      try {
        const res = await fetch("/api/export?format=" + encodeURIComponent(format), {
          method: "GET"
        });

        if (!res.ok) {
          let payload = null;
          try {
            payload = await res.json();
          } catch (_ignored) {
            payload = null;
          }
          throw new Error((payload && payload.error) || ("Ошибка HTTP " + res.status));
        }

        const blob = await res.blob();
        const contentDisposition = res.headers.get("Content-Disposition") || "";
        const match = contentDisposition.match(/filename="?([^\";]+)"?/i);
        const filename = match ? match[1] : ("nuclear-scan-report." + format);
        const link = document.createElement("a");
        const downloadUrl = URL.createObjectURL(blob);
        link.href = downloadUrl;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        link.remove();
        URL.revokeObjectURL(downloadUrl);
      } catch (e) {
        err.textContent = String(e);
        err.classList.add("has-error");
      }
    }

    async function startScan() {
      const err = document.getElementById("err");
      err.textContent = "";
      err.classList.remove("has-error");
      setLoading(true);

      const targetValue = document.getElementById("target").value.trim();
      const urlValue = document.getElementById("url").value.trim();
      const payload = {
        target: urlValue ? "" : targetValue,
        url: urlValue,
        min_severity: document.getElementById("severity").value,
        scan_history: document.getElementById("scan_history").checked,
        history_commits: Number(document.getElementById("history_commits").value || "50"),
        recommendations: document.getElementById("recommendations").checked,
        ai_security: document.getElementById("ai_security").checked
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
        err.classList.add("has-error");
      } finally {
        setLoading(false);
      }
    }

    function renderResult(data) {
      const rows = document.getElementById("rows");
      rows.innerHTML = "";
      setExportEnabled(true);

      let summaryText = "Найдено: " + data.total + " | Время сканирования: " + data.elapsed_ms + " мс";
      if ((data.ai_findings || 0) > 0) {
        summaryText += " | 🤖 LLM: " + data.ai_findings;
      }
      document.getElementById("summary").textContent = summaryText;
      document.getElementById("c_critical").textContent = data.summary.CRITICAL || 0;
      document.getElementById("c_high").textContent = data.summary.HIGH || 0;
      document.getElementById("c_medium").textContent = data.summary.MEDIUM || 0;
      document.getElementById("c_low").textContent = data.summary.LOW || 0;

      if (!Array.isArray(data.findings) || data.findings.length === 0) {
        const empty = document.createElement("tr");
        empty.className = "empty-row";
        empty.innerHTML = "<td colspan='6'>Совпадений не найдено для выбранных параметров.</td>";
        rows.appendChild(empty);
        return;
      }

      for (const f of data.findings) {
        const tr = document.createElement("tr");
        const score = Number.isFinite(Number(f.score)) ? Number(f.score).toFixed(1) : escapeHtml(f.score);
        const confidence = Number.isFinite(Number(f.confidence))
          ? Number(f.confidence).toFixed(2)
          : escapeHtml(f.confidence);

        const mlTag = f.ai_detection ? ' <span title="ML/LLM detection">🤖 ML</span>' : '';
        tr.innerHTML = `
          <td><span class="sev-badge ${sevClass(f.severity)}">${escapeHtml(f.severity)}</span></td>
          <td>${escapeHtml(f.type)}${mlTag}</td>
          <td class="cell-file">${escapeHtml(f.file)}:${f.line}</td>
          <td class="cell-value">${escapeHtml(f.value)}</td>
          <td>${score}</td>
          <td>${confidence}</td>
        `;
        rows.appendChild(tr);
      }
    }

    document.getElementById("scan_history").addEventListener("change", syncHistoryState);
    syncHistoryState();
    setExportEnabled(false);
  </script>
</body>
</html>"""
    return html.encode("utf-8")


class _Handler(BaseHTTPRequestHandler):
    server_version = "NuclearWeb/0.1"

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._write_body(status, body, "application/json; charset=utf-8")

    def _write_body(
        self,
        status: int,
        body: bytes,
        content_type: str,
        *,
        content_disposition: str | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if content_disposition:
            self.send_header("Content-Disposition", content_disposition)
        self.end_headers()
        self.wfile.write(body)

    def _set_latest_scan(self, findings: list[Any], target: str) -> None:
        payload = {"findings": list(findings), "target": target}
        lock = getattr(self.server, "latest_scan_lock", None)
        if lock is None:
            self.server.latest_scan = payload  # type: ignore[attr-defined]
            return
        with lock:
            self.server.latest_scan = payload  # type: ignore[attr-defined]

    def _get_latest_scan(self) -> dict[str, Any] | None:
        lock = getattr(self.server, "latest_scan_lock", None)
        if lock is None:
            return getattr(self.server, "latest_scan", None)
        with lock:
            return getattr(self.server, "latest_scan", None)

    def _handle_export(self, query: str) -> None:
        params = parse_qs(query)
        export_format = str(params.get("format", [""])[0]).strip().lower()
        if export_format not in {"html", "pdf"}:
            self._json(HTTPStatus.BAD_REQUEST, {"error": "Поддерживаемые форматы: html, pdf"})
            return

        latest_scan = self._get_latest_scan()
        if not latest_scan:
            self._json(HTTPStatus.CONFLICT, {"error": "Сначала запустите сканирование"})
            return

        findings = latest_scan.get("findings", [])
        target = str(latest_scan.get("target", ""))
        if export_format == "html":
            body = generate_html_report(findings, target=target).encode("utf-8")
            content_type = "text/html; charset=utf-8"
            filename = "nuclear-scan-report.html"
        else:
            body = generate_pdf_report(findings, target=target)
            content_type = "application/pdf"
            filename = "nuclear-scan-report.pdf"

        self._write_body(
            HTTPStatus.OK,
            body,
            content_type,
            content_disposition=f'attachment; filename="{filename}"',
        )

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        path = parsed.path
        if path in {"/", "/index.html"}:
            body = _render_index()
            self._write_body(HTTPStatus.OK, body, "text/html; charset=utf-8")
            return
        if path == "/api/health":
            self._json(HTTPStatus.OK, {"status": "ok"})
            return
        if path == "/api/export":
            self._handle_export(parsed.query)
            return
        self._json(HTTPStatus.NOT_FOUND, {"error": "Не найдено"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path != "/api/scan":
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
            ai_security_cfg = None
            if params.get("ai_security"):
                from scanner.ai.security import AISecurityConfig

                ai_security_cfg = AISecurityConfig(max_files=30)

            started = time.monotonic()
            findings = run_scan(
                target=params["target"],
                url=params["url"],
                min_severity=params["min_severity"],
                scan_history=params["scan_history"],
                history_commits=params["history_commits"],
                ai_security_cfg=ai_security_cfg,
                exclude=params["exclude"],
                include=params["include"],
            )
            elapsed_ms = int((time.monotonic() - started) * 1000)
        except Exception as exc:
            self._json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
            return

        findings.sort(key=lambda finding: (-finding.score, finding.file, finding.line_number))
        export_target = params["target"] or params["url"] or getattr(self.server, "default_target", ".")
        self._set_latest_scan(findings, str(export_target))
        serialized = [_finding_to_dict(finding, params["include_recommendations"]) for finding in findings]
        ai_count = sum(1 for f in findings if _is_ai_finding(f))
        self._json(
            HTTPStatus.OK,
            {
                "total": len(serialized),
                "summary": _build_summary(findings),
                "ai_findings": ai_count,
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
    # Load local .env (if present) so AI/API keys can be provided without exporting.
    try:
        from scanner.config import load_dotenv

        load_dotenv()
    except Exception:
        pass
    args = build_parser().parse_args()
    server = ThreadingHTTPServer((args.host, args.port), _Handler)
    server.default_target = args.target  # type: ignore[attr-defined]
    server.latest_scan = None  # type: ignore[attr-defined]
    server.latest_scan_lock = Lock()  # type: ignore[attr-defined]
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

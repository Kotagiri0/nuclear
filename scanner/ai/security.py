from __future__ import annotations

import os
import re
from dataclasses import dataclass

from scanner.core.analysis import Finding


class AISecurityError(RuntimeError):
    pass


_THREAT_TO_SEVERITY = {
    # RU
    "КРИТИЧЕСКАЯ": "CRITICAL",
    "ВЫСОКАЯ": "HIGH",
    "СРЕДНЯЯ": "MEDIUM",
    "НИЗКАЯ": "LOW",
    "БЕЗОПАСНО": "SAFE",
    # EN (fallback)
    "CRITICAL": "CRITICAL",
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "SAFE": "SAFE",
}

_SEVERITY_TO_SCORE = {
    "LOW": 3,
    "MEDIUM": 6,
    "HIGH": 9,
    "CRITICAL": 13,
}


@dataclass(frozen=True)
class AISecurityConfig:
    provider: str = "nvidia"
    base_url: str = "https://integrate.api.nvidia.com/v1"
    api_key_env: str = "NUCLEAR_NVIDIA_API_KEY"
    model: str | None = None
    temperature: float = 0.1
    max_tokens: int = 500
    timeout_s: int = 30
    max_bytes: int = 50_000
    # Performance controls
    scan_all_files: bool = False
    max_files: int = 50  # 0 = unlimited


DEFAULT_SYSTEM_PROMPT = (
    "Ты — лаконичный сканер безопасности кода. Твой ответ должен содержать ТОЛЬКО строки в формате: "
    "[УРОВЕНЬ УГРОЗЫ] - L<номер>: <строчка кода>. "
    "Уровни: КРИТИЧЕСКАЯ, ВЫСОКАЯ, СРЕДНЯЯ, НИЗКАЯ. "
    "Если строка безопасна, не упоминай её. Если весь код чист, пиши [БЕЗОПАСНО]. "
    "Не добавляй пояснений, заголовков и списков."
)


_LNUM_RE = re.compile(r"^\s*L(?P<lineno>\d+)\s*:\s*(?P<text>.*)\s*$")


def _get_api_key(cfg: AISecurityConfig) -> str:
    key = os.environ.get(cfg.api_key_env) or os.environ.get("NVIDIA_API_KEY") or os.environ.get("NUCLEAR_AI_API_KEY")
    if not key:
        raise AISecurityError(
            "AI security scan is enabled, but API key is missing. "
            f"Set {cfg.api_key_env} (recommended) or NVIDIA_API_KEY / NUCLEAR_AI_API_KEY."
        )
    return key


def _make_client(cfg: AISecurityConfig):
    try:
        from openai import OpenAI  # type: ignore
    except Exception as exc:  # noqa: BLE001
        raise AISecurityError(
            "AI security scan requires optional dependency 'openai'. "
            "Install it via: pip install 'nuclear-secret-scanner[ai]'"
        ) from exc

    return OpenAI(base_url=cfg.base_url, api_key=_get_api_key(cfg), timeout=cfg.timeout_s)


_CACHED_MODEL: str | None = None


def _pick_model(client, explicit_model: str | None) -> str:
    global _CACHED_MODEL
    if explicit_model:
        return explicit_model
    if _CACHED_MODEL:
        return _CACHED_MODEL

    try:
        available = client.models.list()
        ids = [m.id for m in getattr(available, "data", []) if "qwen" in getattr(m, "id", "").lower()]
        if not ids:
            raise AISecurityError("No Qwen models found for this NVIDIA account.")
        for mid in ids:
            if "122b" in mid.lower():
                _CACHED_MODEL = mid
                return mid
        _CACHED_MODEL = ids[0]
        return ids[0]
    except AISecurityError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AISecurityError(f"Could not list NVIDIA models: {exc}") from exc


def _normalize_threat(raw: str) -> str | None:
    t = raw.strip().upper()
    return _THREAT_TO_SEVERITY.get(t)


def _with_line_numbers(code_text: str) -> str:
    lines = code_text.splitlines()
    return "\n".join(f"L{i + 1}: {line}" for i, line in enumerate(lines))


_RISK_MARKERS = [
    # Code execution / shell
    r"\bos\.system\s*\(",
    r"\bsubprocess\.(run|call|Popen|check_output)\b",
    r"\bshell\s*=\s*True\b",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    # Deserialization
    r"\bpickle\.loads\s*\(",
    r"\byaml\.load\s*\(",
    # Web / templates (common hotspots)
    r"\brender_template_string\b",
    r"\bJinja2\b",
    # SQL (very rough heuristics)
    r"SELECT\s+.+\+\s*\w+",
    r"INSERT\s+INTO\s+.+\+\s*\w+",
    r"UPDATE\s+.+\+\s*\w+",
]

_RISK_RE = re.compile("|".join(f"(?:{p})" for p in _RISK_MARKERS), re.IGNORECASE)


def looks_risky_code_for_llm(code_text: str) -> bool:
    """Cheap prefilter to avoid LLM calls for obviously safe files."""
    return bool(_RISK_RE.search(code_text))


def _parse_model_output(text: str) -> list[tuple[str, int | None, str]]:
    """Return list of (severity, line_number?, line_text)."""
    out: list[tuple[str, int | None, str]] = []
    if not text:
        return out
    upper = text.strip().upper()
    if "[БЕЗОПАСНО]" in upper or "[SAFE]" in upper or upper == "БЕЗОПАСНО" or upper == "SAFE":
        return out

    for raw_line in text.splitlines():
        raw_line = raw_line.strip()
        if not raw_line:
            continue

        # Accept both formats:
        #   [КРИТИЧЕСКАЯ] - L4: ...
        #   КРИТИЧЕСКАЯ - L4: ...
        if " - " not in raw_line:
            continue
        left, right = raw_line.split(" - ", 1)
        left = left.strip()
        if left.startswith("[") and left.endswith("]"):
            left = left[1:-1].strip()

        sev = _normalize_threat(left)
        if not sev or sev == "SAFE":
            continue

        ln: int | None = None
        code = right.strip()
        m2 = _LNUM_RE.match(code)
        if m2:
            ln = int(m2.group("lineno"))
            code = (m2.group("text") or "").strip()

        out.append((sev, ln, code))
    return out


def scan_code_security(
    code_text: str,
    *,
    filepath: str,
    cfg: AISecurityConfig,
    system_prompt: str = DEFAULT_SYSTEM_PROMPT,
) -> list[Finding]:
    if not code_text.strip():
        return []

    try:
        size = len(code_text.encode("utf-8", errors="ignore"))
    except Exception:
        size = len(code_text)
    if size > cfg.max_bytes:
        return []

    if cfg.provider != "nvidia":
        raise AISecurityError(f"Unsupported AI provider: {cfg.provider!r}")

    client = _make_client(cfg)
    model = _pick_model(client, cfg.model)

    # Provide line numbers to make parsing deterministic.
    user_payload = _with_line_numbers(code_text)

    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_payload},
            ],
            temperature=cfg.temperature,
            max_tokens=cfg.max_tokens,
        )
        content = resp.choices[0].message.content or ""
    except Exception as exc:  # noqa: BLE001
        raise AISecurityError(f"AI request failed ({model}): {exc}") from exc

    parsed = _parse_model_output(content.strip())
    if not parsed:
        return []

    original_lines = code_text.splitlines()
    findings: list[Finding] = []
    for severity, ln, code_line in parsed:
        if ln is None:
            # Best-effort lookup by content
            ln = 1
            if code_line:
                for i, line in enumerate(original_lines, start=1):
                    if code_line in line:
                        ln = i
                        break

        line_content = ""
        if 1 <= ln <= len(original_lines):
            line_content = original_lines[ln - 1].rstrip()
        elif code_line:
            line_content = code_line[:200]

        score = _SEVERITY_TO_SCORE.get(severity, 5)
        findings.append(
            Finding(
                file=filepath,
                line_number=ln,
                line_content=line_content,
                secret_type="AI Security",
                matched_value=(code_line or line_content)[:80],
                score=score,
                severity=severity,
                category="ai_security",
                source="ai:nvidia",
                entropy=0.0,
                context_match=False,
                structural_valid=False,
                confidence=0.55 if severity in {"LOW", "MEDIUM"} else 0.7,
                taint_traces=[],
            )
        )

    return findings


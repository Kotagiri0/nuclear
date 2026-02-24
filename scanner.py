import re
import math
import os
import zipfile
import tempfile
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


PATTERNS = {
    "AWS Access Key": (r"\bAKIA[0-9A-Z]{16}\b", 9),
    "AWS Secret Key": (r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", 9),
    "GitHub Token": (r"\bghp_[a-zA-Z0-9]{36}\b", 9),
    "GitHub OAuth": (r"\bgho_[a-zA-Z0-9]{36}\b", 8),
    "GitHub App Token": (r"\bghs_[a-zA-Z0-9]{36}\b", 8),
    "Slack Token": (r"\bxox[bpoa]-[0-9a-zA-Z\-]{10,48}\b", 8),
    "Stripe Secret Key": (r"\bsk_live_[0-9a-zA-Z]{24,}\b", 9),
    "Stripe Publishable Key": (r"\bpk_live_[0-9a-zA-Z]{24,}\b", 5),
    "Twilio Account SID": (r"\bAC[a-zA-Z0-9]{32}\b", 7),
    "Twilio Auth Token": (r"\b[a-f0-9]{32}\b", 3),
    "Google API Key": (r"\bAIza[0-9A-Za-z\-_]{35}\b", 8),
    "Google OAuth": (r"\b[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com\b", 7),
    "Private Key": (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", 10),
    "JWT Token": (r"\beyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\b", 7),
    "Bearer Token": (r"(?i)bearer\s+[a-zA-Z0-9_\-\.=]{20,}", 6),
    "Basic Auth": (r"(?i)basic\s+[a-zA-Z0-9+/]{20,}={0,2}\b", 6),
    "Telegram Bot Token": (r"\b[0-9]{8,10}:[a-zA-Z0-9_\-]{35}\b", 8),
    "SendGrid API Key": (r"\bSG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}\b", 9),
    "Mailgun API Key": (r"\bkey-[a-zA-Z0-9]{32}\b", 7),
    "HubSpot API Key": (r"\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b", 3),
    "Generic API Key": (r"(?i)api[_\-\s]?key\s*[=:]\s*['\"]?([a-zA-Z0-9_\-\.]{20,})['\"]?", 5),
    "Generic Secret": (r"(?i)(?:secret|password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{8,})['\"]", 5),
    "Generic Token": (r"(?i)token\s*[=:]\s*['\"]([a-zA-Z0-9_\-\.]{16,})['\"]", 4),
    "Private IP in code": (r"(?i)(?:host|server|endpoint)\s*[=:]\s*['\"]?(192\.168\.|10\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)", 2),
}

CONTEXT_KEYWORDS = [
    "api_key", "apikey", "secret", "password", "passwd", "pwd",
    "token", "auth", "credential", "private_key", "access_key",
    "client_secret", "app_secret", "api_secret",
]

IGNORE_PATTERNS = [
    r"example", r"test", r"fake", r"dummy", r"placeholder",
    r"xxxx", r"1234", r"your[_\-]?key", r"<[^>]+>", r"\*{4,}",
    r"TODO", r"FIXME",
]

HASH_PATTERNS = [
    r"^[a-f0-9]{32}$",
    r"^[a-f0-9]{40}$",
    r"^[a-f0-9]{64}$",
]

SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".woff", ".woff2",
    ".ttf", ".eot", ".mp4", ".mp3", ".zip", ".tar", ".gz", ".pdf",
    ".lock", ".sum",
}

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".idea", ".vscode", "vendor",
}

HIGH_ENTROPY_FILE_TYPES = {".env", ".cfg", ".conf", ".ini", ".yaml", ".yml", ".json", ".toml"}

SINK_NAMES = {
    r"\brequests\.(get|post|put|patch|delete|head)\b": "HTTP request",
    r"\burllib\.request\.": "HTTP request",
    r"\bhttpx\.(get|post|put|patch|delete)\b": "HTTP request",
    r"\baiohttp\.": "HTTP request",
    r"\bsmtplib\.": "Email sending",
    r"\blogging\.(info|debug|warning|error|critical)\b": "Logging",
    r"\bprint\s*\(": "Console output",
    r"\bopen\s*\(": "File write",
    r"\bsubprocess\.(run|call|Popen|check_output)\b": "Shell execution",
    r"\bos\.system\s*\(": "Shell execution",
    r"\bsocket\.": "Raw socket",
    r"\bparamiko\.": "SSH connection",
    r"\bpysftp\.": "SFTP connection",
    r"\bboto3\.": "AWS SDK call",
    r"\bpymongo\.": "MongoDB query",
    r"\bpsycopg2\.": "PostgreSQL query",
    r"\bsqlalchemy\.": "Database query",
}


@dataclass
class TaintStep:
    file: str
    line_number: int
    line_content: str
    variable: str
    action: str


@dataclass
class TaintTrace:
    source_variable: str
    source_file: str
    source_line: int
    sink_type: str
    sink_file: str
    sink_line: int
    sink_content: str
    steps: list = field(default_factory=list)

    def depth(self) -> int:
        return len(self.steps)


@dataclass
class Finding:
    file: str
    line_number: int
    line_content: str
    secret_type: str
    matched_value: str
    score: int
    severity: str
    entropy: float = 0.0
    context_match: bool = False
    structural_valid: bool = False
    taint_traces: list = field(default_factory=list)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def is_likely_hash(value: str) -> bool:
    v = value.strip()
    for p in HASH_PATTERNS:
        if re.match(p, v, re.IGNORECASE):
            return True
    return False


def is_false_positive(value: str) -> bool:
    for p in IGNORE_PATTERNS:
        if re.search(p, value, re.IGNORECASE):
            return True
    if len(set(value)) < 4:
        return True
    return False


def has_context(lines: list, idx: int) -> bool:
    start = max(0, idx - 2)
    end = min(len(lines), idx + 3)
    window = " ".join(lines[start:end]).lower()
    return any(kw in window for kw in CONTEXT_KEYWORDS)


def validate_structure(secret_type: str, value: str) -> bool:
    if secret_type == "JWT Token":
        parts = value.split(".")
        return len(parts) == 3 and all(len(p) > 0 for p in parts)
    if secret_type == "AWS Access Key":
        return bool(re.match(r"^AKIA[0-9A-Z]{16}$", value))
    if secret_type == "Private Key":
        return "BEGIN" in value and ("PRIVATE KEY" in value or "RSA" in value)
    if "UUID" in secret_type or "HubSpot" in secret_type:
        return bool(re.match(r"^[a-f0-9\-]{36}$", value, re.IGNORECASE))
    return False


def score_to_severity(score: int) -> str:
    if score >= 12:
        return "CRITICAL"
    if score >= 8:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


def extract_match_value(match) -> str:
    if match.lastindex and match.lastindex >= 1:
        return match.group(1)
    return match.group(0)


def _extract_var_name(line: str) -> Optional[str]:
    m = re.match(r'\s*([A-Z_a-z][A-Z_a-z0-9]*)\s*=', line)
    if m:
        return m.group(1)
    return None


def _find_sink_name(line: str) -> Optional[str]:
    for pattern, name in SINK_NAMES.items():
        if re.search(pattern, line):
            return name
    return None


def taint_analysis(content: str, filepath: str, secret_vars: list) -> list:
    if not secret_vars:
        return []

    lines = content.splitlines()
    traces = []

    for var_name, source_line in secret_vars:
        tainted = {var_name}
        steps = []

        for i, line in enumerate(lines):
            lineno = i + 1
            if lineno == source_line:
                continue

            assign_match = re.match(r'\s*([A-Z_a-z][A-Z_a-z0-9]*)\s*=(.+)', line)
            if assign_match:
                lhs = assign_match.group(1)
                rhs = assign_match.group(2)
                for tv in list(tainted):
                    if re.search(r'\b' + re.escape(tv) + r'\b', rhs):
                        tainted.add(lhs)
                        steps.append(TaintStep(
                            file=filepath,
                            line_number=lineno,
                            line_content=line.rstrip(),
                            variable=lhs,
                            action=f"propagated from {tv}",
                        ))
                        break

            sink_name = _find_sink_name(line)
            if sink_name:
                for tv in tainted:
                    if re.search(r'\b' + re.escape(tv) + r'\b', line):
                        traces.append(TaintTrace(
                            source_variable=var_name,
                            source_file=filepath,
                            source_line=source_line,
                            sink_type=sink_name,
                            sink_file=filepath,
                            sink_line=lineno,
                            sink_content=line.rstrip(),
                            steps=list(steps),
                        ))
                        break

    return traces


def scan_content(content: str, filepath: str) -> list:
    findings = []
    lines = content.splitlines()
    ext = Path(filepath).suffix.lower()

    secret_vars = []

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue

        for secret_type, (pattern, base_score) in PATTERNS.items():
            for match in re.finditer(pattern, line):
                value = extract_match_value(match)

                if is_false_positive(value):
                    continue

                score = base_score
                entropy = shannon_entropy(value)

                if is_likely_hash(value):
                    score -= 3

                if entropy > 4.5:
                    score += 3
                elif entropy > 3.5:
                    score += 1

                ctx = has_context(lines, i)
                if ctx:
                    score += 2

                if ext in HIGH_ENTROPY_FILE_TYPES:
                    score += 2
                if ext == ".env":
                    score += 1

                struct_valid = validate_structure(secret_type, value)
                if struct_valid:
                    score += 3

                if score < 2:
                    continue

                severity = score_to_severity(score)

                var_name = _extract_var_name(line)
                if var_name:
                    secret_vars.append((var_name, i + 1))

                findings.append(Finding(
                    file=filepath,
                    line_number=i + 1,
                    line_content=line.rstrip(),
                    secret_type=secret_type,
                    matched_value=value[:80] + "..." if len(value) > 80 else value,
                    score=score,
                    severity=severity,
                    entropy=round(entropy, 2),
                    context_match=ctx,
                    structural_valid=struct_valid,
                ))

    if secret_vars and ext in {".py", ".js", ".ts", ".rb", ".go", ".java", ".php"}:
        traces = taint_analysis(content, filepath, secret_vars)
        for finding in findings:
            relevant = [
                t for t in traces
                if t.source_line == finding.line_number
                or any(s.line_number == finding.line_number for s in t.steps)
            ]
            finding.taint_traces = relevant
            if relevant:
                finding.score += 2
                finding.severity = score_to_severity(finding.score)

    return findings


def scan_file(filepath: str) -> list:
    path = Path(filepath)
    if path.suffix.lower() in SKIP_EXTENSIONS:
        return []
    try:
        content = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return []
    return scan_content(content, filepath)


def scan_directory(root: str) -> list:
    findings = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            findings.extend(scan_file(filepath))
    return findings


def scan_zip(zip_path: str) -> list:
    findings = []
    tmp_dir = tempfile.mkdtemp(prefix="secret_scanner_")
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            members = [
                m for m in zf.namelist()
                if not m.endswith("/")
                and not any(part in SKIP_DIRS for part in Path(m).parts)
                and Path(m).suffix.lower() not in SKIP_EXTENSIONS
            ]
            zf.extractall(tmp_dir, members=members)

        for member in members:
            extracted_path = os.path.join(tmp_dir, member)
            if not os.path.isfile(extracted_path):
                continue
            file_findings = scan_file(extracted_path)
            for f in file_findings:
                f.file = member
            findings.extend(file_findings)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

    return findings


def deduplicate(findings: list) -> list:
    seen = set()
    result = []
    for f in findings:
        key = (f.file, f.line_number, f.secret_type, f.matched_value)
        if key not in seen:
            seen.add(key)
            result.append(f)
    return result


def _format_taint_trace(trace, color: str, reset: str, bold: str) -> list:
    lines = []
    lines.append(f"  {bold}🔗 Taint trace:{reset} {color}{trace.source_variable}{reset} → {bold}{trace.sink_type}{reset}")
    lines.append(f"     📍 Source : {trace.source_file}:{trace.source_line}")
    for step in trace.steps:
        lines.append(f"     ↓  {step.file}:{step.line_number}  [{step.action}]")
        lines.append(f"        {step.line_content.strip()[:100]}")
    lines.append(f"     💥 Sink   : {trace.sink_file}:{trace.sink_line}  [{trace.sink_type}]")
    lines.append(f"        {trace.sink_content.strip()[:100]}")
    return lines


def generate_report(findings: list, output_format: str = "text") -> str:
    findings = deduplicate(findings)
    findings.sort(key=lambda f: (-f.score, f.file, f.line_number))

    if output_format == "json":
        import json
        data = []
        for f in findings:
            traces = []
            for t in f.taint_traces:
                traces.append({
                    "source_variable": t.source_variable,
                    "source_file": t.source_file,
                    "source_line": t.source_line,
                    "sink_type": t.sink_type,
                    "sink_file": t.sink_file,
                    "sink_line": t.sink_line,
                    "sink_content": t.sink_content.strip(),
                    "depth": t.depth(),
                    "steps": [
                        {
                            "file": s.file,
                            "line": s.line_number,
                            "variable": s.variable,
                            "action": s.action,
                            "content": s.line_content.strip(),
                        }
                        for s in t.steps
                    ],
                })
            data.append({
                "file": f.file,
                "line": f.line_number,
                "type": f.secret_type,
                "severity": f.severity,
                "score": f.score,
                "entropy": f.entropy,
                "value": f.matched_value,
                "context_match": f.context_match,
                "structural_valid": f.structural_valid,
                "line_content": f.line_content.strip(),
                "taint_traces": traces,
            })
        return json.dumps({"total": len(findings), "findings": data}, indent=2)

    if not findings:
        return "✅ No secrets found."

    severity_colors = {
        "CRITICAL": "\033[91m",
        "HIGH": "\033[31m",
        "MEDIUM": "\033[33m",
        "LOW": "\033[34m",
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"

    out = [f"\n{BOLD}🔍 Secret Scanner Report{RESET}", f"Found {len(findings)} potential secret(s)\n"]
    out.append("=" * 70)

    for f in findings:
        color = severity_colors.get(f.severity, "")
        out.append(f"{BOLD}{color}[{f.severity}]{RESET} {f.secret_type}")
        out.append(f"  📁 File   : {f.file}:{f.line_number}")
        out.append(f"  🔑 Value  : {f.matched_value}")
        out.append(f"  📊 Score  : {f.score} | Entropy: {f.entropy}")
        flags = []
        if f.context_match:
            flags.append("context✓")
        if f.structural_valid:
            flags.append("structure✓")
        if f.taint_traces:
            flags.append(f"taint:{len(f.taint_traces)}✓")
        if flags:
            out.append(f"  🏷  Flags  : {', '.join(flags)}")
        out.append(f"  📝 Line   : {f.line_content.strip()[:120]}")

        if f.taint_traces:
            out.append(f"  {DIM}{'─' * 50}{RESET}")
            for trace in f.taint_traces:
                out.extend(_format_taint_trace(trace, color, RESET, BOLD))

        out.append("-" * 70)

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        summary[f.severity] += 1
    out.append(f"\n{BOLD}Summary:{RESET}")
    for sev, count in summary.items():
        if count:
            c = severity_colors[sev]
            out.append(f"  {c}{sev}{RESET}: {count}")

    tainted_count = sum(1 for f in findings if f.taint_traces)
    if tainted_count:
        out.append(f"\n  {severity_colors['CRITICAL']}⚠  Secrets actively used in dangerous sinks: {tainted_count}{RESET}")

    return "\n".join(out)

import math
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .patterns import (
    CONTEXT_KEYWORDS,
    HASH_PATTERNS,
    HIGH_ENTROPY_FILE_TYPES,
    IGNORE_PATTERNS,
    PATTERNS,
    SINK_NAMES,
)


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
    category: str = "unknown"
    source: str = "current"
    entropy: float = 0.0
    context_match: bool = False
    structural_valid: bool = False
    confidence: float = 0.0
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
    return len(set(value)) < 4


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
    if secret_type == "Connection String":
        return "://" in value and "@" in value
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
    m = re.match(r"\s*([A-Z_a-z][A-Z_a-z0-9]*)\s*=", line)
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

            assign_match = re.match(r"\s*([A-Z_a-z][A-Z_a-z0-9]*)\s*=(.+)", line)
            if assign_match:
                lhs = assign_match.group(1)
                rhs = assign_match.group(2)
                for tv in list(tainted):
                    if re.search(r"\b" + re.escape(tv) + r"\b", rhs):
                        tainted.add(lhs)
                        steps.append(
                            TaintStep(
                                file=filepath,
                                line_number=lineno,
                                line_content=line.rstrip(),
                                variable=lhs,
                                action=f"propagated from {tv}",
                            )
                        )
                        break

            sink_name = _find_sink_name(line)
            if sink_name:
                for tv in tainted:
                    if re.search(r"\b" + re.escape(tv) + r"\b", line):
                        traces.append(
                            TaintTrace(
                                source_variable=var_name,
                                source_file=filepath,
                                source_line=source_line,
                                sink_type=sink_name,
                                sink_file=filepath,
                                sink_line=lineno,
                                sink_content=line.rstrip(),
                                steps=list(steps),
                            )
                        )
                        break

    return traces


def _confidence(score: int, entropy: float, struct_valid: bool, tainted: bool) -> float:
    confidence = min(0.99, 0.15 + (score / 16.0))
    if entropy > 4.5:
        confidence += 0.1
    if struct_valid:
        confidence += 0.15
    if tainted:
        confidence += 0.15
    return round(min(confidence, 0.99), 2)


def scan_content(content: str, filepath: str, source: str = "current") -> list:
    findings = []
    lines = content.splitlines()
    ext = Path(filepath).suffix.lower()

    secret_vars = []

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("//"):
            continue

        for secret_type, (pattern, base_score, category) in PATTERNS.items():
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

                findings.append(
                    Finding(
                        file=filepath,
                        line_number=i + 1,
                        line_content=line.rstrip(),
                        secret_type=secret_type,
                        matched_value=value[:80] + "..." if len(value) > 80 else value,
                        score=score,
                        severity=severity,
                        category=category,
                        source=source,
                        entropy=round(entropy, 2),
                        context_match=ctx,
                        structural_valid=struct_valid,
                    )
                )

    if secret_vars and ext in {".py", ".js", ".ts", ".rb", ".go", ".java", ".php"}:
        traces = taint_analysis(content, filepath, secret_vars)
        for finding in findings:
            relevant = [
                t
                for t in traces
                if t.source_line == finding.line_number
                or any(s.line_number == finding.line_number for s in t.steps)
            ]
            finding.taint_traces = relevant
            if relevant:
                finding.score += 2
                finding.severity = score_to_severity(finding.score)
            finding.confidence = _confidence(
                score=finding.score,
                entropy=finding.entropy,
                struct_valid=finding.structural_valid,
                tainted=bool(relevant),
            )
    else:
        for finding in findings:
            finding.confidence = _confidence(
                score=finding.score,
                entropy=finding.entropy,
                struct_valid=finding.structural_valid,
                tainted=False,
            )

    return findings

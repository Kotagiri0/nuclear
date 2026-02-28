import json


def deduplicate(findings: list) -> list:
    seen = set()
    result = []
    for finding in findings:
        key = (finding.file, finding.line_number, finding.secret_type, finding.matched_value, finding.source)
        if key not in seen:
            seen.add(key)
            result.append(finding)
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


def _json_report(findings: list) -> str:
    data = []
    for finding in findings:
        traces = []
        for trace in finding.taint_traces:
            traces.append(
                {
                    "source_variable": trace.source_variable,
                    "source_file": trace.source_file,
                    "source_line": trace.source_line,
                    "sink_type": trace.sink_type,
                    "sink_file": trace.sink_file,
                    "sink_line": trace.sink_line,
                    "sink_content": trace.sink_content.strip(),
                    "depth": trace.depth(),
                    "steps": [
                        {
                            "file": step.file,
                            "line": step.line_number,
                            "variable": step.variable,
                            "action": step.action,
                            "content": step.line_content.strip(),
                        }
                        for step in trace.steps
                    ],
                }
            )
        data.append(
            {
                "file": finding.file,
                "line": finding.line_number,
                "type": finding.secret_type,
                "category": finding.category,
                "source": finding.source,
                "severity": finding.severity,
                "score": finding.score,
                "confidence": finding.confidence,
                "entropy": finding.entropy,
                "value": finding.matched_value,
                "context_match": finding.context_match,
                "structural_valid": finding.structural_valid,
                "line_content": finding.line_content.strip(),
                "taint_traces": traces,
            }
        )
    return json.dumps({"total": len(findings), "findings": data}, indent=2)


def _sarif_report(findings: list) -> str:
    results = []
    rules = {}
    for finding in findings:
        rule_id = finding.secret_type.replace(" ", "_").upper()
        rules[rule_id] = {
            "id": rule_id,
            "name": finding.secret_type,
            "shortDescription": {"text": finding.secret_type},
            "fullDescription": {"text": f"Detected potential secret: {finding.secret_type}"},
            "properties": {"category": finding.category},
        }
        level = "warning"
        if finding.severity in {"HIGH", "CRITICAL"}:
            level = "error"

        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {
                    "text": (
                        f"{finding.secret_type} ({finding.severity}) at {finding.file}:{finding.line_number}; "
                        f"confidence={finding.confidence}"
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file},
                            "region": {"startLine": finding.line_number},
                        }
                    }
                ],
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "nuclear-secret-scanner",
                        "informationUri": "https://example.local/nuclear-secret-scanner",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def _text_report(findings: list) -> str:
    if not findings:
        return "✅ Секреты не найдены."

    severity_colors = {
        "CRITICAL": "\033[91m",
        "HIGH": "\033[31m",
        "MEDIUM": "\033[33m",
        "LOW": "\033[34m",
    }
    reset = "\033[0m"
    bold = "\033[1m"
    dim = "\033[2m"

    out = [f"\n{bold}🔍 Secret Scanner Report{reset}", f"Found {len(findings)} potential secret(s)\n"]
    out.append("=" * 70)

    for finding in findings:
        color = severity_colors.get(finding.severity, "")
        out.append(f"{bold}{color}[{finding.severity}]{reset} {finding.secret_type} ({finding.category})")
        out.append(f"  📁 File   : {finding.file}:{finding.line_number}")
        mv = finding.matched_value
        mv_display = (mv[:60] + "...") if len(mv) > 60 else mv
        out.append(f"  🔑 Value  : {mv_display}")
        out.append(f"  📊 Score  : {finding.score} | Entropy: {finding.entropy} | Confidence: {finding.confidence}")
        out.append(f"  🧭 Source : {finding.source}")
        flags = []
        if finding.context_match:
            flags.append("context✓")
        if finding.structural_valid:
            flags.append("structure✓")
        if finding.taint_traces:
            flags.append(f"taint:{len(finding.taint_traces)}✓")
        if flags:
            out.append(f"  🏷  Flags  : {', '.join(flags)}")
        out.append(f"  📝 Line   : {finding.line_content.strip()[:120]}")

        if finding.taint_traces:
            out.append(f"  {dim}{'─' * 50}{reset}")
            for trace in finding.taint_traces:
                out.extend(_format_taint_trace(trace, color, reset, bold))

        out.append("-" * 70)

    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        summary[finding.severity] += 1
    out.append(f"\n{bold}Summary:{reset}")
    for severity, count in summary.items():
        if count:
            c = severity_colors[severity]
            out.append(f"  {c}{severity}{reset}: {count}")

    tainted_count = sum(1 for finding in findings if finding.taint_traces)
    if tainted_count:
        out.append(
            f"\n  {severity_colors['CRITICAL']}⚠  Secrets actively used in dangerous sinks: {tainted_count}{reset}"
        )

    return "\n".join(out)


def generate_report(findings: list, output_format: str = "text") -> str:
    findings = deduplicate(findings)
    findings.sort(key=lambda finding: (-finding.score, finding.file, finding.line_number))

    if output_format == "json":
        return _json_report(findings)
    if output_format == "sarif":
        return _sarif_report(findings)
    return _text_report(findings)

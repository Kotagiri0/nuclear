"""
Tests for scanner/reporting.py — full branch coverage.
"""
from __future__ import annotations

import json

import pytest

from scanner import Finding, generate_report
from scanner.core.analysis import TaintStep, TaintTrace
from scanner.output.reporting import (
    _json_report,
    _sarif_report,
    _text_report,
    deduplicate,
)


# ── helpers ───────────────────────────────────────────────────────────────────

def _f(
    severity="HIGH",
    score=9,
    file="app.py",
    line=1,
    secret_type="Generic Secret",
    matched_value="s3cr3tValu3_123456",
    source="current",
    context_match=False,
    structural_valid=False,
    entropy=4.0,
    confidence=0.6,
) -> Finding:
    return Finding(
        file=file,
        line_number=line,
        line_content=f"key = '{matched_value}'",
        secret_type=secret_type,
        matched_value=matched_value,
        score=score,
        severity=severity,
        category="credential",
        source=source,
        entropy=entropy,
        context_match=context_match,
        structural_valid=structural_valid,
        confidence=confidence,
    )


def _f_with_taint() -> Finding:
    f = _f(severity="CRITICAL", score=14)
    f.taint_traces = [
        TaintTrace(
            source_variable="API_KEY",
            source_file="app.py",
            source_line=1,
            sink_type="HTTP request",
            sink_file="app.py",
            sink_line=5,
            sink_content="requests.get(url, headers={'key': API_KEY})",
            steps=[
                TaintStep("app.py", 3, "headers = {'key': API_KEY}", "headers", "propagated from API_KEY")
            ],
        )
    ]
    return f


# ── deduplicate ───────────────────────────────────────────────────────────────

class TestDeduplicate:
    def test_removes_exact_duplicates(self):
        f1 = _f()
        f2 = _f()  # same key tuple
        result = deduplicate([f1, f2])
        assert len(result) == 1

    def test_keeps_different_lines(self):
        f1 = _f(line=1)
        f2 = _f(line=2)
        result = deduplicate([f1, f2])
        assert len(result) == 2

    def test_keeps_different_files(self):
        f1 = _f(file="a.py")
        f2 = _f(file="b.py")
        result = deduplicate([f1, f2])
        assert len(result) == 2

    def test_keeps_different_types(self):
        f1 = _f(secret_type="Yandex Cloud Service Account Key")
        f2 = _f(secret_type="VK API Access Token")
        result = deduplicate([f1, f2])
        assert len(result) == 2

    def test_keeps_different_source(self):
        f1 = _f(source="current")
        f2 = _f(source="history")
        result = deduplicate([f1, f2])
        assert len(result) == 2

    def test_empty_list(self):
        assert deduplicate([]) == []

    def test_preserves_order(self):
        f1 = _f(line=3)
        f2 = _f(line=1)
        result = deduplicate([f1, f2])
        assert result[0].line_number == 3
        assert result[1].line_number == 1


# ── _text_report ──────────────────────────────────────────────────────────────

class TestTextReport:
    def test_empty_findings_message(self):
        report = _text_report([])
        assert "Секреты не найдены" in report

    def test_critical_in_output(self):
        report = _text_report([_f(severity="CRITICAL", score=14)])
        assert "CRITICAL" in report

    def test_high_in_output(self):
        report = _text_report([_f(severity="HIGH", score=9)])
        assert "HIGH" in report

    def test_medium_in_output(self):
        report = _text_report([_f(severity="MEDIUM", score=6)])
        assert "MEDIUM" in report

    def test_low_in_output(self):
        report = _text_report([_f(severity="LOW", score=3)])
        assert "LOW" in report

    def test_context_match_flag_shown(self):
        report = _text_report([_f(context_match=True)])
        assert "context✓" in report

    def test_structural_valid_flag_shown(self):
        report = _text_report([_f(structural_valid=True)])
        assert "structure✓" in report

    def test_taint_flag_shown(self):
        report = _text_report([_f_with_taint()])
        assert "taint:" in report

    def test_long_line_content_truncated(self):
        long_line = "x" * 200
        f = _f()
        f.line_content = long_line
        report = _text_report([f])
        # Line content is trimmed to 120 chars
        assert "x" * 121 not in report

    def test_long_matched_value_truncated(self):
        f = _f(matched_value="A" * 90)
        report = _text_report([f])
        assert "..." in report

    def test_summary_counts_correct(self):
        findings = [
            _f(severity="HIGH"),
            _f(severity="HIGH", line=2),
            _f(severity="LOW", line=3),
        ]
        report = _text_report(findings)
        assert "HIGH" in report
        assert "LOW" in report

    def test_dangerous_sinks_warning_shown_with_taint(self):
        report = _text_report([_f_with_taint()])
        assert "dangerous sinks" in report

    def test_no_dangerous_sinks_warning_without_taint(self):
        report = _text_report([_f()])
        assert "dangerous sinks" not in report

    def test_file_and_line_in_output(self):
        report = _text_report([_f(file="secret/config.py", line=42)])
        assert "secret/config.py:42" in report

    def test_taint_trace_section_present(self):
        report = _text_report([_f_with_taint()])
        assert "Taint trace" in report
        assert "HTTP request" in report

    def test_taint_steps_in_text(self):
        report = _text_report([_f_with_taint()])
        assert "headers" in report


# ── _json_report ──────────────────────────────────────────────────────────────

class TestJsonReport:
    def test_total_field_present(self):
        data = json.loads(_json_report([_f()]))
        assert data["total"] == 1

    def test_total_zero_for_empty(self):
        data = json.loads(_json_report([]))
        assert data["total"] == 0

    def test_finding_has_all_fields(self):
        data = json.loads(_json_report([_f()]))
        finding = data["findings"][0]
        for field in ("file", "line", "type", "category", "source", "severity",
                      "score", "confidence", "entropy", "value", "context_match",
                      "structural_valid", "line_content", "taint_traces"):
            assert field in finding, f"Missing field: {field}"

    def test_taint_traces_in_json(self):
        data = json.loads(_json_report([_f_with_taint()]))
        traces = data["findings"][0]["taint_traces"]
        assert len(traces) == 1
        assert traces[0]["sink_type"] == "HTTP request"
        assert traces[0]["depth"] == 1

    def test_taint_steps_in_json(self):
        data = json.loads(_json_report([_f_with_taint()]))
        steps = data["findings"][0]["taint_traces"][0]["steps"]
        assert len(steps) == 1
        assert steps[0]["variable"] == "headers"

    def test_empty_taint_traces_list(self):
        data = json.loads(_json_report([_f()]))
        assert data["findings"][0]["taint_traces"] == []

    def test_multiple_findings(self):
        data = json.loads(_json_report([_f(), _f(line=2)]))
        assert data["total"] == 2
        assert len(data["findings"]) == 2


# ── _sarif_report ─────────────────────────────────────────────────────────────

class TestSarifReportFull:
    def test_location_uri_present(self):
        f = _f(file="src/config.py")
        data = json.loads(_sarif_report([f]))
        uri = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        assert "config.py" in uri

    def test_location_start_line(self):
        f = _f(line=17)
        data = json.loads(_sarif_report([f]))
        region = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
        assert region["startLine"] == 17

    def test_rule_full_description(self):
        data = json.loads(_sarif_report([_f()]))
        rule = data["runs"][0]["tool"]["driver"]["rules"][0]
        assert "fullDescription" in rule

    def test_rule_short_description(self):
        data = json.loads(_sarif_report([_f()]))
        rule = data["runs"][0]["tool"]["driver"]["rules"][0]
        assert "shortDescription" in rule

    def test_message_contains_severity(self):
        f = _f(severity="CRITICAL", score=14)
        data = json.loads(_sarif_report([f]))
        msg = data["runs"][0]["results"][0]["message"]["text"]
        assert "CRITICAL" in msg

    def test_message_contains_filename(self):
        f = _f(file="main.py")
        data = json.loads(_sarif_report([f]))
        msg = data["runs"][0]["results"][0]["message"]["text"]
        assert "main.py" in msg


# ── generate_report integration ───────────────────────────────────────────────

class TestGenerateReportIntegration:
    def test_deduplication_applied(self):
        f1 = _f()
        f2 = _f()
        report = generate_report([f1, f2], "json")
        data = json.loads(report)
        assert data["total"] == 1

    def test_sorted_by_score_descending(self):
        f_low = _f(severity="LOW", score=2, line=1)
        f_high = _f(severity="CRITICAL", score=14, line=2)
        data = json.loads(generate_report([f_low, f_high], "json"))
        scores = [d["score"] for d in data["findings"]]
        assert scores == sorted(scores, reverse=True)

    def test_text_format(self):
        report = generate_report([_f()], "text")
        assert "HIGH" in report

    def test_json_format(self):
        data = json.loads(generate_report([_f()], "json"))
        assert "findings" in data

    def test_sarif_format(self):
        data = json.loads(generate_report([_f()], "sarif"))
        assert "runs" in data

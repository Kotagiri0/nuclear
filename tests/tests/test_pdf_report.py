from __future__ import annotations

from scanner import Finding
from scanner.output.pdf_report import generate_pdf_report, save_pdf_report


def _finding() -> Finding:
    return Finding(
        file="app.py",
        line_number=7,
        line_content="API_KEY = 'AKIAJX7LKQHMBQWRFP2A'",
        secret_type="AWS Access Key",
        matched_value="AKIAJX7LKQHMBQWRFP2A",
        score=13,
        severity="CRITICAL",
        category="api_key",
        source="current",
        entropy=4.6,
        context_match=True,
        structural_valid=True,
        confidence=0.93,
    )


def test_generate_pdf_report_returns_valid_header():
    body = generate_pdf_report([_finding()], target="demo-project")
    assert body.startswith(b"%PDF")
    assert b"Nuclear Secret Scanner Report" in body


def test_save_pdf_report_writes_file(tmp_path):
    output = tmp_path / "reports" / "scan.pdf"
    path = save_pdf_report([_finding()], target="demo-project", output_path=output)
    assert path == output
    assert output.exists()
    assert output.read_bytes().startswith(b"%PDF")

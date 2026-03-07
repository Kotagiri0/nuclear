from __future__ import annotations

import textwrap
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from scanner.output.reporting import deduplicate


_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _ascii_text(value: Any) -> str:
    text = str(value)
    return text.encode("latin-1", errors="replace").decode("latin-1")


def _escape_pdf_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _build_report_lines(findings: list, target: str = "") -> list[str]:
    normalized = deduplicate(findings)
    normalized.sort(key=lambda finding: (-finding.score, finding.file, finding.line_number))

    counts = {sev: 0 for sev in _SEVERITY_ORDER}
    for finding in normalized:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1

    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines = [
        "Nuclear Secret Scanner Report",
        f"Target: {_ascii_text(target or 'N/A')}",
        f"Generated: {generated_at}",
        f"Total findings: {len(normalized)}",
        (
            "Summary: "
            + " | ".join(f"{severity}={counts.get(severity, 0)}" for severity in _SEVERITY_ORDER)
        ),
        "",
    ]

    if not normalized:
        lines.append("No secrets found.")
        return lines

    for index, finding in enumerate(normalized, 1):
        header = (
            f"{index}. [{finding.severity}] {finding.secret_type} "
            f"| {_ascii_text(finding.file)}:{finding.line_number}"
        )
        stats = (
            f"score={finding.score} | confidence={finding.confidence:.2f} "
            f"| category={_ascii_text(finding.category)}"
        )
        value = _ascii_text(finding.matched_value)
        context = _ascii_text(finding.line_content.strip())

        lines.extend(textwrap.wrap(header, width=100) or [""])
        lines.extend(textwrap.wrap(stats, width=100) or [""])
        lines.extend(textwrap.wrap(f"value: {value}", width=100) or [""])
        lines.extend(textwrap.wrap(f"line : {context}", width=100) or [""])
        lines.append("")

    return lines


def _render_page_stream(lines: list[str]) -> bytes:
    content_parts = ["BT", "/F1 10 Tf", "14 TL", "40 800 Td"]
    for line in lines:
        safe_line = _escape_pdf_text(_ascii_text(line))
        content_parts.append(f"({safe_line}) Tj")
        content_parts.append("T*")
    content_parts.append("ET")
    stream_text = "\n".join(content_parts)
    return stream_text.encode("latin-1", errors="replace")


def generate_pdf_report(findings: list, target: str = "") -> bytes:
    lines = _build_report_lines(findings, target=target)
    lines_per_page = 52
    pages: list[list[str]] = []
    for start in range(0, len(lines), lines_per_page):
        pages.append(lines[start : start + lines_per_page])
    if not pages:
        pages = [["Nuclear Secret Scanner Report", "No data available."]]

    next_id = 1
    font_id = next_id
    next_id += 1
    pages_id = next_id
    next_id += 1

    page_ids: list[int] = []
    content_ids: list[int] = []
    for _ in pages:
        page_ids.append(next_id)
        next_id += 1
        content_ids.append(next_id)
        next_id += 1

    catalog_id = next_id
    total_objects = catalog_id
    objects: dict[int, bytes] = {}

    objects[font_id] = b"<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"
    kids = " ".join(f"{pid} 0 R" for pid in page_ids)
    objects[pages_id] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("ascii")

    for page_number, page_lines in enumerate(pages):
        page_id = page_ids[page_number]
        content_id = content_ids[page_number]
        page_object = (
            f"<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 595 842] "
            f"/Resources << /Font << /F1 {font_id} 0 R >> >> /Contents {content_id} 0 R >>"
        )
        objects[page_id] = page_object.encode("ascii")

        stream = _render_page_stream(page_lines)
        objects[content_id] = (
            f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"\nendstream"
        )

    objects[catalog_id] = f"<< /Type /Catalog /Pages {pages_id} 0 R >>".encode("ascii")

    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for obj_id in range(1, total_objects + 1):
        offsets.append(len(pdf))
        pdf.extend(f"{obj_id} 0 obj\n".encode("ascii"))
        pdf.extend(objects[obj_id])
        if not objects[obj_id].endswith(b"\n"):
            pdf.extend(b"\n")
        pdf.extend(b"endobj\n")

    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {total_objects + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))

    pdf.extend(
        (
            f"trailer\n<< /Size {total_objects + 1} /Root {catalog_id} 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(pdf)


def save_pdf_report(
    findings: list,
    target: str = "",
    output_path: str | Path | None = None,
    output_dir: str = ".nuclear-scan-result",
) -> Path:
    if output_path is None:
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)
        path = out / "report.pdf"
    else:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

    path.write_bytes(generate_pdf_report(findings, target=target))
    return path

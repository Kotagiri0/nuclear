"""UI components for the nuclear REPL — banner, styles, tables, summary."""
from __future__ import annotations

from pathlib import Path

from prompt_toolkit.styles import Style
from rich import box
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

console = Console()

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "blue",
}

PROMPT_STYLE = Style.from_dict({
    "prompt":      "ansigreen bold",
    "prompt.sign": "ansicyan bold",
})


def banner() -> None:
    console.print(Panel.fit(
        "[bold cyan]☢  nuclear[/bold cyan]  [dim]secret & vulnerability scanner REPL[/dim]\n"
        "Type [bold green]help[/bold green] to see commands  •  "
        "[bold green]scan <path>[/bold green] to start  •  "
        "[bold green]Ctrl+C ×2[/bold green] to quit",
        border_style="cyan",
    ))


def findings_table(findings: list) -> None:
    if not findings:
        console.print("[bold green]✔  No secrets found.[/bold green]")
        return

    table = Table(
        title=f"[bold]Found {len(findings)} secret(s)[/bold]",
        box=box.ROUNDED,
        show_lines=False,
        header_style="bold cyan",
    )
    table.add_column("#",        style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Type",     width=22)
    table.add_column("File",     width=35, overflow="fold")
    table.add_column("Line",     width=6)
    table.add_column("Score",    width=6)
    table.add_column("Conf",     width=5)
    table.add_column("Value",    width=35, overflow="fold")

    for idx, f in enumerate(findings, 1):
        sev_style = SEVERITY_STYLE.get(f.severity, "white")
        table.add_row(
            str(idx),
            Text(f.severity, style=sev_style),
            f.secret_type,
            str(Path(f.file).as_posix()),
            str(f.line_number),
            str(f.score),
            f"{f.confidence:.2f}",
            f.matched_value[:32] + ("…" if len(f.matched_value) > 32 else ""),
        )

    console.print(table)

    # Summary bar
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    parts = [
        Text(f"{sev}: {counts[sev]}", style=SEVERITY_STYLE.get(sev, "white"))
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        if sev in counts
    ]
    if parts:
        console.print(Columns(parts, padding=(0, 2)))


def session_summary(state: dict) -> None:
    """Print a brief session summary on exit."""
    scans = state.get("scan_count", 0)
    findings = state.get("total_findings", 0)
    cmds = len(state.get("cmd_history", []))
    findings_style = "red" if findings else "green"
    console.print(
        f"\n[bold cyan]☢  Сессия завершена[/bold cyan]  •  "
        f"команд: [bold]{cmds}[/bold]  •  "
        f"сканов: [bold]{scans}[/bold]  •  "
        f"секретов найдено: [bold {findings_style}]{findings}[/bold {findings_style}]"
    )


def status_table(state: dict) -> None:
    table = Table(title="[bold]Session settings[/bold]", box=box.SIMPLE, show_header=False)
    table.add_column("Key",   style="bold cyan", width=16)
    table.add_column("Value", style="white")
    for k, v in (
        ("format",      state["format"]),
        ("min-severity", state["severity"]),
        ("fail-on",     state["fail_on"]),
        ("history",     "on" if state["history"] else "off"),
        ("commits",     str(state["commits"])),
    ):
        table.add_row(k, str(v))
    console.print(table)

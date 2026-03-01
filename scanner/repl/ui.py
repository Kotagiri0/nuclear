"""UI components for the nuclear REPL — redesigned with professional dark theme."""
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

# ── Professional dark color palette ──────────────────────────────────────────

SEVERITY_STYLE = {
    "CRITICAL": "bold #ff4444",
    "HIGH":     "bold #ff8c00",
    "MEDIUM":   "#ffd700",
    "LOW":      "#6ec1e4",
}

SEVERITY_BADGE = {
    "CRITICAL": "[bold white on #cc0000] CRIT [/bold white on #cc0000]",
    "HIGH":     "[bold white on #cc5500] HIGH [/bold white on #cc5500]",
    "MEDIUM":   "[bold black on #e6b800] MED  [/bold black on #e6b800]",
    "LOW":      "[bold white on #336699]  LOW [/bold white on #336699]",
}

PROMPT_STYLE = Style.from_dict({
    "prompt":       "#00d787 bold",
    "prompt.sign":  "#ff5f00 bold",
    "prompt.path":  "#808080",
    "":             "#e0e0e0",
    # Autocomplete styling
    "completion-menu":                    "bg:#1a1a2e #e0e0e0",
    "completion-menu.completion":          "bg:#1a1a2e #e0e0e0",
    "completion-menu.completion.current":  "bg:#16213e #00d787 bold",
    "completion-menu.meta":               "bg:#1a1a2e #808080",
    "completion-menu.meta.current":       "bg:#16213e #00d787",
    "auto-suggest":                       "#555555",
    "scrollbar.background":               "bg:#1a1a2e",
    "scrollbar.button":                   "bg:#16213e",
})

# ── ASCII Art Banner ─────────────────────────────────────────────────────────

_LOGO = r"""[bold #ff5f00]
  ███╗   ██╗██╗   ██╗ ██████╗██╗     ███████╗ █████╗ ██████╗
  ████╗  ██║██║   ██║██╔════╝██║     ██╔════╝██╔══██╗██╔══██╗
  ██╔██╗ ██║██║   ██║██║     ██║     █████╗  ███████║██████╔╝
  ██║╚██╗██║██║   ██║██║     ██║     ██╔══╝  ██╔══██║██╔══██╗
  ██║ ╚████║╚██████╔╝╚██████╗███████╗███████╗██║  ██║██║  ██║
  ╚═╝  ╚═══╝ ╚═════╝  ╚═════╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝[/bold #ff5f00]"""

_TAGLINE = "[dim #808080]secret & vulnerability scanner[/dim #808080]  [dim]v0.2.0[/dim]"


def banner() -> None:
    content = (
        f"{_LOGO}\n"
        f"  {_TAGLINE}\n\n"
        f"  [#00d787]scan[/#00d787] [dim]<path>[/dim]  start scanning    "
        f"[#00d787]help[/#00d787]  command reference    "
        f"[#00d787]Ctrl+C ×2[/#00d787]  quit"
    )
    console.print(Panel(
        content,
        border_style="#333333",
        padding=(0, 1),
        expand=False,
    ))
    console.print()


# ── Findings table ───────────────────────────────────────────────────────────

def findings_table(findings: list) -> None:
    if not findings:
        console.print(
            Panel(
                "[bold #00d787]✔  No secrets found[/bold #00d787]",
                border_style="#333333",
                expand=False,
                padding=(0, 2),
            )
        )
        return

    table = Table(
        box=box.ROUNDED,
        show_lines=False,
        header_style="bold #6ec1e4",
        border_style="#333333",
        padding=(0, 1),
        expand=False,
    )
    table.add_column("#",        style="dim", width=4, justify="right")
    table.add_column("Severity", width=8, justify="center")
    table.add_column("Type",     style="#e0e0e0", width=22)
    table.add_column("File",     style="#808080", width=35, overflow="fold")
    table.add_column("Line",     style="dim", width=5, justify="right")
    table.add_column("Score",    style="#ffd700", width=5, justify="right")
    table.add_column("Conf",     style="dim", width=5, justify="right")
    table.add_column("Value",    style="#ff8c00", width=30, overflow="fold")

    for idx, f in enumerate(findings, 1):
        badge = Text.from_markup(SEVERITY_BADGE.get(f.severity, f.severity))
        table.add_row(
            str(idx),
            badge,
            f.secret_type,
            str(Path(f.file).as_posix()),
            str(f.line_number),
            str(f.score),
            f"{f.confidence:.0%}",
            f.matched_value[:28] + ("…" if len(f.matched_value) > 28 else ""),
        )

    header = f"[bold #ff5f00]☢[/bold #ff5f00]  [bold]Found {len(findings)} secret(s)[/bold]"
    console.print()
    console.print(header)
    console.print(table)

    # Severity summary bar
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    parts = []
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev in counts:
            style = SEVERITY_STYLE.get(sev, "white")
            parts.append(Text(f" {sev}: {counts[sev]} ", style=style))

    if parts:
        console.print(Columns(parts, padding=(0, 1)))
    console.print()


# ── Session summary ──────────────────────────────────────────────────────────

def session_summary(state: dict) -> None:
    scans = state.get("scan_count", 0)
    findings_count = state.get("total_findings", 0)
    cmds = len(state.get("cmd_history", []))
    findings_style = "#ff4444" if findings_count else "#00d787"

    grid = Table(box=None, show_header=False, padding=(0, 2), expand=False)
    grid.add_column(style="dim")
    grid.add_column(style="bold")
    grid.add_row("Commands", str(cmds))
    grid.add_row("Scans", str(scans))
    grid.add_row("Secrets found", Text(str(findings_count), style=findings_style))

    console.print()
    console.print(Panel(
        grid,
        title="[bold #ff5f00]☢[/bold #ff5f00] [bold]Session complete[/bold]",
        border_style="#333333",
        expand=False,
        padding=(0, 2),
    ))


# ── Status table ─────────────────────────────────────────────────────────────

def status_table(state: dict) -> None:
    grid = Table(box=None, show_header=False, padding=(0, 2), expand=False)
    grid.add_column("Key", style="bold #6ec1e4", width=16)
    grid.add_column("Value", style="#e0e0e0")

    for k, v in (
        ("format",       state["format"]),
        ("min-severity", state["severity"]),
        ("fail-on",      state["fail_on"]),
        ("history",      "[#00d787]on[/#00d787]" if state["history"] else "[dim]off[/dim]"),
        ("commits",      str(state["commits"])),
    ):
        grid.add_row(k, str(v))

    console.print(Panel(
        grid,
        title="[bold]Settings[/bold]",
        border_style="#333333",
        expand=False,
        padding=(0, 1),
    ))

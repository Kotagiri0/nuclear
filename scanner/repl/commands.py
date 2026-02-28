"""Command handlers for the nuclear REPL."""
from __future__ import annotations

import shlex
from pathlib import Path
from typing import Optional

from rich import box
from rich.panel import Panel
from rich.table import Table

from scanner.config import CONFIG_FILE, load_config, save_default_config, set_config_value
from scanner.core.runner import run_scan
from scanner.output.policy import should_fail
from scanner.output.html_report import save_html_report
from scanner.repl.ui import console, findings_table, SEVERITY_STYLE


# ── scan ─────────────────────────────────────────────────────────────────────

def parse_scan_args(tokens: list[str]) -> tuple[Optional[str], Optional[str], dict]:
    """Parse tokens for scan command. Returns (target, url, extra_opts)."""
    target: Optional[str] = None
    url:    Optional[str] = None
    extra:  dict = {}

    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in ("--url", "-u") and i + 1 < len(tokens):
            url = tokens[i + 1]; i += 2
        elif tok in ("--format", "-f") and i + 1 < len(tokens):
            val = tokens[i + 1].lower()
            if val in ("table", "json", "sarif", "text"):
                extra["format"] = val
            else:
                console.print(f"[yellow]Unknown format '{val}'[/yellow]")
            i += 2
        elif tok in ("--severity", "-s", "--min-severity") and i + 1 < len(tokens):
            val = tokens[i + 1].upper()
            if val in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
                extra["severity"] = val
            else:
                console.print(f"[yellow]Unknown severity '{val}'[/yellow]")
            i += 2
        elif tok in ("--history", "-H"):
            extra["history"] = True; i += 1
        elif tok in ("--commits", "-c") and i + 1 < len(tokens):
            try:
                extra["commits"] = int(tokens[i + 1])
            except ValueError:
                pass
            i += 2
        elif not tok.startswith("-"):
            target = tok; i += 1
        else:
            i += 1

    return target, url, extra


def cmd_scan(rest: list[str], state: dict) -> None:
    target, url, extra = parse_scan_args(rest)
    fmt     = extra.get("format",   state["format"])
    min_sev = extra.get("severity", state["severity"])
    history = extra.get("history",  state["history"])
    commits = extra.get("commits",  state["commits"])

    with console.status("[cyan]Scanning…[/cyan]", spinner="dots"):
        try:
            findings = run_scan(
                target=target,
                url=url,
                min_severity=min_sev,
                scan_history=history,
                history_commits=commits,
            )
        except (ValueError, FileNotFoundError) as exc:
            console.print(f"[red]Error:[/red] {exc}")
            return
        except Exception as exc:
            console.print(f"[red]Scan error:[/red] {exc}")
            return

    # Display results
    if fmt == "table":
        findings_table(findings)
    elif fmt == "json":
        from scanner.output.reporting import generate_report
        console.print_json(generate_report(findings, "json"))
    elif fmt == "sarif":
        from scanner.output.reporting import generate_report
        console.print_json(generate_report(findings, "sarif"))
    elif fmt == "text":
        from scanner.output.reporting import generate_report
        console.print(generate_report(findings, "text"))

    # Generate HTML report
    scan_target = target or url or "unknown"
    report_path = save_html_report(findings, target=scan_target)
    console.print(f"\n[dim]📄 HTML report: [cyan]{report_path}[/cyan][/dim]")

    # Update stats
    state["scan_count"] += 1
    state["total_findings"] += len(findings)

    if should_fail(findings, state["fail_on"]):
        console.print(f"[bold red]⚠  CI gate: findings at or above {state['fail_on']} severity detected.[/bold red]")


# ── set ──────────────────────────────────────────────────────────────────────

def cmd_set(tokens: list[str], state: dict) -> None:
    if len(tokens) < 2:
        console.print(
            "[yellow]Usage:[/yellow] set [bold]format[/bold] <table|json|sarif|text>  |  "
            "set [bold]severity[/bold] <LOW|MEDIUM|HIGH|CRITICAL>  |  "
            "set [bold]fail-on[/bold] <LOW|MEDIUM|HIGH|CRITICAL>  |  "
            "set [bold]history[/bold] <on|off>  |  "
            "set [bold]commits[/bold] <n>"
        )
        return

    key, val = tokens[0].lower(), tokens[1]

    if key == "format":
        if val.lower() in ("table", "json", "sarif", "text"):
            state["format"] = val.lower()
            console.print(f"[green]format = {state['format']}[/green]")
        else:
            console.print("[red]Choices: table | json | sarif | text[/red]")

    elif key == "severity":
        if val.upper() in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            state["severity"] = val.upper()
            console.print(f"[green]min-severity = {state['severity']}[/green]")
        else:
            console.print("[red]Choices: LOW | MEDIUM | HIGH | CRITICAL[/red]")

    elif key == "fail-on":
        if val.upper() in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            state["fail_on"] = val.upper()
            console.print(f"[green]fail-on = {state['fail_on']}[/green]")
        else:
            console.print("[red]Choices: LOW | MEDIUM | HIGH | CRITICAL[/red]")

    elif key == "history":
        state["history"] = val.lower() in ("on", "true", "1", "yes")
        console.print(f"[green]history = {'on' if state['history'] else 'off'}[/green]")

    elif key == "commits":
        try:
            state["commits"] = int(val)
            console.print(f"[green]commits = {state['commits']}[/green]")
        except ValueError:
            console.print("[red]commits must be an integer[/red]")

    else:
        console.print(f"[red]Unknown setting '{key}'[/red]")


# ── config ───────────────────────────────────────────────────────────────────

def cmd_config(tokens: list[str], state: dict) -> None:
    sub = tokens[0].lower() if tokens else "show"

    if sub == "show":
        cfg = load_config()
        table = Table(title="[bold]~/.nuclear/config.toml[/bold]", box=box.SIMPLE, show_header=False)
        table.add_column("Key",   style="bold cyan", width=20)
        table.add_column("Value", style="white")
        for k, v in (
            ("format",      cfg.format),
            ("severity",    cfg.severity),
            ("fail_on",     cfg.fail_on),
            ("history",     str(cfg.history).lower()),
            ("commits",     str(cfg.commits)),
            ("output.file", cfg.output_file or "(stdout)"),
            ("thresholds",  f"critical={cfg.threshold_critical} high={cfg.threshold_high} medium={cfg.threshold_medium}"),
            ("custom patterns", str(len(cfg.custom_patterns))),
            ("extra_ignore",    str(len(cfg.extra_ignore))),
        ):
            table.add_row(k, str(v))
        console.print(table)

    elif sub == "path":
        exists = CONFIG_FILE.exists()
        color = "green" if exists else "red"
        console.print(f"[cyan]{CONFIG_FILE}[/cyan]  (exists: [{color}]{exists}[/{color}])")

    elif sub == "init":
        path = save_default_config()
        if path.exists():
            console.print(f"[green]Config file ready:[/green] {path}")
        else:
            console.print(f"[green]Created:[/green] {path}")

    elif sub == "set" and len(tokens) >= 3:
        key, value = tokens[1], tokens[2]
        try:
            set_config_value(key, value)
            _KEY_TO_STATE = {
                "format": "format", "severity": "severity",
                "fail_on": "fail_on", "history": "history", "commits": "commits",
            }
            if key in _KEY_TO_STATE:
                state[_KEY_TO_STATE[key]] = value if key not in ("history",) else value.lower() in ("true", "on", "1", "yes")
            console.print(f"[green]Saved:[/green] {key} = {value}")
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")

    else:
        console.print(
            "[yellow]Usage:[/yellow] config [bold]show[/bold] | config [bold]path[/bold] | "
            "config [bold]init[/bold] | config [bold]set[/bold] <key> <value>"
        )


# ── history ──────────────────────────────────────────────────────────────────

def cmd_history(state: dict) -> None:
    if not state["cmd_history"]:
        console.print("[dim]No commands yet.[/dim]")
        return
    for i, cmd in enumerate(state["cmd_history"], 1):
        console.print(f"[dim]{i:3}[/dim]  {cmd}")


# ── help ─────────────────────────────────────────────────────────────────────

HELP_COMMAND: dict[str, str] = {
    "scan": (
        "[bold green]scan[/bold green] [bold]<path|.zip>[/bold] [dim][options][/dim]\n\n"
        "Scan a local file, directory or .zip archive for secrets.\n"
        "An HTML report is automatically saved to [cyan].nuclear-scan-result/[/cyan]\n\n"
        "[bold]Options:[/bold]\n"
        "  [cyan]--url, -u[/cyan] <url>           Scan a remote Git repo or URL\n"
        "  [cyan]--format, -f[/cyan] <fmt>        Output format: table | json | sarif | text\n"
        "  [cyan]--severity, -s[/cyan] <level>    Min severity: LOW | MEDIUM | HIGH | CRITICAL\n"
        "  [cyan]--history, -H[/cyan]             Include Git commit history\n"
        "  [cyan]--commits, -c[/cyan] <n>         Max commits to scan (default 50)\n\n"
        "[bold]Examples:[/bold]\n"
        "  [dim]scan .[/dim]                          Scan current directory\n"
        "  [dim]scan src/ --severity HIGH[/dim]       Only HIGH+ findings\n"
        "  [dim]scan secrets.zip --format json[/dim]  ZIP archive, JSON output\n"
        "  [dim]scan --url https://github.com/user/repo[/dim]"
    ),
    "set": (
        "[bold green]set[/bold green] [bold]<key> <value>[/bold]\n\n"
        "Change session settings (this session only).\n\n"
        "[bold]Keys:[/bold]\n"
        "  [cyan]format[/cyan]     table | json | sarif | text\n"
        "  [cyan]severity[/cyan]   LOW | MEDIUM | HIGH | CRITICAL\n"
        "  [cyan]fail-on[/cyan]    LOW | MEDIUM | HIGH | CRITICAL\n"
        "  [cyan]history[/cyan]    on | off\n"
        "  [cyan]commits[/cyan]    integer (max commits to scan)\n\n"
        "[bold]Examples:[/bold]\n"
        "  [dim]set format json[/dim]\n"
        "  [dim]set severity HIGH[/dim]\n"
        "  [dim]set fail-on CRITICAL[/dim]"
    ),
    "config": (
        "[bold green]config[/bold green] [bold]<subcommand>[/bold]\n\n"
        "Manage persistent user config (~/.nuclear/config.toml).\n\n"
        "[bold]Subcommands:[/bold]\n"
        "  [cyan]show[/cyan]              Display all config values\n"
        "  [cyan]path[/cyan]              Show config file location\n"
        "  [cyan]init[/cyan]              Create default config file\n"
        "  [cyan]set <key> <val>[/cyan]   Persist a setting to config\n\n"
        "[bold]Config keys:[/bold] format, severity, fail_on, history, commits\n\n"
        "[bold]Examples:[/bold]\n"
        "  [dim]config show[/dim]\n"
        "  [dim]config init[/dim]\n"
        "  [dim]config set severity HIGH[/dim]"
    ),
    "status": (
        "[bold green]status[/bold green]\n\n"
        "Show current session settings:\n"
        "format, min-severity, fail-on, history, commits."
    ),
    "history": (
        "[bold green]history[/bold green]\n\n"
        "Show all commands entered in this session."
    ),
    "clear": (
        "[bold green]clear[/bold green]\n\n"
        "Clear the terminal screen and show the banner."
    ),
    "exit": (
        "[bold green]exit[/bold green] / [bold green]quit[/bold green]\n\n"
        "Exit nuclear REPL with a session summary.\n"
        "You can also press [bold]Ctrl+C[/bold] twice within 2 seconds."
    ),
}


def cmd_help(tokens: list[str]) -> None:
    if tokens and tokens[0] in HELP_COMMAND:
        console.print(Panel(HELP_COMMAND[tokens[0]], border_style="cyan", expand=False, padding=(1, 2)))
        return

    # Compact help overview — no scrolling
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2), expand=False)
    table.add_column("Command", style="bold green", width=28)
    table.add_column("Description", style="white")

    table.add_row("scan <path|.zip> [opts]",  "Scan for secrets (+ HTML report)")
    table.add_row("  --url/-u <url>",         "[dim]Remote Git repo or URL[/dim]")
    table.add_row("  --format/-f <fmt>",      "[dim]table | json | sarif | text[/dim]")
    table.add_row("  --severity/-s <level>",  "[dim]LOW | MEDIUM | HIGH | CRITICAL[/dim]")
    table.add_row("  --history/-H",           "[dim]Include Git history[/dim]")
    table.add_row("  --commits/-c <n>",       "[dim]Max commits (default 50)[/dim]")
    table.add_row("", "")
    table.add_row("set <key> <value>",        "Change session settings")
    table.add_row("config <show|path|init|set>", "Manage persistent config")
    table.add_row("status",                   "Show current settings")
    table.add_row("history",                  "Show command history")
    table.add_row("clear",                    "Clear screen")
    table.add_row("help [command]",           "This help, or help for a command")
    table.add_row("exit / quit",              "Exit nuclear")

    console.print(Panel(
        table,
        title="[bold cyan]☢ nuclear — commands[/bold cyan]",
        border_style="cyan",
        expand=False,
        padding=(0, 1),
    ))

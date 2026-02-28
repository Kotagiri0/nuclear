"""
nuclear REPL — интерактивный терминал для поиска уязвимостей.

Запуск:
    nuclear                      # REPL режим
    .venv\\Scripts\\python.exe -m secret_scanner.repl
"""
from __future__ import annotations

import os
import shlex
import sys
from pathlib import Path
from typing import Optional

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.styles import Style
from rich.columns import Columns
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich import box

from scanner.config import CONFIG_FILE, load_config, save_default_config, set_config_value
from scanner.policy import should_fail
from scanner.runner import run_scan

console = Console()

# ── colour palette ──────────────────────────────────────────────────────────
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


def _build_state() -> dict:
    """Build initial session state from user config."""
    cfg = load_config()
    return {
        "format":      cfg.format if cfg.format in ("table", "json", "sarif", "text") else "table",
        "severity":    cfg.severity,
        "fail_on":     cfg.fail_on,
        "history":     cfg.history,
        "commits":     cfg.commits,
        "cmd_history": [],
    }


# ── global session state ─────────────────────────────────────────────────────
_state: dict = {}  # populated in run()

# ── helpers ──────────────────────────────────────────────────────────────────

def _banner() -> None:
    console.print(Panel.fit(
        "[bold cyan]☢  nuclear[/bold cyan]  [dim]secret & vulnerability scanner REPL[/dim]\n"
        "Type [bold green]help[/bold green] to see commands  •  "
        "[bold green]scan <path>[/bold green] to start  •  "
        "[bold green]exit[/bold green] to quit",
        border_style="cyan",
    ))


def _findings_table(findings: list) -> None:
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


def _do_scan(target_str: Optional[str], url: Optional[str], extra: dict) -> None:
    fmt      = extra.get("format",   _state["format"])
    min_sev  = extra.get("severity", _state["severity"])
    history  = extra.get("history",  _state["history"])
    commits  = extra.get("commits",  _state["commits"])

    with console.status("[cyan]Scanning…[/cyan]", spinner="dots"):
        try:
            findings = run_scan(
                target=target_str,
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

    if fmt == "table":
        _findings_table(findings)
    elif fmt == "json":
        from scanner.reporting import generate_report
        console.print_json(generate_report(findings, "json"))
    elif fmt == "sarif":
        from scanner.reporting import generate_report
        console.print_json(generate_report(findings, "sarif"))
    elif fmt == "text":
        from scanner.reporting import generate_report
        console.print(generate_report(findings, "text"))

    if should_fail(findings, _state["fail_on"]):
        console.print(f"\n[bold red]⚠  CI gate: findings at or above {_state['fail_on']} severity detected.[/bold red]")


# ── command parser ────────────────────────────────────────────────────────────

def _parse_scan_args(tokens: list[str]) -> tuple[Optional[str], Optional[str], dict]:
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
                console.print(f"[yellow]Unknown format '{val}', using '{_state['format']}'[/yellow]")
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


def _cmd_set(tokens: list[str]) -> None:
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
            _state["format"] = val.lower()
            console.print(f"[green]format = {_state['format']}[/green]")
        else:
            console.print("[red]Choices: table | json | sarif | text[/red]")

    elif key == "severity":
        if val.upper() in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            _state["severity"] = val.upper()
            console.print(f"[green]min-severity = {_state['severity']}[/green]")
        else:
            console.print("[red]Choices: LOW | MEDIUM | HIGH | CRITICAL[/red]")

    elif key == "fail-on":
        if val.upper() in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            _state["fail_on"] = val.upper()
            console.print(f"[green]fail-on = {_state['fail_on']}[/green]")
        else:
            console.print("[red]Choices: LOW | MEDIUM | HIGH | CRITICAL[/red]")

    elif key == "history":
        _state["history"] = val.lower() in ("on", "true", "1", "yes")
        console.print(f"[green]history = {'on' if _state['history'] else 'off'}[/green]")

    elif key == "commits":
        try:
            _state["commits"] = int(val)
            console.print(f"[green]commits = {_state['commits']}[/green]")
        except ValueError:
            console.print("[red]commits must be an integer[/red]")

    else:
        console.print(f"[red]Unknown setting '{key}'[/red]")


def _cmd_status() -> None:
    table = Table(title="[bold]Session settings[/bold]", box=box.SIMPLE, show_header=False)
    table.add_column("Key",   style="bold cyan", width=16)
    table.add_column("Value", style="white")
    for k, v in (
        ("format",      _state["format"]),
        ("min-severity", _state["severity"]),
        ("fail-on",     _state["fail_on"]),
        ("history",     "on" if _state["history"] else "off"),
        ("commits",     str(_state["commits"])),
    ):
        table.add_row(k, str(v))
    console.print(table)


def _cmd_history() -> None:
    if not _state["cmd_history"]:
        console.print("[dim]No commands yet.[/dim]")
        return
    for i, cmd in enumerate(_state["cmd_history"], 1):
        console.print(f"[dim]{i:3}[/dim]  {cmd}")


def _cmd_config(tokens: list[str]) -> None:
    """Handle `config` subcommands: show | path | init | set <key> <value>."""
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
        console.print(f"[cyan]{CONFIG_FILE}[/cyan]  (exists: [{'green' if CONFIG_FILE.exists() else 'red'}]{CONFIG_FILE.exists()}[/])")

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
            # Also update the live session state where applicable
            _KEY_TO_STATE = {
                "format": "format", "severity": "severity",
                "fail_on": "fail_on", "history": "history", "commits": "commits",
            }
            if key in _KEY_TO_STATE:
                _state[_KEY_TO_STATE[key]] = value if key not in ("history",) else value.lower() in ("true", "on", "1", "yes")
            console.print(f"[green]Saved:[/green] {key} = {value}")
        except ValueError as exc:
            console.print(f"[red]{exc}[/red]")

    else:
        console.print(
            "[yellow]Usage:[/yellow] config [bold]show[/bold] | config [bold]path[/bold] | "
            "config [bold]init[/bold] | config [bold]set[/bold] <key> <value>"
        )


HELP_TEXT = """
[bold cyan]☢  nuclear REPL — commands[/bold cyan]

[bold green]scan[/bold green] [bold]<path|.zip>[/bold]              Scan a file, directory or zip archive
     [dim]--url <url>[/dim]                   Scan a remote Git repo or URL
     [dim]--format <table|json|sarif|text>[/dim]  Output format (overrides session setting)
     [dim]--severity <LOW|MEDIUM|HIGH|CRITICAL>[/dim]  Min severity to show
     [dim]--history[/dim]                      Include Git commit history
     [dim]--commits <n>[/dim]                 Max commits to scan (default 50)

[bold green]set[/bold green] [bold]<key> <value>[/bold]             Change session settings (this session only)
     Keys: format · severity · fail-on · history · commits
     Example: set format json
              set severity HIGH

[bold green]config[/bold green] [bold]<subcommand>[/bold]           Manage persistent user config (~/.nuclear/config.toml)
     [dim]config show[/dim]                   Display current config values
     [dim]config path[/dim]                   Show config file location
     [dim]config init[/dim]                   Create default config file
     [dim]config set <key> <value>[/dim]      Save a value to config file

[bold green]status[/bold green]                           Show current session settings

[bold green]history[/bold green]                          Show command history for this session

[bold green]clear[/bold green]                            Clear the screen

[bold green]help[/bold green] [bold][command][/bold]                This help, or help for a specific command

[bold green]exit[/bold green] / [bold green]quit[/bold green]                   Exit nuclear

─────────────────────────────────────────────────────
[dim]Examples:[/dim]
  scan .                          Scan current directory
  scan src/ --severity HIGH
  scan secrets.zip --format json
  scan --url https://github.com/user/repo --history
  set format table
  set fail-on CRITICAL
  config show
  config set severity HIGH
"""

HELP_COMMAND: dict[str, str] = {
    "scan": (
        "[bold]scan <target> [options][/bold]\n\n"
        "Scan a local file, directory or .zip archive for secrets.\n"
        "Options same as shown in [bold]help[/bold]."
    ),
    "set": (
        "[bold]set <key> <value>[/bold]\n\n"
        "Keys:\n"
        "  format   — table | json | sarif | text\n"
        "  severity — LOW | MEDIUM | HIGH | CRITICAL\n"
        "  fail-on  — LOW | MEDIUM | HIGH | CRITICAL\n"
        "  history  — on | off\n"
        "  commits  — integer\n"
    ),
    "config": (
        "[bold]config <subcommand>[/bold]\n\n"
        "Subcommands:\n"
        "  show              — display all config values\n"
        "  path              — show config file location\n"
        "  init              — create default ~/.nuclear/config.toml\n"
        "  set <key> <value> — persist a setting to the config file\n\n"
        "Supported keys for 'config set': format, severity, fail_on, history, commits\n"
    ),
}


def _cmd_help(tokens: list[str]) -> None:
    if tokens and tokens[0] in HELP_COMMAND:
        console.print(Panel(HELP_COMMAND[tokens[0]], border_style="cyan"))
    else:
        console.print(Panel(HELP_TEXT, border_style="cyan", expand=False))


# ── REPL loop ─────────────────────────────────────────────────────────────────

_COMPLETIONS = [
    "scan", "set", "config", "status", "history", "clear", "help", "exit", "quit",
    "--url", "--format", "--severity", "--history", "--commits",
    "format", "severity", "fail-on", "commits",
    "table", "json", "sarif", "text",
    "LOW", "MEDIUM", "HIGH", "CRITICAL",
    "on", "off",
    "show", "path", "init",
]


def run() -> None:
    """Entry point for the nuclear REPL."""
    global _state
    _state = _build_state()
    _banner()

    completer = WordCompleter(_COMPLETIONS, ignore_case=True, sentence=False)
    session: PromptSession = PromptSession(
        history=InMemoryHistory(),
        auto_suggest=AutoSuggestFromHistory(),
        completer=completer,
        style=PROMPT_STYLE,
        complete_while_typing=True,
    )

    while True:
        try:
            raw = session.prompt(
                [("class:prompt.sign", "☢ "), ("class:prompt", "nuclear"), ("", " ❯ ")],
            )
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]Bye![/dim]")
            break

        raw = raw.strip()
        if not raw:
            continue

        _state["cmd_history"].append(raw)

        try:
            tokens = shlex.split(raw)
        except ValueError as exc:
            console.print(f"[red]Parse error:[/red] {exc}")
            continue

        cmd, *rest = tokens

        if cmd in ("exit", "quit"):
            console.print("[dim]Bye![/dim]")
            break

        elif cmd == "scan":
            target, url, extra = _parse_scan_args(rest)
            _do_scan(target, url, extra)

        elif cmd == "set":
            _cmd_set(rest)

        elif cmd == "status":
            _cmd_status()

        elif cmd == "history":
            _cmd_history()

        elif cmd == "clear":
            os.system("cls" if sys.platform == "win32" else "clear")

        elif cmd == "config":
            _cmd_config(rest)

        elif cmd in ("help", "?"):
            _cmd_help(rest)

        else:
            console.print(
                f"[yellow]Unknown command:[/yellow] [bold]{cmd}[/bold]  "
                "(type [bold green]help[/bold green] for a list)"
            )

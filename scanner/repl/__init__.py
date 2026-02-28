"""
nuclear REPL — интерактивный терминал для поиска уязвимостей.

Запуск:
    python -m scanner           # REPL режим
    nuclear                     # если установлен через pip
"""
from __future__ import annotations

import shlex
import sys
import time

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.history import InMemoryHistory

from scanner.config import load_config
from scanner.repl.commands import cmd_config, cmd_help, cmd_history, cmd_scan, cmd_set
from scanner.repl.completer import NuclearCompleter
from scanner.repl.ui import banner, console, session_summary, status_table, PROMPT_STYLE


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
        "scan_count":  0,
        "total_findings": 0,
    }


def run() -> None:
    """Entry point for the nuclear REPL."""
    # Ensure stdout supports Unicode on Windows
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")

    state = _build_state()
    banner()

    completer = NuclearCompleter()
    session: PromptSession = PromptSession(
        history=InMemoryHistory(),
        auto_suggest=AutoSuggestFromHistory(),
        completer=completer,
        style=PROMPT_STYLE,
        complete_while_typing=True,
    )

    _last_interrupt: float = 0.0

    while True:
        try:
            raw = session.prompt(
                [("class:prompt.sign", "☢ "), ("class:prompt", "nuclear"), ("", " > ")],
            )
        except KeyboardInterrupt:
            now = time.time()
            if now - _last_interrupt < 2.0:
                session_summary(state)
                break
            _last_interrupt = now
            console.print("\n[yellow]Нажмите Ctrl+C ещё раз в течение 2 сек для выхода[/yellow]")
            continue
        except EOFError:
            continue

        raw = raw.strip()
        if not raw:
            continue

        # Reset interrupt timer on any valid input
        _last_interrupt = 0.0

        state["cmd_history"].append(raw)

        try:
            tokens = shlex.split(raw)
        except ValueError as exc:
            console.print(f"[red]Parse error:[/red] {exc}")
            continue

        cmd, *rest = tokens

        if cmd in ("exit", "quit"):
            session_summary(state)
            break

        elif cmd == "scan":
            cmd_scan(rest, state)

        elif cmd == "set":
            cmd_set(rest, state)

        elif cmd == "status":
            status_table(state)

        elif cmd == "history":
            cmd_history(state)

        elif cmd == "clear":
            console.clear()
            banner()

        elif cmd == "config":
            cmd_config(rest, state)

        elif cmd in ("help", "?"):
            cmd_help(rest)

        else:
            console.print(
                f"[yellow]Unknown command:[/yellow] [bold]{cmd}[/bold]  "
                "(type [bold green]help[/bold green] for a list)"
            )

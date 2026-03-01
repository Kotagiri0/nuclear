"""Contextual auto-completer for the nuclear REPL."""
from __future__ import annotations

import os
from pathlib import Path

from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.document import Document


# Command definitions with their arguments
COMMANDS = {
    "scan":    "Scan a file, directory or zip archive for secrets",
    "set":     "Change session settings (format, severity, etc.)",
    "config":  "Manage persistent user config (~/.nuclear/config.toml)",
    "status":  "Show current session settings",
    "history": "Show command history for this session",
    "clear":   "Clear the screen",
    "help":    "Show help for commands",
    "exit":    "Exit nuclear REPL",
    "quit":    "Exit nuclear REPL",
}

SCAN_ARGS = {
    "--url":       "Scan a remote Git repo or URL",
    "--format":    "Output format (table|json|sarif|text)",
    "--severity":  "Min severity to show (LOW|MEDIUM|HIGH|CRITICAL)",
    "--history":   "Include Git commit history",
    "--commits":   "Max commits to scan (default 50)",
    "--quiet":     "Show only summary, save full report to file",
    "-u":          "Short for --url",
    "-f":          "Short for --format",
    "-s":          "Short for --severity",
    "-H":          "Short for --history",
    "-c":          "Short for --commits",
    "-q":          "Short for --quiet",
}

SET_KEYS = {
    "format":   "Output format (table|json|sarif|text)",
    "severity": "Min severity level (LOW|MEDIUM|HIGH|CRITICAL)",
    "fail-on":  "CI gate threshold (LOW|MEDIUM|HIGH|CRITICAL)",
    "history":  "Scan git history (on|off)",
    "commits":  "Max commits to scan (integer)",
}

CONFIG_SUBS = {
    "show":  "Display current config values",
    "path":  "Show config file location",
    "init":  "Create default config file",
    "set":   "Save a value to config file",
}

FORMAT_VALUES = ["table", "json", "sarif", "text"]
SEVERITY_VALUES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
BOOL_VALUES = ["on", "off"]

FORMAT_META = {
    "table": "Rich table",
    "json":  "JSON output",
    "sarif": "SARIF 2.1",
    "text":  "Plain text",
}

SEVERITY_META = {
    "LOW":      "Score < 5",
    "MEDIUM":   "Score 5–7",
    "HIGH":     "Score 8–11",
    "CRITICAL": "Score 12+",
}

BOOL_META = {
    "on":  "Enable",
    "off": "Disable",
}

HELP_TOPICS = list(COMMANDS.keys())


class NuclearCompleter(Completer):
    """Context-aware completer that separates commands from arguments."""

    def get_completions(self, document: Document, complete_event):
        text = document.text_before_cursor
        words = text.split()

        # Empty or first word → suggest commands only
        if not words or (len(words) == 1 and not text.endswith(" ")):
            prefix = words[0] if words else ""
            for cmd, desc in COMMANDS.items():
                if cmd.startswith(prefix):
                    yield Completion(cmd, start_position=-len(prefix), display_meta=desc)
            return

        cmd = words[0].lower()
        # Determine what we're currently typing
        current = words[-1] if not text.endswith(" ") else ""
        prev = words[-1] if text.endswith(" ") else (words[-2] if len(words) > 1 else "")

        if cmd == "scan":
            yield from self._complete_scan(current, prev, text)
        elif cmd == "set":
            yield from self._complete_set(words, current, text)
        elif cmd == "config":
            yield from self._complete_config(words, current, text)
        elif cmd in ("help", "?"):
            yield from self._complete_help(current)

    def _complete_scan(self, current: str, prev: str, text: str):
        # After --format → suggest format values
        if prev in ("--format", "-f"):
            for v in FORMAT_VALUES:
                if v.startswith(current.lower()):
                    yield Completion(v, start_position=-len(current), display_meta=FORMAT_META.get(v, ""))
            return
        # After --severity → suggest severity values
        if prev in ("--severity", "-s", "--min-severity"):
            for v in SEVERITY_VALUES:
                if v.startswith(current.upper()):
                    yield Completion(v, start_position=-len(current), display_meta=SEVERITY_META.get(v, ""))
            return
        # Suggest scan arguments (flags)
        if current.startswith("-"):
            for arg, desc in SCAN_ARGS.items():
                if arg.startswith(current):
                    yield Completion(arg, start_position=-len(current), display_meta=desc)
            return
        # Suggest filesystem paths (directories and files)
        yield from self._complete_path(current)

    def _complete_set(self, words: list, current: str, text: str):
        # After "set" → suggest keys
        if len(words) <= 2 and not (len(words) == 2 and text.endswith(" ")):
            prefix = current
            for key, desc in SET_KEYS.items():
                if key.startswith(prefix):
                    yield Completion(key, start_position=-len(prefix), display_meta=desc)
            return
        # After "set format" → suggest format values
        key = words[1].lower() if len(words) > 1 else ""
        if key == "format":
            for v in FORMAT_VALUES:
                if v.startswith(current.lower()):
                    yield Completion(v, start_position=-len(current), display_meta=FORMAT_META.get(v, ""))
        elif key in ("severity", "fail-on"):
            for v in SEVERITY_VALUES:
                if v.startswith(current.upper()):
                    yield Completion(v, start_position=-len(current), display_meta=SEVERITY_META.get(v, ""))
        elif key == "history":
            for v in BOOL_VALUES:
                if v.startswith(current.lower()):
                    yield Completion(v, start_position=-len(current), display_meta=BOOL_META.get(v, ""))

    def _complete_config(self, words: list, current: str, text: str):
        # After "config" → suggest subcommands
        if len(words) <= 2 and not (len(words) == 2 and text.endswith(" ")):
            prefix = current
            for sub, desc in CONFIG_SUBS.items():
                if sub.startswith(prefix):
                    yield Completion(sub, start_position=-len(prefix), display_meta=desc)
            return
        # After "config set" → suggest config keys
        sub = words[1].lower() if len(words) > 1 else ""
        if sub == "set":
            config_keys = {"format": "Output format", "severity": "Min severity", "fail_on": "CI gate", "history": "Git history", "commits": "Max commits"}
            if len(words) <= 3 and not (len(words) == 3 and text.endswith(" ")):
                for key, desc in config_keys.items():
                    if key.startswith(current):
                        yield Completion(key, start_position=-len(current), display_meta=desc)
            else:
                # After "config set <key>" → suggest values
                cfg_key = words[2].lower() if len(words) > 2 else ""
                if cfg_key == "format":
                    for v in FORMAT_VALUES:
                        if v.startswith(current.lower()):
                            yield Completion(v, start_position=-len(current), display_meta=FORMAT_META.get(v, ""))
                elif cfg_key in ("severity", "fail_on"):
                    for v in SEVERITY_VALUES:
                        if v.startswith(current.upper()):
                            yield Completion(v, start_position=-len(current), display_meta=SEVERITY_META.get(v, ""))
                elif cfg_key == "history":
                    for v in BOOL_VALUES:
                        if v.startswith(current.lower()):
                            yield Completion(v, start_position=-len(current), display_meta=BOOL_META.get(v, ""))

    def _complete_path(self, current: str):
        """Suggest filesystem paths for scan target."""
        try:
            if current:
                p = Path(current)
                if p.is_dir() and current.endswith(("/", "\\")):
                    base_dir, prefix = p, ""
                else:
                    base_dir, prefix = p.parent, p.name
            else:
                base_dir, prefix = Path("."), ""

            if not base_dir.is_dir():
                return

            for entry in sorted(base_dir.iterdir()):
                name = entry.name
                if name.startswith(".") and not prefix.startswith("."):
                    continue
                if not name.lower().startswith(prefix.lower()):
                    continue

                display = str(base_dir / name) if current and base_dir != Path(".") else name
                if entry.is_dir():
                    yield Completion(
                        display + "/",
                        start_position=-len(current),
                        display_meta="directory",
                    )
                else:
                    yield Completion(
                        display,
                        start_position=-len(current),
                        display_meta="file",
                    )
        except OSError:
            return

    def _complete_help(self, current: str):
        for topic in HELP_TOPICS:
            if topic.startswith(current):
                desc = COMMANDS.get(topic, "")
                yield Completion(topic, start_position=-len(current), display_meta=desc)

"""
User configuration for Nuclear Secret Scanner.

Config file location: ~/.nuclear/config.toml
Priority: CLI flags > ENV variables > config.toml > built-in defaults
"""
from __future__ import annotations

import os
import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

# ── default config file location ─────────────────────────────────────────────
CONFIG_DIR = Path.home() / ".nuclear"
CONFIG_FILE = CONFIG_DIR / "config.toml"

_DEFAULT_TOML = """\
# Nuclear Secret Scanner — user configuration
# Priority: CLI flags > ENV variables > this file > built-in defaults

[defaults]
# Output format: text | json | sarif | table (table is REPL-only)
format = "text"
# Minimum severity to show: LOW | MEDIUM | HIGH | CRITICAL
severity = "LOW"
# CI gate — fail with exit code 1 when findings reach this level
fail_on = "HIGH"
# Scan git history by default
history = false
# Max commits to scan in history mode
commits = 50

[thresholds]
# Score thresholds for severity levels
critical = 12
high = 8
medium = 5

[output]
# Default output file path (empty = stdout)
file = ""
# Append ISO timestamp to output filename: report_{timestamp}.json
timestamp = false

[ignore]
# Extra false-positive keywords (added to built-in IGNORE_PATTERNS)
extra_ignore = []
# Extra file extensions to skip, e.g. [".backup", ".snap"]
extra_skip_extensions = []
# Extra directory names to skip, e.g. ["terraform", "infra"]
extra_skip_dirs = []

# Custom patterns — uncomment and fill to add your own detection rules
# [[patterns.custom]]
# name     = "My Corp Token"
# regex    = "CORP_[A-Z0-9]{32}"
# score    = 8
# category = "api_key"
"""


@dataclass
class CustomPattern:
    name: str
    regex: str
    score: int = 5
    category: str = "api_key"


@dataclass
class NuclearConfig:
    # [defaults]
    format: str = "text"
    severity: str = "LOW"
    fail_on: str = "HIGH"
    history: bool = False
    commits: int = 50
    # [thresholds]
    threshold_critical: int = 12
    threshold_high: int = 8
    threshold_medium: int = 5
    # [output]
    output_file: str = ""
    output_timestamp: bool = False
    # [ignore]
    extra_ignore: list[str] = field(default_factory=list)
    extra_skip_extensions: list[str] = field(default_factory=list)
    extra_skip_dirs: list[str] = field(default_factory=list)
    # [[patterns.custom]]
    custom_patterns: list[CustomPattern] = field(default_factory=list)


# ── TOML loader (stdlib tomllib ≥3.11, else tomli fallback) ──────────────────

def _load_toml(path: Path) -> dict:
    try:
        import tomllib  # type: ignore[import]
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[import,no-redef]
        except ImportError:
            return {}
    with path.open("rb") as f:
        return tomllib.load(f)


# ── public API ────────────────────────────────────────────────────────────────

def load_config(path: Optional[Path] = None) -> NuclearConfig:
    """Load NuclearConfig from *path* (defaults to ~/.nuclear/config.toml).

    Missing keys fall back to built-in defaults.
    ENV variables override file values (NUCLEAR_FORMAT, NUCLEAR_SEVERITY,
    NUCLEAR_FAIL_ON, NUCLEAR_HISTORY, NUCLEAR_COMMITS, NUCLEAR_OUTPUT).
    """
    cfg_path = path or CONFIG_FILE
    raw: dict = {}
    if cfg_path.exists():
        try:
            raw = _load_toml(cfg_path)
        except Exception:  # noqa: BLE001 — tomllib raises various errors
            warnings.warn(
                f"[nuclear] Could not parse config file {cfg_path!s}; using defaults.",
                stacklevel=2,
            )

    defaults = raw.get("defaults", {})
    thresholds = raw.get("thresholds", {})
    output = raw.get("output", {})
    ignore = raw.get("ignore", {})
    patterns_section = raw.get("patterns", {})

    custom_patterns: list[CustomPattern] = []
    for p in patterns_section.get("custom", []):
        if "name" in p and "regex" in p:
            # Validate regex before accepting
            try:
                re.compile(p["regex"])
            except re.error as exc:
                warnings.warn(
                    f"[nuclear] Invalid regex in custom pattern '{p['name']}': {exc}; skipping.",
                    stacklevel=2,
                )
                continue
            custom_patterns.append(
                CustomPattern(
                    name=p["name"],
                    regex=p["regex"],
                    score=int(p.get("score", 5)),
                    category=p.get("category", "api_key"),
                )
            )

    cfg = NuclearConfig(
        format=defaults.get("format", "text"),
        severity=defaults.get("severity", "LOW"),
        fail_on=defaults.get("fail_on", "HIGH"),
        history=bool(defaults.get("history", False)),
        commits=int(defaults.get("commits", 50)),
        threshold_critical=int(thresholds.get("critical", 12)),
        threshold_high=int(thresholds.get("high", 8)),
        threshold_medium=int(thresholds.get("medium", 5)),
        output_file=str(output.get("file", "")),
        output_timestamp=bool(output.get("timestamp", False)),
        extra_ignore=list(ignore.get("extra_ignore", [])),
        extra_skip_extensions=list(ignore.get("extra_skip_extensions", [])),
        extra_skip_dirs=list(ignore.get("extra_skip_dirs", [])),
        custom_patterns=custom_patterns,
    )

    # ENV overrides
    _apply_env(cfg)
    return cfg


def _apply_env(cfg: NuclearConfig) -> None:
    """Apply NUCLEAR_* environment variable overrides in-place."""
    if v := os.environ.get("NUCLEAR_FORMAT"):
        cfg.format = v
    if v := os.environ.get("NUCLEAR_SEVERITY"):
        cfg.severity = v.upper()
    if v := os.environ.get("NUCLEAR_FAIL_ON"):
        cfg.fail_on = v.upper()
    if v := os.environ.get("NUCLEAR_HISTORY"):
        cfg.history = v.lower() in ("1", "true", "yes")
    if v := os.environ.get("NUCLEAR_COMMITS"):
        try:
            cfg.commits = int(v)
        except ValueError:
            pass
    if v := os.environ.get("NUCLEAR_OUTPUT"):
        cfg.output_file = v


def save_default_config(path: Optional[Path] = None) -> Path:
    """Create the default config file if it does not already exist.

    Returns the path where the file was written (or already existed).
    """
    cfg_path = path or CONFIG_FILE
    if cfg_path.exists():
        return cfg_path
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(_DEFAULT_TOML, encoding="utf-8")
    return cfg_path


def set_config_value(key: str, value: str, path: Optional[Path] = None) -> None:
    """Persist a single key=value into the config file.

    Creates the config file with defaults first if it does not exist.
    Only flat keys under [defaults] and [output] are supported by this helper.
    """
    cfg_path = save_default_config(path)
    lines = cfg_path.read_text(encoding="utf-8").splitlines(keepends=True)

    _SECTION_KEYS = {
        "format": "defaults",
        "severity": "defaults",
        "fail_on": "defaults",
        "history": "defaults",
        "commits": "defaults",
        "file": "output",
        "timestamp": "output",
    }
    if key not in _SECTION_KEYS:
        raise ValueError(f"Unknown config key: {key!r}")

    # Value quoting: strings get quotes, booleans/ints stay bare
    def _toml_value(v: str) -> str:
        if v.lower() in ("true", "false"):
            return v.lower()
        try:
            int(v)
            return v
        except ValueError:
            pass
        return f'"{v}"'

    toml_val = _toml_value(value)
    target_section = _SECTION_KEYS[key]
    in_section = False
    replaced = False
    new_lines: list[str] = []

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("[") and not stripped.startswith("[["):
            section_name = stripped.strip("[]").strip()
            in_section = section_name == target_section
        if in_section and stripped.startswith(f"{key}") and "=" in stripped:
            line = f"{key} = {toml_val}\n"
            replaced = True
        new_lines.append(line)

    if not replaced:
        # Append key under the correct section
        result: list[str] = []
        in_section = False
        inserted = False
        for i, line in enumerate(new_lines):
            result.append(line)
            stripped = line.strip()
            if stripped.startswith("[") and not stripped.startswith("[["):
                section_name = stripped.strip("[]").strip()
                if in_section and not inserted:
                    result.insert(-1, f"{key} = {toml_val}\n")
                    inserted = True
                in_section = section_name == target_section
        if in_section and not inserted:
            result.append(f"{key} = {toml_val}\n")
        new_lines = result

    cfg_path.write_text("".join(new_lines), encoding="utf-8")

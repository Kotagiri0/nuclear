from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(path: str | Path = ".env", *, override: bool = False) -> bool:
    """Load simple KEY=VALUE pairs from a .env file into os.environ.

    - Ignores blank lines and comments starting with '#'
    - Supports optional 'export KEY=VALUE' prefix
    - Does not expand variables or interpret escapes
    - Does not override existing env vars unless override=True
    """
    p = Path(path)
    if not p.exists() or not p.is_file():
        return False

    try:
        raw = p.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False

    changed = False
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if s.startswith("export "):
            s = s[len("export ") :].lstrip()
        if "=" not in s:
            continue
        key, value = s.split("=", 1)
        key = key.strip()
        if not key:
            continue

        value = value.strip()
        if (value.startswith('"') and value.endswith('"')) or (value.startswith("'") and value.endswith("'")):
            value = value[1:-1]

        if not override and key in os.environ:
            continue
        os.environ[key] = value
        changed = True

    return changed


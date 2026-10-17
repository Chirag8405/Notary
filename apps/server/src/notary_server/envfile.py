"""Load a `.env` file into the process environment (a local convenience, never required).

The file holds `NAME=value` lines; blank lines and `#` comments are skipped, a value may be
wrapped in one pair of quotes, and a name already set in the environment wins over the file.
Values are never logged or returned. `.env` is git-ignored; `.env.example` shows the names.
"""

import os
from collections.abc import MutableMapping
from pathlib import Path

ENV_FILE_NAME = ".env"


def find_env_file(start: Path) -> Path | None:
    """The nearest `.env` in `start` or one of its parents."""
    for directory in (start, *start.parents):
        candidate = directory / ENV_FILE_NAME
        if candidate.is_file():
            return candidate
    return None


def parse_env(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        name, _, raw = stripped.partition("=")
        name = name.removeprefix("export ").strip()
        value = raw.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if name:
            values[name] = value
    return values


def load_env_file(
    path: Path | None = None, environ: MutableMapping[str, str] | None = None
) -> list[str]:
    """Set the names in the file that are not set (or are empty) in `environ`.

    Returns the names it set. With no `path` it looks for `.env` upward from the working
    directory; no file is not an error.
    """
    target = os.environ if environ is None else environ
    file = path if path is not None else find_env_file(Path.cwd())
    if file is None or not file.is_file():
        return []
    applied: list[str] = []
    for name, value in parse_env(file.read_text(encoding="utf-8")).items():
        if value and not target.get(name):
            target[name] = value
            applied.append(name)
    return applied

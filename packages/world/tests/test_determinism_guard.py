"""`notary_world` has no import-linter purity contract, so this scan enforces determinism."""

import ast
from pathlib import Path

import pytest

import notary_world

FORBIDDEN_ROOTS = {
    "time", "datetime", "socket", "urllib", "http", "requests", "httpx", "aiohttp",
    "subprocess", "secrets", "uuid",
}  # fmt: skip
FORBIDDEN_ATTRIBUTES = {("os", "environ"), ("os", "getenv")}
EXEMPT_FILES = {"loader.py"}
"""`loader.py` reads the fixture files, the only file I/O allowed inside `notary_world`."""


def scan(source: str) -> list[str]:
    """Violations of the determinism rules in `source`, as `line what` strings."""
    found: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            found.extend(
                f"{node.lineno} imports {alias.name}"
                for alias in node.names
                if alias.name.split(".")[0] in FORBIDDEN_ROOTS
            )
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            if node.module.split(".")[0] in FORBIDDEN_ROOTS:
                found.append(f"{node.lineno} imports {node.module}")
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            if (node.value.id, node.attr) in FORBIDDEN_ATTRIBUTES:
                found.append(f"{node.lineno} uses {node.value.id}.{node.attr}")
            elif node.value.id == "random" and node.attr != "Random":
                found.append(f"{node.lineno} uses random.{node.attr}")
    return found


def _source_files() -> list[Path]:
    root = Path(notary_world.__file__).parent
    return sorted(p for p in root.glob("*.py") if p.name not in EXEMPT_FILES)


@pytest.mark.invariant("I6")
def test_world_sources_have_no_ambient_nondeterminism() -> None:
    violations = [
        f"{path.name}:{hit}"
        for path in _source_files()
        for hit in scan(path.read_text(encoding="utf-8"))
    ]
    assert violations == []


@pytest.mark.invariant("I6")
@pytest.mark.parametrize(
    "source",
    [
        "import time",
        "from datetime import datetime",
        "import os\nos.environ",
        "import os\nos.getenv('X')",
        "import random\nrandom.random()",
    ],
)
def test_guard_detects_a_planted_violation(source: str) -> None:
    assert scan(source) != []


@pytest.mark.invariant("I6")
def test_guard_accepts_an_explicitly_seeded_random_instance() -> None:
    assert scan("import random\nrandom.Random(3)") == []

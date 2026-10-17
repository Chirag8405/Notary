"""notary_core must stay pure: no I/O, networking, randomness, clock or LLM SDKs."""

import ast
from pathlib import Path

import notary_core

FORBIDDEN_ROOTS = {
    "socket", "http", "urllib", "requests", "httpx", "aiohttp", "subprocess", "random",
    "time", "datetime", "secrets", "asyncio", "threading", "multiprocessing", "ssl",
    "anthropic", "groq", "openai", "langchain", "litellm", "cohere", "mistralai", "google",
}  # fmt: skip
ALLOWED_THIRD_PARTY = {"pydantic"}
FORBIDDEN_ATTRIBUTES = {("os", "environ"), ("os", "getenv")}


def _source_files() -> list[Path]:
    root = Path(notary_core.__file__).parent
    return sorted(root.rglob("*.py"))


def _imported_roots(tree: ast.AST) -> list[tuple[str, int]]:
    found: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.extend((alias.name, node.lineno) for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None and node.level == 0:
            found.append((node.module, node.lineno))
    return found


def test_no_forbidden_imports() -> None:
    violations: list[str] = []
    for path in _source_files():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for module, lineno in _imported_roots(tree):
            if module.split(".")[0] in FORBIDDEN_ROOTS:
                violations.append(f"{path.name}:{lineno} imports {module}")
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == "os":
                for alias in node.names:
                    if ("os", alias.name) in FORBIDDEN_ATTRIBUTES:
                        violations.append(f"{path.name}:{node.lineno} imports os.{alias.name}")
            if (
                isinstance(node, ast.Attribute)
                and isinstance(node.value, ast.Name)
                and (node.value.id, node.attr) in FORBIDDEN_ATTRIBUTES
            ):
                violations.append(f"{path.name}:{node.lineno} uses {node.value.id}.{node.attr}")
    assert not violations, "\n".join(violations)


def test_only_stdlib_and_pydantic_imports() -> None:
    import sys

    stdlib = set(sys.stdlib_module_names)
    violations: list[str] = []
    for path in _source_files():
        for module, lineno in _imported_roots(ast.parse(path.read_text(encoding="utf-8"))):
            root = module.split(".")[0]
            if root not in stdlib and root not in ALLOWED_THIRD_PARTY and root != "notary_core":
                violations.append(f"{path.name}:{lineno} imports {module}")
    assert not violations, "\n".join(violations)

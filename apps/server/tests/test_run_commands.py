"""Every command that runs the server agrees (#235).

The read-token log filter covers the loggers of one WebSocket implementation, and the broker state
and the token key live in one process. So `--ws websockets` is pinned and the server runs with one
worker in the dev script, the Dockerfile and the compose file, and the three must not drift.
"""

import json
import re
import shlex
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
APP = "notary_server.app:app"


def parse(argv: list[str]) -> dict[str, str]:
    """`uvicorn APP --opt value ...` as a dict; a flag without a value maps to "". The program and
    the app target are keys `uvicorn` and `app`."""
    assert "uvicorn" in argv, argv
    rest = argv[argv.index("uvicorn") + 1 :]
    options: dict[str, str] = {"app": rest[0]}
    index = 1
    while index < len(rest):
        name = rest[index]
        assert name.startswith("--"), name
        if index + 1 < len(rest) and not rest[index + 1].startswith("--"):
            options[name] = rest[index + 1]
            index += 2
        else:
            options[name] = ""
            index += 1
    return options


def dev_command() -> dict[str, str]:
    scripts = json.loads((ROOT / "apps/server/package.json").read_text())["scripts"]
    return parse(shlex.split(scripts["dev"]))


def dockerfile_command() -> dict[str, str]:
    text = (ROOT / "apps/server/Dockerfile").read_text()
    (line,) = [ln for ln in text.splitlines() if ln.startswith("CMD ")]
    return parse(json.loads(line.removeprefix("CMD ")))


def compose_command() -> dict[str, str]:
    """The `command:` list of the `server` service. There is no YAML parser in the environment,
    so read the bracketed list of quoted strings that follows `command:`."""
    text = (ROOT / "docker-compose.yml").read_text()
    server = text[text.index("  server:") : text.index("  web:")]
    match = re.search(r"^\s+command:\s*\[(.*?)\]", server, re.DOTALL | re.MULTILINE)
    assert match is not None, "the server service must pin its command"
    return parse(re.findall(r'"([^"]*)"', match.group(1)))


def commands() -> dict[str, dict[str, str]]:
    return {
        "dev": dev_command(),
        "Dockerfile": dockerfile_command(),
        "compose": compose_command(),
    }


def test_every_run_command_pins_the_websockets_implementation() -> None:
    for where, options in commands().items():
        assert options.get("--ws") == "websockets", where


def test_every_run_command_runs_one_worker() -> None:
    for where, options in commands().items():
        assert options.get("--workers", "1") == "1", where
        assert "--reload" not in options or where == "dev", where  # reload is dev only


def test_the_run_commands_agree() -> None:
    all_commands = commands()
    comparable = {
        where: {k: v for k, v in options.items() if k != "--reload"}
        for where, options in all_commands.items()
    }
    assert {options["app"] for options in comparable.values()} == {APP}
    first = comparable["Dockerfile"]
    for where, options in comparable.items():
        assert options == first, f"{where} differs from the Dockerfile"


def test_the_compose_file_does_not_scale_the_server() -> None:
    text = (ROOT / "docker-compose.yml").read_text()
    server = text[text.index("  server:") : text.index("  web:")]
    assert "replicas" not in server
    assert "scale" not in server
    assert "WEB_CONCURRENCY" not in server


def locked_version(name: str) -> tuple[int, ...]:
    lock = (ROOT / "uv.lock").read_text()
    match = re.search(rf'\[\[package\]\]\nname = "{name}"\nversion = "([0-9.]+)"', lock)
    assert match is not None, name
    return tuple(int(part) for part in match.group(1).split("."))


def test_uvicorn_and_websockets_are_pinned_to_a_range_the_lock_satisfies() -> None:
    """`--ws websockets` is deprecated upstream (uvicorn 0.54 says it will point at the sansio
    implementation), and the log filter covers the `websockets` loggers of this implementation. So
    both are held to a minor range; moving them is a reviewed change (see the deploy notes)."""
    pyproject = (ROOT / "apps/server/pyproject.toml").read_text()
    uvicorn_pin = re.search(r'"uvicorn>=(\d+)\.(\d+),<(\d+)\.(\d+)"', pyproject)
    websockets_pin = re.search(r'"websockets>=(\d+),<(\d+)"', pyproject)
    assert uvicorn_pin is not None, "uvicorn needs a lower and an upper bound"
    assert websockets_pin is not None, "websockets needs a lower and an upper bound"
    low = (int(uvicorn_pin[1]), int(uvicorn_pin[2]))
    high = (int(uvicorn_pin[3]), int(uvicorn_pin[4]))
    assert low < high
    assert low <= locked_version("uvicorn")[:2] < high
    assert int(websockets_pin[1]) <= locked_version("websockets")[0] < int(websockets_pin[2])

"""`serve --http`: the token file, the bind address, the flags and one real process."""

import json
import os
import queue
import re
import signal
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import IO

import pytest

from notary_mcp_proxy.http_client import HttpClient
from notary_mcp_proxy.http_server import (
    BindError,
    TokenFileError,
    parse_bind,
    read_token_file,
)
from notary_mcp_proxy.main import main

BANK = Path(__file__).resolve().parents[1] / "examples" / "bank"
TOKEN = "fedcba9876543210fedcba9876543210"
ACME_IBAN = "DE00ACME00000000000001"
ATTACKER_IBAN = "DE00ATTACKER0000000001"
BEARER = {"Authorization": f"Bearer {TOKEN}"}
PATIENCE = 30.0
"""Only a failing test waits this long."""


def _token_file(tmp_path: Path, text: str = TOKEN, mode: int = 0o600) -> Path:
    path = tmp_path / "token"
    path.write_text(text)
    path.chmod(mode)
    return path


def test_the_token_file_is_read_and_trimmed(tmp_path: Path) -> None:
    assert read_token_file(str(_token_file(tmp_path, TOKEN + "\n"))) == TOKEN.encode()
    assert read_token_file(str(_token_file(tmp_path, mode=0o400))) == TOKEN.encode()


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660, 0o666, 0o620])
def test_a_token_file_others_can_access_is_refused(tmp_path: Path, mode: int) -> None:
    with pytest.raises(TokenFileError, match="accessible by group or others") as raised:
        read_token_file(str(_token_file(tmp_path, mode=mode)))
    assert TOKEN not in str(raised.value)


@pytest.mark.parametrize(
    "text", ["", "short", " " * 40, "has a space in the middle of the token!!", "tök" * 10]
)
def test_a_bad_token_is_refused_without_echoing_it(tmp_path: Path, text: str) -> None:
    with pytest.raises(TokenFileError) as raised:
        read_token_file(str(_token_file(tmp_path, text)))
    assert text.strip() == "" or text.strip() not in str(raised.value)


def test_a_token_file_that_is_not_a_plain_file_is_refused(tmp_path: Path) -> None:
    real = _token_file(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(TokenFileError):
        read_token_file(str(link))
    with pytest.raises(TokenFileError):
        read_token_file(str(tmp_path))
    with pytest.raises(TokenFileError, match="cannot open"):
        read_token_file(str(tmp_path / "missing"))


def test_the_bind_address_defaults_to_loopback_and_remote_needs_a_flag() -> None:
    assert parse_bind("127.0.0.1:8765", allow_remote=False) == ("127.0.0.1", 8765)
    assert parse_bind("localhost:1", allow_remote=False) == ("localhost", 1)
    assert parse_bind("[::1]:80", allow_remote=False) == ("::1", 80)
    for remote in ("0.0.0.0:8765", "192.168.1.5:80", "example.com:80", ":8765", "[::]:80"):
        with pytest.raises(BindError):
            parse_bind(remote, allow_remote=False)
    assert parse_bind("0.0.0.0:8765", allow_remote=True) == ("0.0.0.0", 8765)
    for malformed in ("8765", "127.0.0.1", "127.0.0.1:", "127.0.0.1:99999", "127.0.0.1:x"):
        with pytest.raises(BindError):
            parse_bind(malformed, allow_remote=True)


def _config(tmp_path: Path) -> Path:
    data = json.loads((BANK / "notary.json").read_text())
    data["server"]["command"] = [sys.executable, str(BANK / "server.py")]
    path = tmp_path / "notary.json"
    path.write_text(json.dumps(data))
    return path


def test_usage_errors_exit_2_before_anything_starts(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = str(_config(tmp_path))
    token = str(_token_file(tmp_path))
    cases = [
        ["--config", config, "--http", "127.0.0.1:0"],  # no token file
        ["--config", config, "--token-file", token],  # no --http
        ["--config", config, "--allow-origin", "http://x"],
        ["--config", config, "--http", "0.0.0.0:0", "--token-file", token],
        ["--config", config, "--http", "nonsense", "--token-file", token],
    ]
    for argv in cases:
        with pytest.raises(SystemExit) as raised:
            main(argv)
        assert raised.value.code == 2, argv
    loose = _token_file(tmp_path, mode=0o644)
    with pytest.raises(SystemExit) as raised:
        main(["--config", config, "--http", "127.0.0.1:0", "--token-file", str(loose)])
    assert raised.value.code == 2
    assert TOKEN not in capsys.readouterr().err


class Proxy:
    """`python -m notary_mcp_proxy --http ...` as a child process."""

    def __init__(self, tmp_path: Path) -> None:
        self.audit = tmp_path / "audit"
        self.process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "notary_mcp_proxy",
                "--config",
                str(_config(tmp_path)),
                "--http",
                "127.0.0.1:0",
                "--token-file",
                str(_token_file(tmp_path)),
                "--control",
                str(tmp_path / "c" / "p.sock"),
                "--audit-dir",
                str(self.audit),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        assert self.process.stderr is not None
        self.lines: queue.Queue[str | None] = queue.Queue()
        self.log: list[str] = []
        threading.Thread(target=self._pump, args=(self.process.stderr,), daemon=True).start()
        self.url = self._wait_for_url()

    def _pump(self, stream: IO[bytes]) -> None:
        for raw in iter(stream.readline, b""):
            self.lines.put(raw.decode("utf-8"))
        self.lines.put(None)

    def _wait_for_url(self) -> str:
        while True:
            line = self.lines.get(timeout=PATIENCE)
            assert line is not None, "".join(self.log)
            self.log.append(line)
            found = re.search(r"listening on (http://\S+)", line)
            if found:
                return found.group(1)

    def finish(self) -> str:
        assert self.process.wait(timeout=PATIENCE) == 0, "".join(self.log)
        while (line := self.lines.get(timeout=PATIENCE)) is not None:
            self.log.append(line)
        assert self.process.stdout is not None
        assert self.process.stdout.read() == b""  # HTTP mode writes nothing to stdout
        return "".join(self.log)

    def kill(self) -> None:
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait()


@pytest.fixture
def proxy(tmp_path: Path) -> Iterator[Proxy]:
    started = Proxy(tmp_path)
    yield started
    started.kill()


def test_a_real_run_over_http_ends_with_the_clients_delete(proxy: Proxy) -> None:
    client = HttpClient(
        proxy.url, headers={"Authorization": f"Bearer {TOKEN}"}, timeout_seconds=PATIENCE
    )
    client.initialize()
    inbox = client.call_tool("read_inbox", {})
    assert inbox["isError"] is False
    blocked = client.call_tool("pay_bill", {"payee": ATTACKER_IBAN, "amount": 120})
    assert blocked["isError"] is True
    assert "LEDGER_NOT_FOUND" in json.dumps(blocked)
    paid = client.call_tool("pay_bill", {"payee": ACME_IBAN, "amount": 120})
    assert paid["isError"] is False
    client.close()
    log = proxy.finish()
    assert TOKEN not in log
    assert re.search(r"closed: length \d+ head [0-9a-f]+", log)
    chains = list(proxy.audit.glob("*.chain.jsonl"))
    assert len(chains) == 1
    types = [json.loads(line)["event"]["type"] for line in chains[0].read_text().splitlines()]
    assert types[0] == "run_started"
    assert types[-1] == "run_finished"
    assert types.count("decision_made") == 3


def test_sigterm_ends_the_run_cleanly(proxy: Proxy) -> None:
    client = HttpClient(
        proxy.url, headers={"Authorization": f"Bearer {TOKEN}"}, timeout_seconds=PATIENCE
    )
    client.initialize()
    assert client.call_tool("read_inbox", {})["isError"] is False
    os.kill(proxy.process.pid, signal.SIGTERM)
    log = proxy.finish()
    assert "closed: length" in log
    client.close()  # the server is gone; closing must not raise

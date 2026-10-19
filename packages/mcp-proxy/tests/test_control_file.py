"""`<run_id>.control.json`: how the proxy announces its control socket to the X-ray (#262)."""

import json
import re
import stat
import sys
from pathlib import Path

import pytest
from stdio_session import StdioSession, proxy_command, request

from notary_mcp_proxy.main import CONTROL_SUFFIX, write_control_file

BANK = Path(__file__).resolve().parents[1] / "examples" / "bank"
RUN = "mcp-0123456789ab"


def bank_config(directory: Path) -> Path:
    data = json.loads((BANK / "notary.json").read_text())
    data["server"]["command"] = [sys.executable, str(BANK / "server.py")]
    config = directory / "notary.json"
    config.write_text(json.dumps(data))
    return config


def test_write_control_file_is_private_absolute_and_atomic(tmp_path: Path) -> None:
    path = write_control_file(tmp_path, RUN, Path("ctl") / "a.sock")
    assert path == tmp_path / (RUN + CONTROL_SUFFIX)
    assert json.loads(path.read_text()) == {"socket": str(Path("ctl/a.sock").resolve())}
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert sorted(item.name for item in tmp_path.iterdir()) == [RUN + CONTROL_SUFFIX]
    again = write_control_file(tmp_path, RUN, tmp_path / "b.sock")  # a rewrite replaces it
    assert json.loads(again.read_text()) == {"socket": str(tmp_path / "b.sock")}


def control_files(directory: Path) -> list[Path]:
    return sorted(directory.glob("*" + CONTROL_SUFFIX))


def test_the_proxy_announces_its_socket_next_to_the_chain(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    directory = tmp_path_factory.mktemp("cf")
    audit = directory / "runs"
    socket_path = directory / "ctl" / "bank.sock"
    session = StdioSession(
        proxy_command(
            bank_config(directory), "--audit-dir", str(audit), "--control", str(socket_path)
        )
    )
    session.send(request(1, "initialize", {"protocolVersion": "2025-06-18"}))
    session.result(1)  # the control socket is up before the proxy answers
    (found,) = control_files(audit)
    assert re.fullmatch(r"mcp-[0-9a-f]{12}", found.name.removesuffix(CONTROL_SUFFIX))
    assert (audit / (found.name.removesuffix(CONTROL_SUFFIX) + ".chain.jsonl")).is_file()
    assert json.loads(found.read_text()) == {"socket": str(socket_path.resolve())}
    assert stat.S_IMODE(found.stat().st_mode) == 0o600
    session.finish()
    assert control_files(audit) == []  # removed with the socket


def test_no_file_without_audit_dir_or_with_control_none(
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    directory = tmp_path_factory.mktemp("cn")
    audit = directory / "runs"
    config = bank_config(directory)
    plain = StdioSession(proxy_command(config, "--control", str(directory / "c" / "x.sock")))
    plain.send(request(1, "initialize", {"protocolVersion": "2025-06-18"}))
    plain.result(1)
    plain.finish()
    disabled = StdioSession(proxy_command(config, "--audit-dir", str(audit), "--control", "none"))
    disabled.send(request(1, "initialize", {"protocolVersion": "2025-06-18"}))
    disabled.result(1)
    assert control_files(audit) == []
    disabled.finish()
    assert control_files(directory) == []

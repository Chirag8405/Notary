"""`notary-mcp-proxy check`: `check_config` on hand-built inputs, and the CLI over the toy bank."""

import json
import sys
from pathlib import Path

import pytest

from notary_core.pinning import ToolManifest
from notary_mcp_proxy.check import CheckReport, check_config, render_report
from notary_mcp_proxy.config import ProxyConfig
from notary_mcp_proxy.jsonrpc import JsonObject
from notary_mcp_proxy.main import main

BANK = Path(__file__).resolve().parents[1] / "examples" / "bank"
EXPECTED = Path(__file__).resolve().parent / "expected_bank_check.txt"

BUDGET = {
    "max_effects": 2,
    "max_spend_cents": 20000,
    "max_egress_bytes": 0,
    "max_call_amount_cents": 20000,
    "max_approvals": 1,
}
FREE = {"marker": {"kind": "free"}}


def _config(tools: dict[str, object], **extra: object) -> ProxyConfig:
    data: dict[str, object] = {
        "server": {"command": ["x"]},
        "user_intent": "test",
        "tools": tools,
        "budget": BUDGET,
        **extra,
    }
    return ProxyConfig.model_validate_json(json.dumps(data))


def _schema(props: list[str], required: list[str] | None = None) -> JsonObject:
    return {
        "type": "object",
        "properties": {name: {"type": "string"} for name in props},
        "required": list(required or []),
    }


def _run(
    config: ProxyConfig, server: dict[str, list[str]], required: dict[str, list[str]] | None = None
) -> CheckReport:
    manifests = [
        ToolManifest(name=name, description="d", input_schema=json.dumps(_schema(props)))
        for name, props in server.items()
    ]
    schemas = {name: _schema(props, (required or {}).get(name)) for name, props in server.items()}
    return check_config(config, manifests, schemas)


def _codes(report: CheckReport) -> set[tuple[str, str]]:
    return {(f.severity, f.code) for f in report.findings}


def test_clean_config_is_ok() -> None:
    config = _config({"read_file": {"effect": "read", "params": {"path": FREE}}})
    report = _run(config, {"read_file": ["path"]})
    assert report.ok
    assert report.findings == ()
    assert report.tools[0].params == (("path", "free", "identifier", "identifier"),)


def test_tool_missing() -> None:
    report = _run(_config({"read_file": {"effect": "read"}}), {})
    assert _codes(report) == {("error", "TOOL_MISSING")}
    assert not report.ok
    assert report.tools == ()


def test_param_not_in_config_warning_and_error_when_required() -> None:
    config = _config({"read_file": {"effect": "read"}})
    assert _codes(_run(config, {"read_file": ["path"]})) == {("warning", "PARAM_NOT_IN_CONFIG")}
    required = _run(config, {"read_file": ["path"]}, {"read_file": ["path"]})
    assert _codes(required) == {("error", "PARAM_NOT_IN_CONFIG")}
    assert not required.ok


def test_param_not_on_server() -> None:
    config = _config({"read_file": {"effect": "read", "params": {"path": FREE}}})
    assert _codes(_run(config, {"read_file": []})) == {("warning", "PARAM_NOT_ON_SERVER")}


def test_param_unclassified() -> None:
    config = _config(
        {"send_money": {"effect": "irreversible", "params": {"memo": FREE}}},
        authorized_irreversible=["send_money"],
    )
    report = _run(config, {"send_money": ["memo"]})
    assert _codes(report) == {("error", "PARAM_UNCLASSIFIED")}


def test_effect_stricter_than_config() -> None:
    config = _config({"send_email": {"effect": "read"}})
    assert ("info", "EFFECT_STRICTER_THAN_CONFIG") in _codes(_run(config, {"send_email": []}))


def test_ledger_value_invalid() -> None:
    config = _config(
        {"read_file": {"effect": "read"}},
        ledger=[{"ledger": "payees", "key": "Acme", "unit": "iban", "value": "not an iban"}],
    )
    assert _codes(_run(config, {"read_file": []})) == {("error", "LEDGER_VALUE_INVALID")}


def test_ledger_placeholder_iban_is_a_warning() -> None:
    config = _config(
        {"read_file": {"effect": "read"}},
        ledger=[
            {"ledger": "payees", "key": "Acme", "unit": "iban", "value": "DE00ACME00000000000001"}
        ],
    )
    report = _run(config, {"read_file": []})
    assert _codes(report) == {("warning", "LEDGER_VALUE_PLACEHOLDER")}
    assert report.ok


def test_ledger_iban_with_a_typo_is_an_error() -> None:
    config = _config(
        {"read_file": {"effect": "read"}},
        ledger=[
            {"ledger": "payees", "key": "Acme", "unit": "iban", "value": "DE89370400440532013001"}
        ],
    )
    report = _run(config, {"read_file": []})
    assert _codes(report) == {("error", "LEDGER_VALUE_INVALID")}
    assert not report.ok


def test_irreversible_not_authorized() -> None:
    config = _config({"delete_email": {"effect": "irreversible", "params": {"message_id": FREE}}})
    assert _codes(_run(config, {"delete_email": ["message_id"]})) == {
        ("warning", "IRREVERSIBLE_NOT_AUTHORIZED")
    }


def test_server_tool_not_exposed() -> None:
    config = _config({"read_file": {"effect": "read"}})
    report = _run(config, {"read_file": [], "other": []})
    assert _codes(report) == {("info", "SERVER_TOOL_NOT_EXPOSED")}


def _bank_config(
    tmp_path: Path, command: list[str] | None = None, ledger_value: str | None = None
) -> Path:
    data = json.loads((BANK / "notary.json").read_text())
    data["server"]["command"] = command or [sys.executable, str(BANK / "server.py")]
    if ledger_value is not None:
        data["ledger"][0]["value"] = ledger_value
    path = tmp_path / "notary.json"
    path.write_text(json.dumps(data))
    return path


def test_bank_config_is_clean(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check", "--config", str(_bank_config(tmp_path))]) == 0
    out = capsys.readouterr().out
    assert "param payee  marker=ledger  unit=iban  kind=destination" in out
    assert "param amount  marker=free  unit=amount  kind=amount" in out
    assert out == EXPECTED.read_text()


def test_invalid_ledger_exits_1(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check", "--config", str(_bank_config(tmp_path, ledger_value="nope"))]) == 1
    assert "LEDGER_VALUE_INVALID" in capsys.readouterr().out


def test_server_failure_exits_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    path = _bank_config(tmp_path, command=[sys.executable, "-c", "pass"])
    assert main(["check", "--config", str(path)]) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "failed to start" in captured.err


def test_missing_command_and_bad_config_exit_2(tmp_path: Path) -> None:
    missing = _bank_config(tmp_path, command=["/no/such/binary"])
    assert main(["check", "--config", str(missing)]) == 2
    bad = tmp_path / "bad.json"
    bad.write_text("{}")
    assert main(["check", "--config", str(bad)]) == 2


def test_usage_error_exits_2() -> None:
    with pytest.raises(SystemExit) as exit_info:
        main(["check"])
    assert exit_info.value.code == 2


def test_json_output_is_a_report(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["check", "--config", str(_bank_config(tmp_path)), "--json"]) == 0
    report = CheckReport.model_validate_json(capsys.readouterr().out)
    assert report.ok
    assert [row.tool for row in report.tools] == ["pay_bill", "read_inbox"]
    assert render_report(report) == EXPECTED.read_text()

"""`ServerSpec` is a union of stdio and http specs; the old form without `kind` stays stdio."""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from notary_mcp_proxy.config import (
    HttpServerSpec,
    ProxyConfig,
    StdioServerSpec,
    resolve_headers,
)
from notary_mcp_proxy.jsonrpc import JsonObject
from notary_mcp_proxy.main import main

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"
BUDGET: JsonObject = {
    "max_effects": 1,
    "max_spend_cents": 0,
    "max_egress_bytes": 0,
    "max_call_amount_cents": 0,
    "max_approvals": 0,
}


def _config(**servers: JsonObject) -> ProxyConfig:
    return ProxyConfig.model_validate_json(
        json.dumps(
            {
                "servers": servers,
                "user_intent": "x",
                "tools": {"t": {"effect": "read", "server": next(iter(servers))}},
                "budget": BUDGET,
            }
        )
    )


def _http(**fields: object) -> HttpServerSpec:
    return HttpServerSpec.model_validate(
        {"kind": "http", "url": "https://mcp.example/mcp", **fields}
    )


@pytest.mark.parametrize(
    "path", sorted(EXAMPLES.glob("*/notary.json")), ids=lambda p: p.parent.name
)
def test_every_example_config_loads_as_stdio(path: Path) -> None:
    config = ProxyConfig.model_validate_json(path.read_bytes())
    assert all(isinstance(spec, StdioServerSpec) for spec in config.servers.values())


def test_the_old_form_without_kind_means_stdio() -> None:
    old = _config(a={"command": ["x", "y"], "timeout_seconds": 2})
    new = _config(a={"kind": "stdio", "command": ["x", "y"], "timeout_seconds": 2})
    assert old == new
    spec = old.servers["a"]
    assert isinstance(spec, StdioServerSpec)
    assert spec.kind == "stdio"
    assert spec.command == ("x", "y")


def test_the_single_server_form_accepts_both_kinds() -> None:
    old = ProxyConfig.model_validate_json(
        json.dumps(
            {
                "server": {"command": ["x"]},
                "user_intent": "x",
                "tools": {"t": {"effect": "read"}},
                "budget": BUDGET,
            }
        )
    )
    assert isinstance(old.server, StdioServerSpec)
    remote = ProxyConfig.model_validate_json(
        json.dumps(
            {
                "server": {"kind": "http", "url": "https://mcp.example/mcp"},
                "user_intent": "x",
                "tools": {"t": {"effect": "read"}},
                "budget": BUDGET,
            }
        )
    )
    assert isinstance(remote.servers["default"], HttpServerSpec)
    with pytest.raises(ValueError, match="not a stdio server"):
        _ = remote.server


def test_http_and_stdio_servers_mix_and_keep_resources_prompts_and_timeout() -> None:
    config = _config(
        local={"command": ["x"]},
        remote={
            "kind": "http",
            "url": "https://mcp.example/mcp",
            "timeout_seconds": 7,
            "resources": {"allow": ["file:///docs/"]},
            "prompts": {"allow": ["summarize"]},
        },
    )
    remote = config.servers["remote"]
    assert isinstance(remote, HttpServerSpec)
    assert remote.timeout_seconds == 7
    assert remote.resources is not None
    assert remote.prompts is not None
    assert remote.headers == {}


def test_an_unknown_kind_or_extra_field_is_refused() -> None:
    with pytest.raises(ValidationError):
        _config(a={"kind": "websocket", "url": "wss://x"})
    with pytest.raises(ValidationError):
        _config(a={"kind": "stdio", "command": ["x"], "url": "https://x"})
    with pytest.raises(ValidationError):
        _config(a={"kind": "http", "url": "https://x/mcp", "command": ["x"]})
    with pytest.raises(ValidationError):
        _config(a={"kind": "http"})


@pytest.mark.parametrize(
    "url",
    [
        "ftp://mcp.example/mcp",
        "https://",
        "mcp.example/mcp",
        "https://user:pass@mcp.example/mcp",
        "https://mcp.example/mcp#frag",
        "http://mcp.example/mcp",  # plain http to a remote host
        "https://mcp.example:99999/mcp",
    ],
)
def test_bad_urls_are_refused(url: str) -> None:
    with pytest.raises(ValidationError):
        _http(url=url)


@pytest.mark.parametrize(
    "url", ["http://127.0.0.1:8080/mcp", "http://localhost/mcp", "http://[::1]:9/mcp"]
)
def test_plain_http_is_for_loopback_only(url: str) -> None:
    assert _http(url=url).url == url


def test_a_credential_header_must_reference_a_variable() -> None:
    assert _http(headers={"Authorization": "Bearer ${GH_TOKEN}"}).headers
    assert _http(headers={"X-Api-Key": "${KEY}"}).headers
    assert _http(headers={"X-Team": "platform"}).headers  # not a credential
    for headers in (
        {"Authorization": "Bearer abc123"},
        {"authorization": "abc"},
        {"Cookie": "a=b"},
        {"X-Api-Key": "abc"},
        {"X-Auth-Token": "abc"},
    ):
        with pytest.raises(ValidationError, match="credential"):
            _http(headers=headers)


@pytest.mark.parametrize(
    "headers",
    [
        {"X-A": "${"},
        {"X-A": "${1BAD}"},
        {"X-A": "${NAME"},
        {"Bad Name": "v"},
        {"Accept": "text/plain"},
        {"Mcp-Session-Id": "x"},
        {"mcp-protocol-version": "x"},
        {"Content-Type": "x"},
        {"X-A": "a\nb"},
        {"X-A": "a", "x-a": "b"},
    ],
)
def test_unsafe_headers_are_refused(headers: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        _http(headers=headers)


def test_headers_resolve_from_the_environment() -> None:
    spec = _http(headers={"Authorization": "Bearer ${GH_TOKEN}", "X-Both": "${A}-${B}", "X-P": "p"})
    resolved = resolve_headers("gh", spec, {"GH_TOKEN": "tok", "A": "1", "B": "2", "C": "3"})
    assert resolved == {"Authorization": "Bearer tok", "X-Both": "1-2", "X-P": "p"}


@pytest.mark.parametrize("env", [{}, {"GH_TOKEN": ""}])
def test_a_missing_variable_fails_with_its_name_only(env: dict[str, str]) -> None:
    spec = _http(headers={"Authorization": "Bearer ${GH_TOKEN}"})
    with pytest.raises(ValueError, match="GH_TOKEN") as raised:
        resolve_headers("gh", spec, env)
    assert "Bearer" not in str(raised.value)


def test_a_variable_with_a_line_break_is_refused_without_its_value() -> None:
    spec = _http(headers={"Authorization": "Bearer ${GH_TOKEN}"})
    with pytest.raises(ValueError, match="GH_TOKEN") as raised:
        resolve_headers("gh", spec, {"GH_TOKEN": "abc\nX-Evil: 1"})
    assert "abc" not in str(raised.value)


def test_startup_fails_clearly_for_a_missing_variable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("NOTARY_TEST_MISSING_TOKEN", raising=False)
    path = tmp_path / "notary.json"
    path.write_text(
        json.dumps(
            {
                "server": {
                    "kind": "http",
                    "url": "https://mcp.example/mcp",
                    "headers": {"Authorization": "Bearer ${NOTARY_TEST_MISSING_TOKEN}"},
                },
                "user_intent": "x",
                "tools": {"t": {"effect": "read"}},
                "budget": BUDGET,
            }
        )
    )
    assert main(["--config", str(path)]) == 2
    err = capsys.readouterr().err
    assert "NOTARY_TEST_MISSING_TOKEN" in err
    assert "startup failed" in err

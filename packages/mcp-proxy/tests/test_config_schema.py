"""The config's JSON Schema file, the `$schema` key and the example configs (#269)."""

import json
from pathlib import Path

import pytest
from pydantic import JsonValue, ValidationError

from notary_mcp_proxy.config import ProxyConfig
from notary_mcp_proxy.jsonrpc import JsonObject, as_object

PACKAGE = Path(__file__).resolve().parents[1]
SCHEMA_FILE = PACKAGE / "schema" / "proxy-config.schema.json"
EXAMPLE_CONFIGS = sorted((PACKAGE / "examples").glob("*/notary.json"))
BUDGET: JsonObject = {
    "max_effects": 1,
    "max_spend_cents": 0,
    "max_egress_bytes": 0,
    "max_call_amount_cents": 0,
    "max_approvals": 0,
}


def _raw(**extra: object) -> str:
    return json.dumps(
        {
            "server": {"command": ["server"]},
            "user_intent": "x",
            "tools": {"t": {"effect": "read"}},
            "budget": BUDGET,
            **extra,
        }
    )


def test_the_schema_file_is_json_that_describes_the_config() -> None:
    text = SCHEMA_FILE.read_text(encoding="utf-8")
    parsed: JsonValue = json.loads(text)
    schema = as_object(parsed)
    assert schema is not None
    assert text.endswith("}\n")
    assert schema["additionalProperties"] is False
    properties = as_object(schema["properties"])
    assert properties is not None
    assert {"$schema", "server", "servers", "tools", "budget", "approvals"} <= set(properties)
    assert schema["oneOf"] == [{"required": ["server"]}, {"required": ["servers"]}]


def test_there_are_example_configs() -> None:
    assert [path.parent.name for path in EXAMPLE_CONFIGS] == ["bank", "office"]


@pytest.mark.parametrize("path", EXAMPLE_CONFIGS, ids=lambda path: path.parent.name)
def test_an_example_config_loads_and_points_at_the_schema(path: Path) -> None:
    config = ProxyConfig.model_validate_json(path.read_bytes())
    assert config.schema_uri is not None
    assert (path.parent / config.schema_uri).resolve() == SCHEMA_FILE


def test_the_schema_key_is_accepted_and_ignored() -> None:
    plain = ProxyConfig.model_validate_json(_raw())
    pointed = ProxyConfig.model_validate_json(_raw(**{"$schema": "x.schema.json"}))
    assert pointed.schema_uri == "x.schema.json"
    assert pointed.model_dump(exclude={"schema_uri"}) == plain.model_dump(exclude={"schema_uri"})


@pytest.mark.parametrize("key", ["schema", "$schemas", "$id", "extra"])
def test_any_other_unknown_key_still_fails(key: str) -> None:
    with pytest.raises(ValidationError):
        ProxyConfig.model_validate_json(_raw(**{key: "x"}))

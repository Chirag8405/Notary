"""`NOTARY_WEB_ORIGINS`: which web pages CORS lets call the server."""

import pytest
from fastapi.testclient import TestClient

from notary_server.app import create_app
from notary_server.wiring import Settings, build_app

PUBLIC = "https://notary.example.app"


def _preflight(client: TestClient, origin: str) -> str | None:
    response = client.options(
        "/playground/poison",
        headers={"Origin": origin, "Access-Control-Request-Method": "POST"},
    )
    return response.headers.get("access-control-allow-origin")


def test_default_is_the_local_web_app() -> None:
    assert Settings.from_env({}).web_origins == ("http://localhost:3000",)
    for blank in ("", "  "):
        assert Settings.from_env({"NOTARY_WEB_ORIGINS": blank}).web_origins == (
            "http://localhost:3000",
        )


def test_env_replaces_the_default_and_normalizes() -> None:
    raw = f" {PUBLIC}/ , http://localhost:3000,{PUBLIC}"
    settings = Settings.from_env({"NOTARY_WEB_ORIGINS": raw})
    assert settings.web_origins == (PUBLIC, "http://localhost:3000")


@pytest.mark.parametrize(
    "raw",
    ["*", "notary.example.app", "ftp://x.example", f"{PUBLIC}/path", f"{PUBLIC}?a=1", " , "],
)
def test_invalid_origin_fails_at_startup(raw: str) -> None:
    with pytest.raises(ValueError, match="NOTARY_WEB_ORIGINS"):
        Settings.from_env({"NOTARY_WEB_ORIGINS": raw})


def test_cors_follows_the_setting() -> None:
    client = TestClient(build_app(Settings.from_env({"NOTARY_WEB_ORIGINS": PUBLIC})))
    assert _preflight(client, PUBLIC) == PUBLIC
    assert _preflight(client, "http://localhost:3000") is None
    assert _preflight(client, "https://evil.example") is None


def test_create_app_default_stays_local() -> None:
    client = TestClient(create_app(event_delay=0))
    assert _preflight(client, "http://localhost:3000") == "http://localhost:3000"
    assert _preflight(client, PUBLIC) is None

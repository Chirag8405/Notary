"""`render.yaml`: the proxy trust list behind the per-client rate limits."""

import re
from pathlib import Path

import pytest
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

BLUEPRINT = Path(__file__).resolve().parents[3] / "render.yaml"
PROXY = "10.20.30.40"


def _trusted() -> str:
    match = re.search(r'key: FORWARDED_ALLOW_IPS\s+value: "([^"]+)"', BLUEPRINT.read_text("utf-8"))
    assert match, "render.yaml must set FORWARDED_ALLOW_IPS"
    return match.group(1)


def _client_seen(forwarded_for: str, peer: str = PROXY) -> str | None:
    seen: list[str | None] = []

    async def app(scope: dict, receive: object, send: object) -> None:  # type: ignore[type-arg]
        client = scope.get("client")
        seen.append(client[0] if client else None)

    middleware = ProxyHeadersMiddleware(app, trusted_hosts=_trusted())  # type: ignore[arg-type]
    scope = {
        "type": "http",
        "client": (peer, 1234),
        "headers": [(b"x-forwarded-for", forwarded_for.encode())],
    }

    import asyncio

    asyncio.run(middleware(scope, None, None))  # type: ignore[arg-type]
    return seen[0]


def test_the_trust_list_never_trusts_everything() -> None:
    assert "*" not in _trusted()
    assert "0.0.0.0/0" not in _trusted()


def test_the_client_comes_from_the_forwarding_header() -> None:
    assert _client_seen("203.0.113.7") == "203.0.113.7"


@pytest.mark.parametrize("fake", ["1.2.3.4", "10.9.9.9", "203.0.113.200, 198.51.100.1"])
def test_an_address_a_visitor_puts_in_front_is_ignored(fake: str) -> None:
    # The proxy appends the address it saw, so the real client is the last one.
    assert _client_seen(f"{fake}, 203.0.113.7") == "203.0.113.7"


def test_a_public_peer_is_not_trusted() -> None:
    # A direct connection from the internet cannot pick its own address.
    assert _client_seen("1.2.3.4", peer="198.51.100.9") == "198.51.100.9"

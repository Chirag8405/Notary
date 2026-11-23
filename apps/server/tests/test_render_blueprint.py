"""`render.yaml`: the proxy trust list behind the per-client rate limits."""

import asyncio
import re
from collections.abc import MutableMapping
from pathlib import Path
from typing import cast

import pytest
from uvicorn._types import ASGI3Application, ASGIReceiveCallable, ASGISendCallable, Scope
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

BLUEPRINT = Path(__file__).resolve().parents[3] / "render.yaml"
PROXY = "10.20.30.40"


def _trusted() -> str:
    match = re.search(r'key: FORWARDED_ALLOW_IPS\s+value: "([^"]+)"', BLUEPRINT.read_text("utf-8"))
    assert match, "render.yaml must set FORWARDED_ALLOW_IPS"
    return match.group(1)


def _client_seen(forwarded_for: str, peer: str = PROXY) -> str:
    seen: list[str] = []

    async def app(scope: MutableMapping[str, object], receive: object, send: object) -> None:
        seen.append(cast(tuple[str, int], scope["client"])[0])

    middleware = ProxyHeadersMiddleware(cast(ASGI3Application, app), trusted_hosts=_trusted())
    scope = cast(
        Scope,
        {
            "type": "http",
            "client": (peer, 1234),
            "headers": [(b"x-forwarded-for", forwarded_for.encode())],
        },
    )
    asyncio.run(middleware(scope, cast(ASGIReceiveCallable, None), cast(ASGISendCallable, None)))
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

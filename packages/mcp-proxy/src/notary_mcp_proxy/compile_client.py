"""Ask the NOTARY server to compile the user's first prompt into a contract (`--compile-url`).

The Intent Compiler lives in `apps/server`; the proxy may not import it. This module is the proxy's
side of `POST /mcp/compile` and it is stdlib plus `notary_core` only. Three limits hold:

- **Loopback only.** The URL must be `http://127.0.0.1:<port>/...` or `http://localhost:<port>/...`
  (no credentials, query or fragment); anything else is refused when the proxy starts. The address
  actually connected to is checked again, so a `localhost` that resolves elsewhere is refused. The
  prompt and the tool manifests never leave the machine through this channel.
- **Bounded.** One request, one overall deadline (`COMPILE_TIMEOUT`), a response of at most
  `MAX_RESPONSE` bytes, status 200 only, no redirect, no proxy from the environment.
- **It can only narrow.** The answer is a proposal. `narrow` accepts it only when
  `widening_reasons(config_contract, compiled)` is empty, so the compile server (or a model behind
  it) can at most remove tools, parameters, budget or authority from what the config allows, never
  add any (I5). Any failure keeps the config contract.

Whatever the server says is untrusted text: failures are reported with constant reasons, and names
that come from the answer are quoted before they reach stderr.
"""

import contextlib
import http.client
import ipaddress
import json
import socket
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import cast
from urllib.parse import urlsplit

from pydantic import ValidationError

from notary_core.contract import widening_reasons
from notary_core.models import IntentContract, NotaryModel
from notary_core.pinning import ToolManifest
from notary_mcp_proxy.client import diagnostic, quoted
from notary_mcp_proxy.config import CONTENT_TOOLS

COMPILE_TIMEOUT = 15.0
"""Seconds for the whole request (connect, send, answer). A compile is one LLM call, normally a few
seconds. When it overruns the run starts with the config contract. The prompt waits of the proxy
and the hook are sized from this number (docs/decisions.md)."""
MAX_RESPONSE = 256 * 1024
"""Bytes of the answer read; a longer one is refused. A contract is a few kilobytes."""
LOOPBACK_NAMES = frozenset({"127.0.0.1", "localhost"})
_CHUNK = 8192


class CompileClientError(Exception):
    """The compile request failed. The message is constant and safe to print."""


@dataclass(frozen=True, slots=True)
class CompileTarget:
    host: str
    port: int
    path: str


class CompileUrlError(ValueError):
    """The `--compile-url` is not a loopback http URL with a port."""


def parse_compile_url(url: str) -> CompileTarget:
    """The target of a loopback `http://HOST:PORT/PATH` URL; `CompileUrlError` for anything else."""
    if not url.isprintable() or " " in url:
        raise CompileUrlError("the compile URL has a space or a control character")
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise CompileUrlError("the compile URL is not a valid URL") from None
    if parts.scheme != "http":
        raise CompileUrlError("the compile URL must be http (loopback only)")
    if parts.hostname not in LOOPBACK_NAMES:
        raise CompileUrlError("the compile URL must name 127.0.0.1 or localhost")
    if "@" in parts.netloc:
        raise CompileUrlError("the compile URL must not carry credentials")
    if port is None:
        raise CompileUrlError("the compile URL must name a port")
    if parts.query or parts.fragment:
        raise CompileUrlError("the compile URL must not have a query or a fragment")
    return CompileTarget(host=parts.hostname, port=port, path=parts.path or "/")


Transport = Callable[[CompileTarget, bytes, float], bytes]
"""POST the body, return the answer's body. Raises `CompileClientError`. Tests inject their own."""


def _peer_is_loopback(connection: http.client.HTTPConnection) -> bool:
    sock = connection.sock
    if sock is None:
        return False
    if sock.family not in (socket.AF_INET, socket.AF_INET6):
        return False
    peer = cast(tuple[object, ...], sock.getpeername())  # (host, port, ...) for both families
    host = peer[0]
    if not isinstance(host, str):
        return False
    try:
        address = ipaddress.ip_address(host.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    return address.is_loopback


def post_json(target: CompileTarget, body: bytes, timeout: float) -> bytes:
    """The real transport: one POST to the loopback server within `timeout` seconds overall."""
    deadline = time.monotonic() + timeout
    connection = http.client.HTTPConnection(target.host, target.port, timeout=timeout)
    try:
        try:
            connection.connect()
            if not _peer_is_loopback(connection):
                raise CompileClientError("the compile server is not on this machine")
            # No `Origin` and no forwarding header: the caller is the proxy, not a web page.
            connection.request(
                "POST",
                target.path,
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Connection": "close",
                },
            )
            sock = connection.sock
            if sock is not None:
                sock.settimeout(max(deadline - time.monotonic(), 0.001))
            response = connection.getresponse()
            if response.status != 200:
                raise CompileClientError(f"the compile server answered status {response.status}")
            chunks: list[bytes] = []
            size = 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise CompileClientError("the compile server did not answer in time")
                if sock is not None:
                    # Once the answer says "close" the connection object closes its socket (the
                    # response keeps the descriptor): then the timeout set before `getresponse`
                    # stays, and the deadline above still ends a slow answer after one more read.
                    with contextlib.suppress(OSError):
                        sock.settimeout(remaining)
                chunk = response.read(_CHUNK)
                if not chunk:
                    return b"".join(chunks)
                size += len(chunk)
                if size > MAX_RESPONSE:
                    raise CompileClientError("the compile server's answer is too large")
                chunks.append(chunk)
        except TimeoutError:
            raise CompileClientError("the compile server did not answer in time") from None
        except (OSError, http.client.HTTPException):
            raise CompileClientError("the compile server could not be reached") from None
    finally:
        connection.close()


class _CompileAnswer(NotaryModel):
    """The server's answer, read here without importing the server (`McpCompileResponse`)."""

    contract: IntentContract
    dropped: tuple[str, ...]


class CompileClient:
    def __init__(
        self,
        url: str,
        *,
        timeout: float = COMPILE_TIMEOUT,
        transport: Transport = post_json,
    ) -> None:
        """Raises `CompileUrlError` for a URL that is not loopback http with a port."""
        self._target = parse_compile_url(url)
        self._timeout = timeout
        self._transport = transport

    def compile(self, prompt: str, manifests: Sequence[ToolManifest]) -> IntentContract:
        """The contract the server compiled from `prompt` and `manifests`, unchecked.

        Raises `CompileClientError` (constant message) for anything but a valid answer. The caller
        decides whether to use it (`narrow`).
        """
        body = json.dumps(
            {"request": prompt, "manifests": [m.model_dump(mode="json") for m in manifests]}
        ).encode("utf-8")
        raw = self._transport(self._target, body, self._timeout)
        try:
            return _CompileAnswer.model_validate_json(raw).contract
        except ValidationError:
            raise CompileClientError(
                "the compile server's answer is not a valid contract"
            ) from None


def narrow(
    config_contract: IntentContract, compiled: IntentContract
) -> tuple[IntentContract | None, tuple[str, ...]]:
    """`(contract, ())` when `compiled` is no wider than the config's, else `(None, reasons)`.

    The compiler names its contract after the prompt (`contract-<hash>`) and sets `user_intent` to
    the prompt; `widening_reasons` wants both equal to the config's, so the candidate carries the
    config's two labels and every other field is the compiler's. The check is the core's function,
    unchanged: tools added, a manifest hash that differs from the one pinned at startup, a marker
    relaxed, a budget raised, a host or an authorization added are all reasons to refuse.
    """
    # The compiler only knows the server's tools. The synthetic tools of a resource read and a
    # prompt get are the config's own, unchanged, so a compiled contract keeps them.
    kept = tuple(
        scope
        for scope in config_contract.allowed_tools
        if scope.tool in CONTENT_TOOLS and all(c.tool != scope.tool for c in compiled.allowed_tools)
    )
    candidate = compiled.model_copy(
        update={
            "contract_id": config_contract.contract_id,
            "user_intent": config_contract.user_intent,
            "allowed_tools": (*compiled.allowed_tools, *kept),
        }
    )
    reasons = widening_reasons(config_contract, candidate)
    if reasons:
        return None, reasons
    return candidate, ()


class PromptCompiler:
    """Compile the first prompt of a run into a narrower contract, or keep the config's."""

    def __init__(
        self,
        client: CompileClient,
        config_contract: IntentContract,
        manifests: Sequence[ToolManifest],
    ) -> None:
        """`manifests` are the tools pinned at startup; only the contract's tools are sent (a
        tool outside the config can never be accepted, so the model is not offered one)."""
        names = {scope.tool for scope in config_contract.allowed_tools}
        self._client = client
        self._config_contract = config_contract
        self._manifests = tuple(m for m in manifests if m.name in names)

    def compile(self, prompt: str) -> IntentContract | None:
        """The contract to start the run with, or None to keep the config's. Never raises; the
        reason goes to stderr (never the prompt)."""
        try:
            compiled = self._client.compile(prompt, self._manifests)
        except CompileClientError as failure:
            diagnostic(f"compile: kept the config contract: {failure}")
            return None
        # fail closed: keep the (narrower) config contract
        except Exception as failure:
            diagnostic(f"compile: kept the config contract: failed ({type(failure).__name__})")
            return None
        accepted, reasons = narrow(self._config_contract, compiled)
        if accepted is None:
            shown = "; ".join(quoted(reason) for reason in reasons[:5])
            more = f" (+{len(reasons) - 5} more)" if len(reasons) > 5 else ""
            diagnostic(f"compile: kept the config contract: it would widen it: {shown}{more}")
            return None
        diagnostic(
            f"compile: the run starts with the contract compiled from the prompt "
            f"({len(accepted.allowed_tools)} of {len(self._config_contract.allowed_tools)} tools, "
            f"{len(accepted.authorized_irreversible)} irreversible authorized)"
        )
        return accepted

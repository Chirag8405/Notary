"""`POST /mcp/compile`: the Intent Compiler for the MCP proxy's first prompt (#265, phase 2).

The proxy (`notary-mcp-proxy --compile-url`) posts the user's first prompt and the manifests it
pinned at startup; the server answers with the contract `compile_contract` makes of them. The
caller is a process on this machine, never a page: the route is off unless `NOTARY_MCP_COMPILE=1`
and the app only hears a loopback peer with no reverse-proxy header and no `Origin` (see
`create_app`).

The answer is a PROPOSAL. The proxy uses it only when `widening_reasons(config_contract, compiled)`
is empty, so this route can at most narrow what the proxy's config allows; it never grants anything.
A failure answers with a fixed message: the model's reply, the prompt and the exception text are
never echoed.
"""

import logging
from collections.abc import Callable
from typing import Annotated, Self

from pydantic import Field, model_validator

from notary_core.models import IntentContract, NotaryModel
from notary_core.pinning import ToolManifest
from notary_core.policy.sensitive_params import DEFAULT_POLICY, PolicyTable
from notary_server.compiler import CompileError, compile_contract
from notary_server.groq_client import GroqClient
from notary_server.llm import DEFAULT_MODEL, LlmClient

MAX_PROMPT_CHARS = 8192
"""The longest prompt the proxy forwards (`control.MAX_PROMPT`); a longer request is refused."""
MAX_MANIFESTS = 64
MAX_MANIFEST_CHARS = 256 * 1024
"""Descriptions and schemas together; a request above it is refused (422)."""

DETAIL_UNAVAILABLE = "the compiler is not available"
DETAIL_NOT_COMPILED = "the request could not be compiled"
DETAIL_MODEL_FAILED = "the language model could not be reached"

LOG = logging.getLogger(__name__)


class McpCompileRequest(NotaryModel):
    request: Annotated[str, Field(min_length=1, max_length=MAX_PROMPT_CHARS)]
    """The user's prompt."""
    manifests: Annotated[tuple[ToolManifest, ...], Field(min_length=1, max_length=MAX_MANIFESTS)]
    """The tools the contract may name, as the proxy pinned them."""

    @model_validator(mode="after")
    def _manifests_fit(self) -> Self:
        size = sum(len(m.name) + len(m.description) + len(m.input_schema) for m in self.manifests)
        if size > MAX_MANIFEST_CHARS:
            raise ValueError("the manifests are too large")
        return self


class McpCompileResponse(NotaryModel):
    contract: IntentContract
    dropped: tuple[str, ...]
    """Proposal items the compiler discarded (`tool:<name>`, `host:<value>`, `authorize:<name>`)."""


class McpCompileError(Exception):
    """A refusal with an HTTP status and a fixed detail."""

    def __init__(self, status: int, detail: str) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail


class McpCompileService:
    """Compiles with the app's Groq client, built on the first request (never earlier)."""

    def __init__(
        self,
        *,
        available: bool,
        client_factory: Callable[[], LlmClient] = GroqClient,
        model: str = DEFAULT_MODEL,
        policy: PolicyTable = DEFAULT_POLICY,
    ) -> None:
        """`available`: whether a model key is set (`Settings.live_available`)."""
        self._available = available
        self._factory = client_factory
        self._model = model
        self._policy = policy
        self._client: LlmClient | None = None

    def compile(self, body: McpCompileRequest) -> McpCompileResponse:
        """Raises `McpCompileError` (503 no key, 422 not compilable, 502 the model failed)."""
        if not self._available:
            raise McpCompileError(503, DETAIL_UNAVAILABLE)
        try:
            if self._client is None:
                self._client = self._factory()
            compiled = compile_contract(
                body.request,
                body.manifests,
                self._client,
                policy=self._policy,
                model=self._model,
            )
        except CompileError:
            raise McpCompileError(422, DETAIL_NOT_COMPILED) from None
        except Exception as failure:
            LOG.warning("mcp compile: the model call failed (%s)", type(failure).__name__)
            raise McpCompileError(502, DETAIL_MODEL_FAILED) from None
        return McpCompileResponse(contract=compiled.contract, dropped=compiled.dropped)

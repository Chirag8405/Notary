"""Resources and prompts: the other server content that reaches the agent's context.

They are injection vectors exactly like tool results, so the proxy shows them labeled and logged
or not at all. Per server, `resources` and `prompts` in the config switch them on; without them
the capability is not declared and `resources/*` / `prompts/*` answer method-not-found.

- Resources. Only URIs under an `allow` prefix are listed or readable; a read outside answers an
  error WITHOUT contacting the server. Every text the agent gets back (the content, and the `uri`,
  `name`, `title`, `description` of a listing entry) is first labeled and logged through
  `Gateway.label_content` under the source `resource:<server>`, then rebuilt from the store, so
  the agent receives exactly the logged texts. Only a bounded `mimeType` token and an integer
  `size` pass through unlabeled; everything else the server sent is dropped. A read changes
  nothing, so it does not count against the budget, but the URI is a string the agent chose and
  the server receives: the part after the allowed prefix (the prefix is the config's) is judged by
  the monitor as a call of the synthetic tool `resources/read` (`Gateway.judge`, decision logged
  before the server is contacted).
- Prompts. The allowed prompts' definitions (name, title, description, arguments) are pinned at
  startup and `prompts/list` shows the pinned ones. `prompts/get` re-lists the owning server and
  refuses a prompt whose definition changed since (A10, a rug pull) before it asks for the prompt.
  The messages it returns are labeled and logged under `prompt:<server>`. The arguments of a get
  come from the agent, so they are never labeled as user-authored: they only name declared
  arguments with string values and go to the server, after the monitor has judged them as a call
  of the synthetic tool `prompts/get`.
- A decision other than ALLOW refuses the read with the failing checks (constant text). An
  ESCALATE is refused too: there is no card for a read.
- Not forwarded: subscriptions (`subscribe: false`), `list_changed` and `updated` notifications
  (the agent's view stays the pinned one).

The Gateway is not thread-safe: `handle` runs on the worker thread that owns it.
"""

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from urllib.parse import unquote

from pydantic import JsonValue

from notary_core.canon import sha256_hex
from notary_core.gateway import ToolResultField
from notary_core.models import Decision
from notary_mcp_proxy.backend import schema_text
from notary_mcp_proxy.client import McpClient, ServerError, diagnostic, quoted
from notary_mcp_proxy.config import (
    PROMPT_GET_TOOL,
    PUBLIC,
    RESOURCE_READ_TOOL,
    PromptPolicy,
    ProxyConfig,
    ResourcePolicy,
    content_manifest_hash,
    prompt_source,
    resource_source,
)
from notary_mcp_proxy.gateway import Gateway, RawCall
from notary_mcp_proxy.jsonrpc import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    RESOURCE_NOT_FOUND,
    JsonObject,
    as_list,
    as_object,
    as_str,
    error,
    result,
)
from notary_mcp_proxy.mcp_backend import encode_argument

RESOURCE_METHODS = frozenset({"resources/list", "resources/templates/list", "resources/read"})
PROMPT_METHODS = frozenset({"prompts/list", "prompts/get"})
QUEUED = frozenset({"resources/list", "resources/templates/list", "resources/read", "prompts/get"})
"""Methods that touch the Gateway or a server: they run on the worker thread, in arrival order."""
IGNORED_NOTIFICATIONS = frozenset(
    {
        "notifications/resources/list_changed",
        "notifications/resources/updated",
        "notifications/prompts/list_changed",
    }
)

MAX_URI = 2048
MAX_ENTRIES = 500
MAX_MESSAGES = 200
_MIME = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}/[A-Za-z0-9][A-Za-z0-9!#$&^_.+-]{0,126}"
    r"(?:;[ ]?charset=[A-Za-z0-9_.-]{1,40})?"
)
ROLES = frozenset({"user", "assistant"})

ERR_NOT_ALLOWED = "resource not found"
ERR_HALTED = "NOTARY halted: the content could not be logged, so it was not returned"
ERR_UNKNOWN_PROMPT = "unknown prompt"
ERR_PROMPT_CHANGED = "NOTARY refused the prompt: its definition changed since startup"
ERR_PROMPT_UNCHECKED = "NOTARY refused the prompt: its definition could not be checked"
ERR_BAD_CONTENT = "the server sent content NOTARY cannot label; nothing was returned"
ERR_REFUSED = "NOTARY refused the read"


class ContentError(Exception):
    """A request answered with a JSON-RPC error (constant text; never server-authored)."""

    def __init__(self, code: int, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True, slots=True)
class PromptPin:
    server: str
    name: str
    digest: str
    definition: JsonObject
    """What the agent is shown in `prompts/list`: the pinned definition."""
    arguments: frozenset[str]
    """The declared argument names."""


def safe_uri(uri: str) -> bool:
    """A bounded URI with no control characters, backslash or `..` segment (also encoded)."""
    if not uri or len(uri) > MAX_URI:
        return False
    if any(ord(ch) < 32 or ord(ch) == 127 or ch == "\\" for ch in uri):
        return False
    decoded = unquote(unquote(uri))
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in decoded):
        return False
    return ".." not in re.split(r"[/\\]", decoded)


def mime_token(value: JsonValue | None) -> str | None:
    """A `mimeType` that is a plain media-type token, else None (it is dropped)."""
    return value if isinstance(value, str) and _MIME.fullmatch(value) else None


def prompt_definition(raw: JsonObject) -> JsonObject:
    """name, title, description and arguments of a prompt, as the server reported them."""
    name = as_str(raw.get("name"))
    if not name:
        raise ServerError("the server broke the protocol", detail="a prompt has no name")
    definition: JsonObject = {"name": name}
    for key in ("title", "description"):
        value = raw.get(key)
        if value is None:
            continue
        if not isinstance(value, str):
            raise ServerError(
                "the server broke the protocol", detail=f"prompt {quoted(name)}: {key} not text"
            )
        definition[key] = value
    arguments = raw.get("arguments")
    if arguments is not None:
        listed = as_list(arguments)
        if listed is None or any(as_object(item) is None for item in listed):
            raise ServerError(
                "the server broke the protocol",
                detail=f"prompt {quoted(name)}: arguments are not a list of objects",
            )
        definition["arguments"] = listed
    return definition


def prompt_digest(definition: JsonObject) -> str:
    """Hash of the canonical text of the definition (key order and whitespace do not matter)."""
    return sha256_hex(schema_text(definition))


def _argument_names(definition: JsonObject) -> frozenset[str]:
    names = [
        as_str((as_object(item) or {}).get("name"))
        for item in as_list(definition.get("arguments")) or []
    ]
    return frozenset(name for name in names if name is not None)


def _failing(decision: Decision) -> str:
    """`check: CODE` for every check that did not pass (constant strings of the monitor)."""
    return "; ".join(f"{r.check}: {r.code}" for r in decision.reasons if r.outcome != "pass")


def _field(name: str, text: str) -> ToolResultField:
    return ToolResultField(name=name, text=text, unit=None)


class ContentProxy:
    def __init__(
        self, config: ProxyConfig, clients: Mapping[str, McpClient], gateway: Gateway
    ) -> None:
        """Pins the allowed prompts of every server now.

        Raises `ValueError` when an allowed prompt is not reported (like a missing tool) and
        `ServerError` when a server cannot list its prompts.
        """
        self._gateway = gateway
        self._clients = dict(clients)
        self._resources: dict[str, ResourcePolicy] = {
            name: spec.resources for name, spec in config.servers.items() if spec.resources
        }
        self._prompts: dict[str, PromptPolicy] = {
            name: spec.prompts for name, spec in config.servers.items() if spec.prompts
        }
        self._counts: dict[str, int] = {}
        self._pins: dict[str, PromptPin] = {}
        for server, policy in self._prompts.items():
            self._pin_prompts(server, policy)

    @property
    def resources(self) -> bool:
        return bool(self._resources)

    @property
    def prompts(self) -> bool:
        return bool(self._prompts)

    def capabilities(self) -> JsonObject:
        """What `initialize` declares: only the configured features, never subscriptions."""
        found: JsonObject = {}
        if self._resources:
            found["resources"] = {"subscribe": False, "listChanged": False}
        if self._prompts:
            found["prompts"] = {"listChanged": False}
        return found

    def serves(self, method: str) -> bool:
        return (method in RESOURCE_METHODS and self.resources) or (
            method in PROMPT_METHODS and self.prompts
        )

    # -- pinning ---------------------------------------------------------------------------------

    def _listed(self, server: str) -> dict[str, tuple[str | None, JsonObject]]:
        """Name -> (digest, definition) of what the server reports now.

        The digest is None for a name reported twice: it can never equal a pin.
        """
        found: dict[str, tuple[str | None, JsonObject]] = {}
        for raw in self._clients[server].list_paged("prompts/list", "prompts"):
            definition = prompt_definition(raw)
            name = str(definition["name"])
            found[name] = (
                (None, definition) if name in found else (prompt_digest(definition), definition)
            )
        return found

    def _pin_prompts(self, server: str, policy: PromptPolicy) -> None:
        listed = self._listed(server)
        for name in policy.allow:
            if name not in listed:
                raise ValueError(f"the server {server!r} does not report prompt {name!r}")
            digest, definition = listed[name]
            if digest is None:
                raise ValueError(f"the server {server!r} reports prompt {name!r} twice")
            self._pins[name] = PromptPin(
                server=server,
                name=name,
                digest=digest,
                definition=definition,
                arguments=_argument_names(definition),
            )
            diagnostic(f"pinned prompt {quoted(name)} of {server}: {digest}")

    # -- dispatch --------------------------------------------------------------------------------

    def handle(self, request_id: JsonValue, method: str, params: JsonObject) -> JsonObject:
        """The full JSON-RPC answer to one resource or prompt request."""
        try:
            if method == "resources/list":
                return result(request_id, self._list_resources())
            if method == "resources/templates/list":
                return result(request_id, self._list_templates())
            if method == "resources/read":
                return result(request_id, self._read(params))
            if method == "prompts/list":
                return result(request_id, {"prompts": self.pinned_prompts()})
            return result(request_id, self._get_prompt(params))
        except ContentError as failure:
            return error(request_id, failure.code, str(failure))

    def pinned_prompts(self) -> list[JsonValue]:
        return [dict(self._pins[name].definition) for name in sorted(self._pins)]

    def _next(self, prefix: str) -> str:
        self._counts[prefix] = self._counts.get(prefix, 0) + 1
        return f"{prefix}{self._counts[prefix]}"

    def _label(
        self,
        source: str,
        record_id: str,
        fields: Sequence[ToolResultField],
        readers: tuple[str, ...],
    ) -> dict[str, str]:
        """Label and log `fields`; the texts are read back from the store by field name."""
        refs = self._gateway.label_content(source, record_id, fields, readers)
        if refs is None:
            raise ContentError(INTERNAL_ERROR, ERR_HALTED)
        texts: dict[str, str] = {}
        for ref in refs:
            value = self._gateway.store.get(ref.id)
            if value is None:
                raise ContentError(INTERNAL_ERROR, ERR_HALTED)
            texts[ref.id[len(record_id) + 1 :]] = value.text
        return texts

    def _allow(self, tool: str, args: dict[str, str]) -> None:
        """Have the monitor judge the read; raise `ContentError` unless it says ALLOW.

        The decision is in the audit chain before the server is contacted. The failing checks are
        constant text (`check: CODE`), never the URI or an argument.
        """
        call = RawCall(
            call_id=self._next("read" if tool == RESOURCE_READ_TOOL else "get"),
            tool=tool,
            args=args,
        )
        decision = self._gateway.judge(call, content_manifest_hash(tool))
        if decision is None:
            raise ContentError(INTERNAL_ERROR, ERR_HALTED)
        if decision.verdict != "ALLOW":
            diagnostic(f"{tool} refused: {_failing(decision)}")
            raise ContentError(INTERNAL_ERROR, f"{ERR_REFUSED}: {_failing(decision)}")

    # -- resources -------------------------------------------------------------------------------

    def _owner(self, uri: str) -> str | None:
        """The server whose allow list covers `uri` (prefixes of two servers never overlap)."""
        if not safe_uri(uri):
            return None
        for server, policy in self._resources.items():
            if any(uri.startswith(prefix) for prefix in policy.allow):
                return server
        return None

    def _listing(self, server: str, method: str, key: str) -> list[JsonObject]:
        try:
            return self._clients[server].list_paged(method, key)[:MAX_ENTRIES]
        except ServerError as failure:
            # One dead server does not hide the others' resources.
            diagnostic(f"{method} on {server}: {type(failure).__name__}: {quoted(failure.detail)}")
            return []

    def _list_resources(self) -> JsonObject:
        return {"resources": self._entries("resources/list", "resources", "rl", "uri")}

    def _list_templates(self) -> JsonObject:
        return {
            "resourceTemplates": self._entries(
                "resources/templates/list", "resourceTemplates", "rt", "uriTemplate"
            )
        }

    def _entries(self, method: str, key: str, prefix: str, uri_key: str) -> list[JsonValue]:
        """The allowed entries of every server, with their texts labeled, logged, then rebuilt."""
        shown: list[JsonValue] = []
        for server, policy in self._resources.items():
            kept: list[tuple[JsonObject, str]] = []
            for item in self._listing(server, method, key):
                locator = as_str(item.get(uri_key))
                if locator is not None and self._allowed_entry(policy, locator, uri_key):
                    kept.append((item, locator))
            if not kept:
                continue
            record = self._next(prefix)
            fields: list[ToolResultField] = []
            for index, (item, locator) in enumerate(kept):
                fields.append(_field(f"e{index:03d}.{uri_key}", locator))
                fields.append(_field(f"e{index:03d}.name", as_str(item.get("name")) or locator))
                for extra in ("title", "description"):
                    text = as_str(item.get(extra))
                    if text is not None:
                        fields.append(_field(f"e{index:03d}.{extra}", text))
            texts = self._label(resource_source(server), record, fields, policy.readers)
            for index, (item, _) in enumerate(kept):
                entry: JsonObject = {}
                for name in (uri_key, "name", "title", "description"):
                    text = texts.get(f"e{index:03d}.{name}")
                    if text is not None:
                        entry[name] = text
                mime = mime_token(item.get("mimeType"))
                if mime is not None:
                    entry["mimeType"] = mime
                size = item.get("size")
                if isinstance(size, int) and not isinstance(size, bool) and size >= 0:
                    entry["size"] = size
                shown.append(entry)
        return shown

    @staticmethod
    def _allowed_entry(policy: ResourcePolicy, locator: str, uri_key: str) -> bool:
        # A template is shown when its fixed part lies under an allowed prefix.
        fixed = locator.split("{", 1)[0] if uri_key == "uriTemplate" else locator
        return safe_uri(fixed) and any(fixed.startswith(prefix) for prefix in policy.allow)

    def _read(self, params: JsonObject) -> JsonObject:
        uri = as_str(params.get("uri"))
        if uri is None:
            raise ContentError(INVALID_PARAMS, "missing uri")
        server = self._owner(uri)
        if server is None:
            diagnostic(f"resources/read refused: {quoted(uri)} is outside the allow list")
            raise ContentError(RESOURCE_NOT_FOUND, ERR_NOT_ALLOWED)
        policy = self._resources[server]
        # The prefix is the config's, trusted; the monitor judges what the agent chose after it.
        prefix = max((p for p in policy.allow if uri.startswith(p)), key=len)
        self._allow(RESOURCE_READ_TOOL, {"server": server, "uri": uri[len(prefix) :]})
        try:
            answer = self._clients[server].request("resources/read", {"uri": uri})
        except ServerError as failure:
            diagnostic(
                f"resources/read on {server}: {type(failure).__name__}: {quoted(failure.detail)}"
            )
            raise ContentError(INTERNAL_ERROR, str(failure)) from failure
        items = as_list(answer.get("contents"))
        if items is None or len(items) > MAX_ENTRIES:
            diagnostic(f"resources/read on {server}: contents missing or too many")
            raise ContentError(INTERNAL_ERROR, ERR_BAD_CONTENT)
        fields: list[ToolResultField] = []
        kinds: list[tuple[str, str, str | None]] = []
        for index, item in enumerate(items):
            entry = as_object(item)
            text = None if entry is None else as_str(entry.get("text"))
            blob = None if entry is None else as_str(entry.get("blob"))
            if entry is None or (text is None) == (blob is None):
                diagnostic(f"resources/read on {server}: content {index} has neither text nor blob")
                raise ContentError(INTERNAL_ERROR, ERR_BAD_CONTENT)
            kind = "text" if text is not None else "blob"
            name = f"content_{index:03d}"
            fields.append(_field(name, text if text is not None else str(blob)))
            kinds.append((kind, name, mime_token(entry.get("mimeType"))))
        texts = self._label(resource_source(server), self._next("rr"), fields, policy.readers)
        # The agent is told the URI it asked for, never one the server chose.
        contents: list[JsonValue] = []
        for kind, name, mime in kinds:
            shown: JsonObject = {"uri": uri, kind: texts[name]}
            if mime is not None:
                shown["mimeType"] = mime
            contents.append(shown)
        return {"contents": contents}

    # -- prompts ---------------------------------------------------------------------------------

    def _get_prompt(self, params: JsonObject) -> JsonObject:
        name = as_str(params.get("name"))
        if name is None:
            raise ContentError(INVALID_PARAMS, "missing prompt name")
        pin = self._pins.get(name)
        if pin is None:
            raise ContentError(INVALID_PARAMS, ERR_UNKNOWN_PROMPT)
        given = self._prompt_arguments(pin, params.get("arguments"))
        self._allow(
            PROMPT_GET_TOOL,
            {
                "server": pin.server,
                "name": name,
                "arguments": json.dumps(given, sort_keys=True, separators=(",", ":")),
            },
        )
        try:
            current = self._listed(pin.server).get(name)
        except ServerError as failure:
            diagnostic(
                f"prompts/list on {pin.server}: {type(failure).__name__}: {quoted(failure.detail)}"
            )
            raise ContentError(INTERNAL_ERROR, ERR_PROMPT_UNCHECKED) from failure
        observed = None if current is None else current[0]
        if observed != pin.digest:
            diagnostic(
                f"prompt {quoted(name)} of {pin.server}: DRIFT (pinned {pin.digest}, "
                f"now {observed}); refused"
            )
            raise ContentError(INTERNAL_ERROR, ERR_PROMPT_CHANGED)
        request: JsonObject = {"name": name}
        if given:
            request["arguments"] = dict(given)
        try:
            answer = self._clients[pin.server].request("prompts/get", request)
        except ServerError as failure:
            diagnostic(
                f"prompts/get on {pin.server}: {type(failure).__name__}: {quoted(failure.detail)}"
            )
            raise ContentError(INTERNAL_ERROR, str(failure)) from failure
        return self._prompt_answer(pin, answer)

    @staticmethod
    def _prompt_arguments(pin: PromptPin, raw: JsonValue | None) -> dict[str, str]:
        """The agent's arguments: declared names, string values. Never trusted, never labeled
        as the user's."""
        if raw is None:
            return {}
        given = as_object(raw)
        if given is None:
            raise ContentError(INVALID_PARAMS, "arguments must be an object")
        checked: dict[str, str] = {}
        for argument, value in given.items():
            if argument not in pin.arguments:
                raise ContentError(INVALID_PARAMS, "unknown prompt argument")
            if not isinstance(value, str):
                raise ContentError(INVALID_PARAMS, "prompt arguments must be strings")
            checked[argument] = value
        return checked

    def _prompt_answer(self, pin: PromptPin, answer: JsonObject) -> JsonObject:
        messages = as_list(answer.get("messages"))
        if messages is None or len(messages) > MAX_MESSAGES:
            diagnostic(f"prompts/get on {pin.server}: messages missing or too many")
            raise ContentError(INTERNAL_ERROR, ERR_BAD_CONTENT)
        fields: list[ToolResultField] = []
        roles: list[str] = []
        description = as_str(answer.get("description"))
        if description is not None:
            fields.append(_field("description", description))
        for index, item in enumerate(messages):
            entry = as_object(item)
            role = None if entry is None else as_str(entry.get("role"))
            content = None if entry is None else entry.get("content")
            if role is None or role not in ROLES or as_object(content) is None:
                diagnostic(f"prompts/get on {pin.server}: message {index} is malformed")
                raise ContentError(INTERNAL_ERROR, ERR_BAD_CONTENT)
            roles.append(role)
            block = as_object(content) or {}
            text = as_str(block.get("text")) if block.get("type") == "text" else None
            fields.append(
                _field(
                    f"message_{index:03d}", text if text is not None else encode_argument(content)
                )
            )
        texts = self._label(prompt_source(pin.server), self._next("pg"), fields, PUBLIC)
        shown: JsonObject = {
            "messages": [
                {
                    "role": role,
                    "content": {"type": "text", "text": texts[f"message_{index:03d}"]},
                }
                for index, role in enumerate(roles)
            ]
        }
        if "description" in texts:
            shown["description"] = texts["description"]
        return shown

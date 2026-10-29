"""`notary-mcp-proxy --config notary.json`: an MCP server in front of other MCP servers.

The agent connects over stdio (the default) or, with `--http HOST:PORT --token-file PATH`, over
MCP Streamable HTTP. The servers behind it are stdio child processes or HTTP endpoints. In stdio
mode stdout carries only MCP messages; diagnostics go to stderr.
"""

import argparse
import json
import os
import signal
import sys
import threading
import uuid
from collections.abc import Mapping, Sequence
from functools import partial
from pathlib import Path
from types import FrameType

from notary_core.audit import append
from notary_core.gateway import make_labeler
from notary_core.models import RunStarted
from notary_core.monitor import decide
from notary_core.pinning import ToolManifest
from notary_core.resolver import ArgumentResolver
from notary_mcp_proxy.approvals import ApprovalDesk, printable
from notary_mcp_proxy.audit_log import AuditWriteError, RunLog, durable_append
from notary_mcp_proxy.auth_throttle import (
    DEFAULT_LOCKOUT_SECONDS,
    DEFAULT_MAX_FAILURES,
    MAX_FAILURES_LIMIT,
    MAX_LOCKOUT_SECONDS,
    validate_throttle,
)
from notary_mcp_proxy.check import check_config, render_report
from notary_mcp_proxy.client import McpClient, ServerError, StdioClient
from notary_mcp_proxy.compile_client import (
    CompileClient,
    CompileUrlError,
    PromptCompiler,
)
from notary_mcp_proxy.config import (
    ProxyConfig,
    ServerSpec,
    StdioServerSpec,
    build_contract,
    build_labeling,
    build_ledger,
    build_policy,
    resolve_headers,
    tool_fields,
    tool_readers,
)
from notary_mcp_proxy.content import ContentProxy, prompt_definition
from notary_mcp_proxy.control import (
    ControlError,
    ControlServer,
    default_path,
    find_socket,
    render_pending,
    send,
)
from notary_mcp_proxy.first_seen import (
    approve_rows,
    load_approved,
    render_review,
    review_tools,
    save_approved,
)
from notary_mcp_proxy.gateway import AuditAppend, Gateway
from notary_mcp_proxy.guard import hook_reason, run_hook
from notary_mcp_proxy.http_client import HttpClient
from notary_mcp_proxy.http_server import (
    DEFAULT_BIND,
    AgentEndpoint,
    BindError,
    HttpSettings,
    TokenFileError,
    parse_bind,
    read_token_file,
)
from notary_mcp_proxy.prompt_hook import MAX_INPUT, forward_prompt
from notary_mcp_proxy.routing import RoutingError, build_routing
from notary_mcp_proxy.server import ProxyServer, serve

DEFAULT_APPROVAL_TIMEOUT = 120.0
SCENARIO = "mcp-proxy"
CONTROL_SUFFIX = ".control.json"
"""`<run_id>.control.json` next to the chain: where this run's control socket is (#262)."""


def _log(text: str) -> None:
    print(f"notary-mcp-proxy: {text}", file=sys.stderr, flush=True)


def write_control_file(directory: Path, run_id: str, socket_path: Path) -> Path:
    """Announce the control socket as `directory/<run_id>.control.json` (`{"socket": "<abs>"}`).

    The file is private (mode 0600) and replaced atomically, so a reader never sees half of it.
    The X-ray server reads it to forward an approval from the endorsement card; it validates the
    path again before it connects.
    """
    target = directory / f"{run_id}{CONTROL_SUFFIX}"
    staging = directory / f"{run_id}{CONTROL_SUFFIX}.tmp"
    body = json.dumps({"socket": str(socket_path.resolve())}).encode("utf-8")
    descriptor = os.open(staging, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
    # cleanup only, then re-raise
    except BaseException:
        staging.unlink(missing_ok=True)
        raise
    os.chmod(staging, 0o600)
    os.replace(staging, target)
    return target


def build_server(
    config: ProxyConfig,
    client: McpClient,
    *,
    run_id: str,
    audit_append: AuditAppend = append,
    desk: ApprovalDesk | None = None,
    control_hint: str = "",
    reject_unanswered: bool = False,
    compile_client: CompileClient | None = None,
) -> ProxyServer:
    """`build_servers` for a config with one server."""
    (name,) = config.servers
    return build_servers(
        config,
        {name: client},
        run_id=run_id,
        audit_append=audit_append,
        desk=desk,
        control_hint=control_hint,
        reject_unanswered=reject_unanswered,
        compile_client=compile_client,
    )


def build_servers(
    config: ProxyConfig,
    clients: Mapping[str, McpClient],
    *,
    run_id: str,
    audit_append: AuditAppend = append,
    desk: ApprovalDesk | None = None,
    control_hint: str = "",
    reject_unanswered: bool = False,
    compile_client: CompileClient | None = None,
) -> ProxyServer:
    """Pin every server's tools, freeze one contract and wrap one Gateway around all of them.

    `audit_append` stores every audit entry; `durable_append(log)` makes each one durable before
    the Gateway goes on. `run_started` is appended here, so it is the first entry on disk.
    With a `compile_client` (`--compile-url`) it is deferred instead: the contract is settled
    before it is written, by the first prompt (compiled, and only if it narrows the config's) or
    else by the first event of any kind (the config's). Either way it is the first entry.
    `desk` is where escalated calls wait for the user; without one, `reject_unanswered` rejects
    every escalation at once (`--control none`) and otherwise the endorsement stays pending.

    Raises `RoutingError` when a contract name is also reported by another server tool, and
    `ValueError` when a configured tool is not reported.
    """
    for client in clients.values():
        client.initialize()
    policy = build_policy(config)
    backend = build_routing(
        config, clients, policy=policy, readers=tool_readers(config), fields=tool_fields(config)
    )
    pinned = backend.list_tools()
    clashes = backend.collisions()
    if clashes:
        raise RoutingError("; ".join(clashes))
    contract = build_contract(config, pinned)
    gateway = Gateway(
        backend=backend,
        contract=contract,
        ledger=build_ledger(config),
        monitor=partial(decide, policy=policy),
        labeler=make_labeler(build_labeling(config)),
        resolver=ArgumentResolver(),
        run_id=run_id,
        policy=policy,
        audit_append=audit_append,
    )
    gateway.pin_session()
    content = ContentProxy(config, clients, gateway)  # pins the allowed prompts, or fails
    if compile_client is None:
        gateway.emit(
            lambda run, lane, seq: RunStarted(
                type="run_started",
                run_id=run,
                lane=lane,
                seq=seq,
                scenario=SCENARIO,
                contract=contract,
                classifier=None,
            )
        )
    else:
        gateway.defer_start(SCENARIO)
    server = ProxyServer(
        gateway,
        backend.pinned_definitions(),
        desk,
        control_hint=control_hint,
        reject_unanswered=reject_unanswered,
        elicitation=config.approvals.elicitation,
        content=content if content.resources or content.prompts else None,
        prompt_compiler=(
            None if compile_client is None else PromptCompiler(compile_client, contract, pinned)
        ),
    )
    for client in clients.values():
        client.on_notification = server.on_server_notification
    return server


def _hook_deny(reason: str) -> int:
    """Exit 2 is the only code that blocks a tool in Claude Code (stderr goes to the model)."""
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": reason,
                }
            }
        )
    )
    print(reason, file=sys.stderr, flush=True)
    return 2


def hook_main(argv: Sequence[str]) -> int:
    """`hook pre-tool-use --policy PATH`: allow = no output, exit 0; deny = exit 2."""
    parser = argparse.ArgumentParser(prog="notary-mcp-proxy hook pre-tool-use")
    parser.add_argument("--policy", type=Path, required=True, help="guard policy (JSON)")
    args = parser.parse_args(argv)  # a usage error exits 2, which also blocks
    policy_path: Path = args.policy
    try:
        try:
            policy_text: str | None = policy_path.read_text(encoding="utf-8")
        except (OSError, ValueError):
            policy_text = None
        try:
            stdin_text = sys.stdin.buffer.read().decode("utf-8")
        except (OSError, ValueError):
            stdin_text = ""
        output = run_hook(stdin_text, policy_text)
        if not output:
            return 0
        print(output)
        print(hook_reason(output), file=sys.stderr, flush=True)
        return 2
    # fail closed: exit 2 blocks the tool
    except Exception as error:
        return _hook_deny(f"NOTARY guard: internal error ({type(error).__name__}); denied")


def prompt_hook_main(argv: Sequence[str]) -> int:
    """`hook user-prompt-submit [--control PATH]`: hand the user's prompt to the proxy.

    ALWAYS exits 0 and prints nothing on stdout. For this Claude Code event exit 2 erases the
    user's prompt and stdout on exit 0 may reach the model, so a failure of any kind (no proxy
    running, an unreachable socket, a refusal, a bug) is one line on stderr and the prompt goes
    on, as untrusted as it was without the hook.
    """
    try:
        parser = argparse.ArgumentParser(prog="notary-mcp-proxy hook user-prompt-submit")
        parser.add_argument(
            "--control", type=Path, help="the proxy's control socket (default: the only one found)"
        )
        args = parser.parse_args(argv)
        control: Path | None = args.control
        try:
            raw = sys.stdin.buffer.read(MAX_INPUT + 1)
            stdin_text = raw.decode("utf-8") if len(raw) <= MAX_INPUT else ""
        except (OSError, ValueError):
            stdin_text = ""
        value_id, why = forward_prompt(stdin_text, control)
        if value_id is None:
            _log(f"hook user-prompt-submit: the prompt was not forwarded: {why}")
        else:
            _log(f"hook user-prompt-submit: the prompt is the trusted value {value_id}")
    except SystemExit:
        pass  # a usage error: argparse printed it to stderr; it must not exit 2 here
    # must exit 0 whatever happens; a prompt that is not forwarded is never a trusted value
    except Exception as failure:
        _log(f"hook user-prompt-submit: failed ({type(failure).__name__}); the prompt goes on")
    return 0


def _load_config(path: Path) -> ProxyConfig | None:
    try:
        return ProxyConfig.model_validate_json(path.read_bytes())
    except (OSError, ValueError) as failure:
        _log(f"cannot load config {path.name}: {type(failure).__name__}: {failure}")
        return None


def _add_review_flags(parser: argparse.ArgumentParser) -> None:
    """The first-seen review flags of `check`; `--approve` includes `--review`."""
    parser.add_argument(
        "--review",
        action="store_true",
        help="show each tool's description and schema and whether it is approved",
    )
    parser.add_argument(
        "--approve",
        action="store_true",
        help="review, then record the tools' hashes once confirmed",
    )
    parser.add_argument("--yes", action="store_true", help="with --approve: confirm without asking")
    parser.add_argument(
        "--approved-file",
        type=Path,
        default=None,
        help="where approvals are kept (default: next to CONFIG)",
    )


def check_main(argv: Sequence[str]) -> int:
    """`check --config CONFIG [--json]`: exit 0 clean, 1 an error finding, 2 could not check."""
    parser = argparse.ArgumentParser(prog="notary-mcp-proxy check")
    parser.add_argument("--config", type=Path, required=True, help="proxy config (JSON)")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    _add_review_flags(parser)
    args = parser.parse_args(argv)
    config_path: Path = args.config
    config = _load_config(config_path)
    if config is None:
        return 2
    clients: dict[str, McpClient] = {}
    try:
        clients = _start_clients(config, config_path)
        for client in clients.values():
            client.initialize()
        backend = build_routing(config, clients, policy=build_policy(config), readers={}, fields={})
        manifests = backend.list_tools()
        schemas = {tool.name: tool.input_schema for tool in backend.pinned_definitions()}
        collisions = backend.collisions()
        prompts = {
            name: [
                str(prompt_definition(raw)["name"])
                for raw in clients[name].list_paged("prompts/list", "prompts")
            ]
            for name, spec in config.servers.items()
            if spec.prompts is not None
        }
    except (ServerError, OSError) as failure:
        detail = failure.detail if isinstance(failure, ServerError) else str(failure)
        _log(f"a server failed to start or list its tools: {type(failure).__name__}: {detail}")
        return 2
    finally:
        _close_all(clients)
    report = check_config(config, manifests, schemas, collisions, prompts)
    print(report.model_dump_json(indent=2) if args.json else render_report(report), end="")
    if args.json:
        print()
    if args.review or args.approve:
        approved_path: Path = args.approved_file or config_path.with_suffix(".approved-tools.json")
        status = _review_tools(manifests, approved_path, approve=args.approve, assume_yes=args.yes)
        if status != 0:
            return status
    return 0 if report.ok else 1


def _review_tools(
    manifests: Sequence[ToolManifest], approved_path: Path, *, approve: bool, assume_yes: bool
) -> int:
    """Show the first-seen review; with `approve`, record it after a confirmation."""
    try:
        approved = load_approved(approved_path)
    except (OSError, ValueError) as failure:
        _log(f"cannot read {approved_path.name}: {type(failure).__name__}")
        return 2
    rows = review_tools(manifests, approved)
    print(render_review(rows), end="")
    pending = [row for row in rows if row.state != "unchanged"]
    if not approve or not pending:
        return 0
    if not assume_yes:
        if not sys.stdin.isatty():
            _log("approval needs a person at a terminal; pass --yes to confirm without asking")
            return 1
        if input(f"approve {len(pending)} tool(s)? [y/N] ").strip().lower() not in ("y", "yes"):
            _log("not approved; nothing written")
            return 1
    save_approved(approved_path, approve_rows(rows, approved))
    _log(f"approved {len(pending)} tool(s) in {approved_path.name}")
    return 0


def _start_clients(
    config: ProxyConfig, config_path: Path, env: Mapping[str, str] | None = None
) -> dict[str, McpClient]:
    """Connect to every server; on a failure stop the ones started.

    A stdio server is started in the config file's directory. An HTTP server's header values
    are resolved from `env` (default: the process environment) here, so a missing variable fails
    startup; no connection is made until `initialize`.
    """
    started: dict[str, McpClient] = {}
    variables = os.environ if env is None else env
    try:
        for name, spec in config.servers.items():
            if isinstance(spec, StdioServerSpec):
                started[name] = StdioClient(
                    spec.command,
                    cwd=config_path.resolve().parent,
                    timeout_seconds=spec.timeout_seconds,
                )
            else:
                started[name] = HttpClient(
                    spec.url,
                    headers=resolve_headers(name, spec, variables),
                    timeout_seconds=spec.timeout_seconds,
                )
    # cleanup only, then re-raise
    except BaseException:
        _close_all(started)
        raise
    return started


def _describe(spec: ServerSpec) -> str:
    """For the log: the command, or the URL (never the headers)."""
    return " ".join(spec.command) if isinstance(spec, StdioServerSpec) else spec.url


def _close_all(clients: Mapping[str, McpClient]) -> None:
    for client in clients.values():
        client.close()


def serve_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="notary-mcp-proxy [serve]", description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="proxy config (JSON)")
    parser.add_argument(
        "--audit-dir",
        type=Path,
        help="write this run's audit chain and anchor here (<run>.chain.jsonl, <run>.anchor.json)",
    )
    parser.add_argument(
        "--control",
        help=(
            "control socket on which the user approves or rejects escalations "
            f"(default {default_path('<run>')}); 'none' rejects every escalation at once"
        ),
    )
    parser.add_argument(
        "--approval-timeout",
        type=float,
        default=DEFAULT_APPROVAL_TIMEOUT,
        help="seconds an escalated call waits for the user; no answer counts as a rejection",
    )
    parser.add_argument(
        "--compile-url",
        metavar="URL",
        help=(
            "compile the contract from the user's FIRST prompt: POST it to this NOTARY server "
            "route (http://127.0.0.1:PORT/mcp/compile, loopback only). The result is used only if "
            "it is no wider than the config's contract; otherwise, or on any failure, the config's "
            "is. Needs the user-prompt-submit hook. run_started is then written at the first event"
        ),
    )
    parser.add_argument(
        "--http",
        metavar="HOST:PORT",
        help=(
            "serve the agent over MCP Streamable HTTP at http://HOST:PORT/mcp instead of stdio "
            f"(e.g. {DEFAULT_BIND}). Needs --token-file; binds to loopback only unless "
            "--allow-remote-bind"
        ),
    )
    parser.add_argument(
        "--token-file",
        type=Path,
        metavar="PATH",
        help=(
            "with --http: the file holding the bearer token every request must present "
            "(Authorization: Bearer ...). It must not be readable by group or others (chmod 600); "
            "try: openssl rand -hex 32"
        ),
    )
    parser.add_argument(
        "--allow-origin",
        action="append",
        default=[],
        metavar="ORIGIN",
        help=(
            "with --http: accept requests whose Origin header is exactly this (e.g. "
            "http://localhost:3000); repeatable. By default a request with an Origin is refused "
            "(403); a request without one (a command-line client) is not affected"
        ),
    )
    parser.add_argument(
        "--allow-remote-bind",
        action="store_true",
        help="with --http: allow a HOST that is not loopback (anything that reaches the port can "
        "try the token; put TLS in front of it)",
    )
    parser.add_argument(
        "--auth-max-failures",
        type=int,
        default=DEFAULT_MAX_FAILURES,
        metavar="N",
        help=(
            "with --http: wrong tokens from one address that lock it out (default "
            f"{DEFAULT_MAX_FAILURES}, 1 to {MAX_FAILURES_LIMIT})"
        ),
    )
    parser.add_argument(
        "--auth-lockout-seconds",
        type=float,
        default=DEFAULT_LOCKOUT_SECONDS,
        metavar="S",
        help=(
            "with --http: how long a locked-out address gets 429 for every request, and the "
            f"window the failures must fall in (default {DEFAULT_LOCKOUT_SECONDS:g}, above 0 "
            f"to {MAX_LOCKOUT_SECONDS:g}). The throttle cannot be turned off"
        ),
    )
    parser.add_argument(
        "--tls-terminated",
        action="store_true",
        help="with --http: a TLS reverse proxy fronts a non-loopback bind (silences the "
        "plain-HTTP warning; the proxy cannot check it)",
    )
    args = parser.parse_args(argv)
    config_path: Path = args.config
    audit_dir: Path | None = args.audit_dir
    compile_url: str | None = args.compile_url
    endpoint: AgentEndpoint | None = None
    if args.http is None:
        if (
            args.token_file is not None
            or args.allow_origin
            or args.allow_remote_bind
            or args.tls_terminated
            or args.auth_max_failures != DEFAULT_MAX_FAILURES
            or args.auth_lockout_seconds != DEFAULT_LOCKOUT_SECONDS
        ):
            parser.error(
                "--token-file, --allow-origin, --allow-remote-bind, --tls-terminated, "
                "--auth-max-failures and --auth-lockout-seconds need --http"
            )
    else:
        if args.token_file is None:
            parser.error(
                "--http needs --token-file (the proxy does not serve HTTP without a token)"
            )
        try:
            validate_throttle(args.auth_max_failures, args.auth_lockout_seconds)
            host, port = parse_bind(args.http, allow_remote=args.allow_remote_bind)
            settings = HttpSettings(
                token=read_token_file(str(args.token_file)),
                host=host,
                port=port,
                allowed_origins=frozenset(args.allow_origin),
                allow_remote=args.allow_remote_bind,
                auth_max_failures=args.auth_max_failures,
                auth_lockout_seconds=args.auth_lockout_seconds,
                tls_terminated=args.tls_terminated,
            )
        except (BindError, TokenFileError, ValueError) as failure:
            parser.error(str(failure))  # a usage error: exit 2 before anything starts
        try:
            endpoint = AgentEndpoint(settings)
        except OSError as failure:
            _log(f"cannot listen on {args.http}: {failure.strerror}")
            return 2
    compile_client: CompileClient | None = None
    if compile_url is not None:
        if args.control == "none":
            parser.error("--compile-url needs the control socket (the prompt arrives on it)")
        try:
            compile_client = CompileClient(compile_url)
        except CompileUrlError as failure:
            parser.error(str(failure))  # a usage error: exit 2 before anything starts
    control_arg: str | None = args.control
    timeout: float = args.approval_timeout
    if timeout <= 0:
        parser.error("--approval-timeout must be positive")
    config = ProxyConfig.model_validate_json(config_path.read_bytes())
    run_id = f"mcp-{uuid.uuid4().hex[:12]}"
    control_path: Path | None = (
        None
        if control_arg == "none"
        else Path(control_arg)
        if control_arg is not None
        else default_path(run_id)
    )
    desk = None if control_path is None else ApprovalDesk(timeout_seconds=timeout)
    hint = (
        ""
        if control_path is None
        else (
            "approve with: notary-mcp-proxy approve {id} --control "
            f"{control_path}   (or reject {{id}})"
        )
    )
    control: ControlServer | None = None
    control_file: Path | None = None
    clients: dict[str, McpClient] = {}
    log: RunLog | None = None
    try:
        try:
            clients = _start_clients(config, config_path)
            if audit_dir is not None:
                log = RunLog(audit_dir, run_id)
            server = build_servers(
                config,
                clients,
                run_id=run_id,
                audit_append=append if log is None else durable_append(log),
                desk=desk,
                control_hint=hint,
                reject_unanswered=control_path is None,
                compile_client=compile_client,
            )
            if desk is not None and control_path is not None:
                control = ControlServer(desk, control_path, server.submit_user_prompt)
                control.start()
                if audit_dir is not None:
                    control_file = write_control_file(audit_dir, run_id, control.path)
        except (ServerError, OSError, ValueError, AuditWriteError, ControlError) as failure:
            # Every server must start and match the config, or the contract would not cover it.
            detail = failure.detail if isinstance(failure, ServerError) else str(failure)
            _log(f"startup failed: {type(failure).__name__}: {detail}")
            return 2
        if server.gateway.halted is not None:
            _log(f"startup failed: NOTARY halted: {server.gateway.halted}")
            return 2
        fronted = [
            _describe(spec) if not config.multi else f"{name}: {_describe(spec)}"
            for name, spec in config.servers.items()
        ]
        _log(f"run {run_id}: fronting {'; '.join(fronted)}")
        if compile_client is not None:
            _log(
                f"run {run_id}: the contract is compiled from the first prompt when it narrows the "
                "config's; run_started is written at the first event"
            )
        if log is not None:
            _log(f"run {run_id}: audit chain {log.chain_path}")
        if control is not None:
            _log(f"run {run_id}: approvals on {control.path} (timeout {timeout:g} s)")
        else:
            _log(f"run {run_id}: approvals disabled; every escalation is rejected at once")
        if endpoint is None:
            serve(server, sys.stdin.buffer, sys.stdout.buffer)
        else:
            _log(f"run {run_id}: listening on {endpoint.url} (a bearer token is required)")
            _serve_http(endpoint, server)
        server.finish_run()  # serve() joined the worker: nothing else touches the Gateway
        if log is not None:
            _report_head(run_id, log, halted=server.gateway.halted)
    finally:
        if control_file is not None:
            control_file.unlink(missing_ok=True)
        if control is not None:
            control.close()
        _close_all(clients)
        if endpoint is not None:
            endpoint.close()
        if log is not None:
            log.close()
    return 0


def _serve_http(endpoint: AgentEndpoint, server: ProxyServer) -> None:
    """Serve until the client deletes its session or the process gets SIGINT / SIGTERM."""

    def stop(_signal: int, _frame: FrameType | None) -> None:
        endpoint.stop()

    if threading.current_thread() is not threading.main_thread():
        endpoint.serve(server)  # signals can only be handled by the main thread
        return
    interrupt = signal.signal(signal.SIGINT, stop)
    terminate = signal.signal(signal.SIGTERM, stop)
    try:
        endpoint.serve(server)
    finally:
        signal.signal(signal.SIGINT, interrupt)
        signal.signal(signal.SIGTERM, terminate)


def control_main(op: str, argv: Sequence[str]) -> int:
    """`pending|approve|reject [ID] [--control PATH]`: the user's side of an escalation.

    Exit 0 done, 1 refused (unknown or already decided id), 2 the proxy could not be reached.
    """
    parser = argparse.ArgumentParser(prog=f"notary-mcp-proxy {op}")
    if op != "pending":
        parser.add_argument("endorsement_id", help="the id on the card, e.g. e1")
    parser.add_argument(
        "--control", type=Path, help="the proxy's control socket (default: the only one found)"
    )
    args = parser.parse_args(argv)
    path: Path | None = args.control
    try:
        target = find_socket() if path is None else path
        if op == "pending":
            print(render_pending(send(target, {"op": "pending"})))
            return 0
        endorsement_id: str = args.endorsement_id
        answer = send(target, {"op": op, "endorsement_id": endorsement_id})
    except ControlError as failure:
        _log(printable(str(failure)))
        return 2
    if answer.get("ok") is True:
        verb = "approved" if op == "approve" else "rejected"
        print(f"{verb} {printable(endorsement_id)}")
        return 0
    reason = answer.get("error")
    _log(f"refused: {printable(str(reason))}")
    return 1


def _report_head(run_id: str, log: RunLog, *, halted: str | None) -> None:
    """The head on stderr is a second copy of the anchor that an attacker on disk cannot edit."""
    anchor = log.anchor
    state = "closed" if halted is None else f"halted ({halted})"
    _log(f"run {run_id} {state}: length {anchor.length} head {anchor.head}")


def main(argv: Sequence[str] | None = None) -> int:
    """Subcommands `serve` (the default), `check`, `hook pre-tool-use`, `hook user-prompt-submit`,
    `pending|approve|reject`."""
    args_list = list(sys.argv[1:] if argv is None else argv)
    if args_list[:2] == ["hook", "pre-tool-use"]:
        return hook_main(args_list[2:])
    if args_list[:2] == ["hook", "user-prompt-submit"]:
        return prompt_hook_main(args_list[2:])
    if args_list[:1] in (["pending"], ["approve"], ["reject"]):
        return control_main(args_list[0], args_list[1:])
    if args_list[:1] == ["check"]:
        return check_main(args_list[1:])
    if args_list[:1] == ["serve"]:
        return serve_main(args_list[1:])
    return serve_main(args_list)


if __name__ == "__main__":
    raise SystemExit(main())

"""`notary-mcp-proxy --config notary.json`: a stdio MCP server in front of another one.

stdout carries only MCP messages; diagnostics go to stderr.
"""

import argparse
import json
import os
import sys
import uuid
from collections.abc import Mapping, Sequence
from functools import partial
from pathlib import Path

from notary_core.audit import append
from notary_core.gateway import make_labeler
from notary_core.models import RunStarted
from notary_core.monitor import decide
from notary_core.resolver import ArgumentResolver
from notary_mcp_proxy.approvals import ApprovalDesk, printable
from notary_mcp_proxy.audit_log import AuditWriteError, RunLog, durable_append
from notary_mcp_proxy.check import check_config, render_report
from notary_mcp_proxy.client import ServerError, StdioClient
from notary_mcp_proxy.config import (
    ProxyConfig,
    build_contract,
    build_labeling,
    build_ledger,
    build_policy,
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
from notary_mcp_proxy.gateway import AuditAppend, Gateway
from notary_mcp_proxy.guard import hook_reason, run_hook
from notary_mcp_proxy.routing import RoutingError, build_routing
from notary_mcp_proxy.server import ProxyServer, serve

DEFAULT_APPROVAL_TIMEOUT = 120.0
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
    except BaseException:
        staging.unlink(missing_ok=True)
        raise
    os.chmod(staging, 0o600)
    os.replace(staging, target)
    return target


def build_server(
    config: ProxyConfig,
    client: StdioClient,
    *,
    run_id: str,
    audit_append: AuditAppend = append,
    desk: ApprovalDesk | None = None,
    control_hint: str = "",
    reject_unanswered: bool = False,
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
    )


def build_servers(
    config: ProxyConfig,
    clients: Mapping[str, StdioClient],
    *,
    run_id: str,
    audit_append: AuditAppend = append,
    desk: ApprovalDesk | None = None,
    control_hint: str = "",
    reject_unanswered: bool = False,
) -> ProxyServer:
    """Pin every server's tools, freeze one contract and wrap one Gateway around all of them.

    `audit_append` stores every audit entry; `durable_append(log)` makes each one durable before
    the Gateway goes on. `run_started` is appended here, so it is the first entry on disk.
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
    gateway.emit(
        lambda run, lane, seq: RunStarted(
            type="run_started",
            run_id=run,
            lane=lane,
            seq=seq,
            scenario="mcp-proxy",
            contract=contract,
            classifier=None,
        )
    )
    server = ProxyServer(
        gateway,
        backend.pinned_definitions(),
        desk,
        control_hint=control_hint,
        reject_unanswered=reject_unanswered,
        elicitation=config.approvals.elicitation,
        content=content if content.resources or content.prompts else None,
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
    except Exception as error:
        return _hook_deny(f"NOTARY guard: internal error ({type(error).__name__}); denied")


def _load_config(path: Path) -> ProxyConfig | None:
    try:
        return ProxyConfig.model_validate_json(path.read_bytes())
    except (OSError, ValueError) as failure:
        _log(f"cannot load config {path.name}: {type(failure).__name__}: {failure}")
        return None


def check_main(argv: Sequence[str]) -> int:
    """`check --config CONFIG [--json]`: exit 0 clean, 1 an error finding, 2 could not check."""
    parser = argparse.ArgumentParser(prog="notary-mcp-proxy check")
    parser.add_argument("--config", type=Path, required=True, help="proxy config (JSON)")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)
    config_path: Path = args.config
    config = _load_config(config_path)
    if config is None:
        return 2
    clients: dict[str, StdioClient] = {}
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
    return 0 if report.ok else 1


def _start_clients(config: ProxyConfig, config_path: Path) -> dict[str, StdioClient]:
    """Start every server (in the config file's directory); on a failure stop the ones started."""
    started: dict[str, StdioClient] = {}
    try:
        for name, spec in config.servers.items():
            started[name] = StdioClient(
                spec.command,
                cwd=config_path.resolve().parent,
                timeout_seconds=spec.timeout_seconds,
            )
    except BaseException:
        _close_all(started)
        raise
    return started


def _close_all(clients: Mapping[str, StdioClient]) -> None:
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
    args = parser.parse_args(argv)
    config_path: Path = args.config
    audit_dir: Path | None = args.audit_dir
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
    clients: dict[str, StdioClient] = {}
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
            )
            if desk is not None and control_path is not None:
                control = ControlServer(desk, control_path)
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
            " ".join(spec.command) if not config.multi else f"{name}: {' '.join(spec.command)}"
            for name, spec in config.servers.items()
        ]
        _log(f"run {run_id}: fronting {'; '.join(fronted)}")
        if log is not None:
            _log(f"run {run_id}: audit chain {log.chain_path}")
        if control is not None:
            _log(f"run {run_id}: approvals on {control.path} (timeout {timeout:g} s)")
        else:
            _log(f"run {run_id}: approvals disabled; every escalation is rejected at once")
        serve(server, sys.stdin.buffer, sys.stdout.buffer)
        server.finish_run()  # serve() joined the worker: nothing else touches the Gateway
        if log is not None:
            _report_head(run_id, log, halted=server.gateway.halted)
    finally:
        if control_file is not None:
            control_file.unlink(missing_ok=True)
        if control is not None:
            control.close()
        _close_all(clients)
        if log is not None:
            log.close()
    return 0


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
    """Subcommands `serve` (the default), `check`, `hook pre-tool-use`, `pending|approve|reject`."""
    args_list = list(sys.argv[1:] if argv is None else argv)
    if args_list[:2] == ["hook", "pre-tool-use"]:
        return hook_main(args_list[2:])
    if args_list[:1] in (["pending"], ["approve"], ["reject"]):
        return control_main(args_list[0], args_list[1:])
    if args_list[:1] == ["check"]:
        return check_main(args_list[1:])
    if args_list[:1] == ["serve"]:
        return serve_main(args_list[1:])
    return serve_main(args_list)


if __name__ == "__main__":
    raise SystemExit(main())

"""`notary-mcp-proxy --config notary.json`: a stdio MCP server in front of another one.

stdout carries only MCP messages; diagnostics go to stderr.
"""

import argparse
import json
import sys
import uuid
from collections.abc import Mapping, Sequence
from functools import partial
from pathlib import Path

from notary_core.gateway import make_labeler
from notary_core.models import AuditEntry, RunStarted
from notary_core.monitor import decide
from notary_core.resolver import ArgumentResolver
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
from notary_mcp_proxy.gateway import Gateway
from notary_mcp_proxy.guard import hook_reason, run_hook
from notary_mcp_proxy.routing import RoutingError, build_routing
from notary_mcp_proxy.server import AuditSink, ProxyServer, serve


def _log(text: str) -> None:
    print(f"notary-mcp-proxy: {text}", file=sys.stderr, flush=True)


def _audit_file(path: Path) -> AuditSink:
    """Appends each new event as one JSON line (readable by `notary replay`)."""
    path.parent.mkdir(parents=True, exist_ok=True)

    def sink(entries: Sequence[AuditEntry]) -> None:
        with path.open("a", encoding="utf-8") as out:
            for entry in entries:
                out.write(entry.event.model_dump_json() + "\n")

    return sink


def build_server(
    config: ProxyConfig, client: StdioClient, *, run_id: str, audit: AuditSink | None
) -> ProxyServer:
    """`build_servers` for a config with one server."""
    (name,) = config.servers
    return build_servers(config, {name: client}, run_id=run_id, audit=audit)


def build_servers(
    config: ProxyConfig,
    clients: Mapping[str, StdioClient],
    *,
    run_id: str,
    audit: AuditSink | None,
) -> ProxyServer:
    """Pin every server's tools, freeze one contract and wrap one Gateway around all of them.

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
    )
    gateway.pin_session()
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
    server = ProxyServer(gateway, backend.pinned_definitions(), audit=audit)
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
    except (ServerError, OSError) as failure:
        detail = failure.detail if isinstance(failure, ServerError) else str(failure)
        _log(f"a server failed to start or list its tools: {type(failure).__name__}: {detail}")
        return 2
    finally:
        _close_all(clients)
    report = check_config(config, manifests, schemas, collisions)
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
    parser.add_argument("--audit-log", type=Path, help="append the event log here (JSON lines)")
    args = parser.parse_args(argv)
    config_path: Path = args.config
    audit_path: Path | None = args.audit_log
    config = ProxyConfig.model_validate_json(config_path.read_bytes())
    run_id = f"mcp-{uuid.uuid4().hex[:12]}"
    clients: dict[str, StdioClient] = {}
    try:
        try:
            clients = _start_clients(config, config_path)
            server = build_servers(
                config,
                clients,
                run_id=run_id,
                audit=None if audit_path is None else _audit_file(audit_path),
            )
        except (ServerError, OSError, ValueError) as failure:
            # Every server must start and match the config, or the contract would not cover it.
            detail = failure.detail if isinstance(failure, ServerError) else str(failure)
            _log(f"startup failed: {type(failure).__name__}: {detail}")
            return 2
        fronted = [
            " ".join(spec.command) if not config.multi else f"{name}: {' '.join(spec.command)}"
            for name, spec in config.servers.items()
        ]
        _log(f"run {run_id}: fronting {'; '.join(fronted)}")
        serve(server, sys.stdin.buffer, sys.stdout.buffer)
    finally:
        _close_all(clients)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    """Subcommands `serve` (the default when none is given), `check` and `hook pre-tool-use`."""
    args_list = list(sys.argv[1:] if argv is None else argv)
    if args_list[:2] == ["hook", "pre-tool-use"]:
        return hook_main(args_list[2:])
    if args_list[:1] == ["check"]:
        return check_main(args_list[1:])
    if args_list[:1] == ["serve"]:
        return serve_main(args_list[1:])
    return serve_main(args_list)


if __name__ == "__main__":
    raise SystemExit(main())

"""`notary-mcp-proxy --config notary.json`: a stdio MCP server in front of another one.

stdout carries only MCP messages; diagnostics go to stderr.
"""

import argparse
import json
import sys
import uuid
from collections.abc import Sequence
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
    tool_readers,
)
from notary_mcp_proxy.gateway import Gateway
from notary_mcp_proxy.guard import hook_reason, run_hook
from notary_mcp_proxy.mcp_backend import McpBackend
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
    """Pin the server's tools, freeze the contract and wrap a Gateway around the backend."""
    client.initialize()
    policy = build_policy(config)
    backend = McpBackend(
        client,
        policy=policy,
        effects={tool: spec.effect for tool, spec in config.tools.items()},
        readers=tool_readers(config),
    )
    pinned = backend.list_tools()
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
    exposed = [tool for tool in backend.pinned_definitions() if tool.name in config.tools]
    server = ProxyServer(gateway, exposed, audit=audit)
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
    client: StdioClient | None = None
    try:
        client = StdioClient(
            config.server.command,
            cwd=config_path.resolve().parent,
            timeout_seconds=config.server.timeout_seconds,
        )
        client.initialize()
        backend = McpBackend(client, policy=build_policy(config), effects={}, readers={})
        manifests = backend.list_tools()
        schemas = {tool.name: tool.input_schema for tool in backend.pinned_definitions()}
    except (ServerError, OSError) as failure:
        detail = failure.detail if isinstance(failure, ServerError) else str(failure)
        _log(f"the server failed to start or list its tools: {type(failure).__name__}: {detail}")
        return 2
    finally:
        if client is not None:
            client.close()
    report = check_config(config, manifests, schemas)
    print(report.model_dump_json(indent=2) if args.json else render_report(report), end="")
    if args.json:
        print()
    return 0 if report.ok else 1


def serve_main(argv: Sequence[str]) -> int:
    parser = argparse.ArgumentParser(prog="notary-mcp-proxy [serve]", description=__doc__)
    parser.add_argument("--config", type=Path, required=True, help="proxy config (JSON)")
    parser.add_argument("--audit-log", type=Path, help="append the event log here (JSON lines)")
    args = parser.parse_args(argv)
    config_path: Path = args.config
    audit_path: Path | None = args.audit_log
    config = ProxyConfig.model_validate_json(config_path.read_bytes())
    client = StdioClient(
        config.server.command,
        cwd=config_path.resolve().parent,
        timeout_seconds=config.server.timeout_seconds,
    )
    run_id = f"mcp-{uuid.uuid4().hex[:12]}"
    try:
        server = build_server(
            config,
            client,
            run_id=run_id,
            audit=None if audit_path is None else _audit_file(audit_path),
        )
        _log(f"run {run_id}: fronting {' '.join(config.server.command)}")
        serve(server, sys.stdin.buffer, sys.stdout.buffer)
    finally:
        client.close()
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

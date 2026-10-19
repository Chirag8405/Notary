"""`notary-mcp-proxy check`: a config against what the server reports and the policy table.

`check_config` is pure over its inputs; the subprocess lives in `main.py`.
"""

from collections.abc import Mapping, Sequence
from typing import Literal

from notary_core.models import NotaryModel, Sha256Hex, ToolEffect
from notary_core.pinning import ToolManifest, manifest_hash
from notary_core.policy.sensitive_params import (
    DEFAULT_POLICY,
    ManifestInfo,
    effective_effect,
    effective_marker,
    param_policy,
    stricter_effect,
    unclassified_params,
)
from notary_core.units import canonicalize
from notary_mcp_proxy.config import ProxyConfig, build_policy, routes
from notary_mcp_proxy.jsonrpc import JsonObject, as_list, as_object, as_str

Severity = Literal["error", "warning", "info"]
FindingCode = Literal[
    "TOOL_MISSING",
    "PARAM_NOT_IN_CONFIG",
    "PARAM_NOT_ON_SERVER",
    "PARAM_UNCLASSIFIED",
    "EFFECT_STRICTER_THAN_CONFIG",
    "LEDGER_VALUE_INVALID",
    "LEDGER_VALUE_PLACEHOLDER",
    "IRREVERSIBLE_NOT_AUTHORIZED",
    "SERVER_TOOL_NOT_EXPOSED",
    "TOOL_NAME_COLLISION",
    "RENAMED_TOOL_UNREVIEWED",
    "PROMPT_MISSING",
    "RESOURCES_EXPOSED",
    "PROMPTS_EXPOSED",
]
SEVERITY_ORDER: tuple[Severity, ...] = ("error", "warning", "info")


class Finding(NotaryModel):
    severity: Severity
    code: FindingCode
    tool: str | None
    param: str | None
    detail: str


class ToolRow(NotaryModel):
    tool: str
    server: str | None = None
    """The server that runs the tool; set only when the config has several servers."""
    effect: ToolEffect
    manifest_hash: Sha256Hex
    params: tuple[tuple[str, str, str, str], ...]
    """`(param, marker kind, unit or "-", kind)`, sorted by param."""


class CheckReport(NotaryModel):
    tools: tuple[ToolRow, ...]
    findings: tuple[Finding, ...]
    ok: bool
    """No error finding."""


def _schema_params(schema: JsonObject | None) -> tuple[frozenset[str], frozenset[str]]:
    """(property names, required names) of a tool's input schema."""
    properties = as_object((schema or {}).get("properties")) or {}
    names = [as_str(name) for name in as_list((schema or {}).get("required")) or []]
    required = frozenset(name for name in names if name is not None)
    return frozenset(properties), required


def _tool_findings(
    config: ProxyConfig, tool: str, schema: JsonObject | None, policy_effect: ToolEffect
) -> list[Finding]:
    spec = config.tools[tool]
    found: list[Finding] = []
    on_server, required = _schema_params(schema)
    for name in sorted(on_server - set(spec.params)):
        needed = name in required
        found.append(
            Finding(
                severity="error" if needed else "warning",
                code="PARAM_NOT_IN_CONFIG",
                tool=tool,
                param=name,
                detail=(
                    f"the server's schema has `{name}`"
                    f"{' (required)' if needed else ''} but the config does not list it; "
                    "a call using it is blocked (SCOPE_PARAM_NOT_IN_CONTRACT)"
                ),
            )
        )
    found.extend(
        Finding(
            severity="warning",
            code="PARAM_NOT_ON_SERVER",
            tool=tool,
            param=name,
            detail=f"the config lists `{name}` but the server's schema does not have it",
        )
        for name in sorted(set(spec.params) - on_server)
    )
    if (
        policy_effect != spec.effect
        and stricter_effect(policy_effect, spec.effect) == policy_effect
    ):
        found.append(
            Finding(
                severity="info",
                code="EFFECT_STRICTER_THAN_CONFIG",
                tool=tool,
                param=None,
                detail=f"the table makes it {policy_effect}; the config says {spec.effect}",
            )
        )
    if policy_effect == "irreversible" and tool not in config.authorized_irreversible:
        found.append(
            Finding(
                severity="warning",
                code="IRREVERSIBLE_NOT_AUTHORIZED",
                tool=tool,
                param=None,
                detail="irreversible and not in authorized_irreversible; every call is blocked",
            )
        )
    return found


def _is_placeholder_iban(value: str) -> bool:
    """Check digits 00 never occur in a real IBAN; a placeholder if that is its only defect."""
    if len(value) < 5 or value[2:4] != "00" or not value.isascii() or not value.isalnum():
        return False
    digits = "".join(str(int(ch, 36)) for ch in value[4:] + value[:2] + "00")
    fixed = value[:2] + f"{98 - int(digits) % 97:02d}" + value[4:]
    return canonicalize("iban", fixed).valid


def _ledger_findings(config: ProxyConfig) -> list[Finding]:
    """An invalid ledger value is an error; an IBAN with check digits 00 is a placeholder."""
    found: list[Finding] = []
    for entry in config.ledger:
        canonical = canonicalize(entry.unit, entry.value)
        if canonical.valid:
            continue
        where = f"ledger {entry.ledger}/{entry.key}"
        if entry.unit == "iban" and _is_placeholder_iban(canonical.value):
            found.append(
                Finding(
                    severity="warning",
                    code="LEDGER_VALUE_PLACEHOLDER",
                    tool=None,
                    param=None,
                    detail=(
                        f"{where}: check digits 00 never occur in a real IBAN; "
                        "a placeholder or test IBAN"
                    ),
                )
            )
            continue
        found.append(
            Finding(
                severity="error",
                code="LEDGER_VALUE_INVALID",
                tool=None,
                param=None,
                detail=f"{where}: not a valid {entry.unit}",
            )
        )
    return found


def _routing_findings(config: ProxyConfig, collisions: Sequence[str]) -> list[Finding]:
    """A contract name another server tool also answers to; a renamed tool's reviewed row."""
    found = [
        Finding(severity="error", code="TOOL_NAME_COLLISION", tool=None, param=None, detail=text)
        for text in collisions
    ]
    for tool, spec in sorted(config.tools.items()):
        if spec.remote_name in DEFAULT_POLICY and tool not in DEFAULT_POLICY:
            found.append(
                Finding(
                    severity="warning",
                    code="RENAMED_TOOL_UNREVIEWED",
                    tool=tool,
                    param=None,
                    detail=(
                        f"the reviewed row of `{spec.remote_name}` does not apply to the "
                        f"contract name `{tool}`; its parameters are classified by the config"
                    ),
                )
            )
    return found


def _content_findings(config: ProxyConfig, prompts: Mapping[str, Sequence[str]]) -> list[Finding]:
    """The resources and prompts the config switches on; an allowed prompt must exist."""
    found: list[Finding] = []
    for server, spec in sorted(config.servers.items()):
        where = f"server {server}: " if config.multi else ""
        if spec.resources is not None:
            found.append(
                Finding(
                    severity="info",
                    code="RESOURCES_EXPOSED",
                    tool=None,
                    param=None,
                    detail=(
                        f"{where}resources under {', '.join(spec.resources.allow)} are listed and "
                        "readable; their content is labeled and logged, always untrusted, "
                        f"readers {', '.join(spec.resources.readers)}"
                    ),
                )
            )
        if spec.prompts is None:
            continue
        found.append(
            Finding(
                severity="info",
                code="PROMPTS_EXPOSED",
                tool=None,
                param=None,
                detail=(
                    f"{where}prompts {', '.join(spec.prompts.allow)} are listed and gettable; "
                    "their definitions are pinned at startup and their messages are labeled"
                ),
            )
        )
        reported = set(prompts.get(server, ()))
        found.extend(
            Finding(
                severity="error",
                code="PROMPT_MISSING",
                tool=None,
                param=None,
                detail=f"{where}the config allows prompt `{name}`; the server does not report it",
            )
            for name in spec.prompts.allow
            if name not in reported
        )
    return found


def check_config(
    config: ProxyConfig,
    manifests: Sequence[ToolManifest],
    schemas: Mapping[str, JsonObject],
    collisions: Sequence[str] = (),
    prompts: Mapping[str, Sequence[str]] | None = None,
) -> CheckReport:
    """What the config exposes and every problem with it.

    `manifests` and `schemas` (tool -> `inputSchema`) are keyed by CONTRACT name; `collisions`
    are the texts from `RoutingBackend.collisions`; `prompts` is server name -> the prompt names
    it reports (only servers with a `prompts` section are looked at).
    """
    policy = build_policy(config)
    servers = {tool: name for tool, (name, _) in routes(config).items()} if config.multi else {}
    by_name = {manifest.name: manifest for manifest in manifests}
    findings: list[Finding] = _routing_findings(config, collisions)
    findings.extend(_content_findings(config, prompts or {}))
    rows: list[ToolRow] = []
    present: list[str] = []
    for tool, spec in sorted(config.tools.items()):
        manifest = by_name.get(tool)
        if manifest is None:
            findings.append(
                Finding(
                    severity="error",
                    code="TOOL_MISSING",
                    tool=tool,
                    param=None,
                    detail=(
                        "the config names a tool the server does not report"
                        if not config.multi
                        else f"the config names a tool server `{servers[tool]}` does not report"
                    ),
                )
            )
            continue
        present.append(tool)
        effect = effective_effect(policy, tool, spec.effect)
        findings.extend(_tool_findings(config, tool, schemas.get(tool), effect))
        params = tuple(
            (
                name,
                effective_marker(policy, tool, name, param.marker).kind,
                param_policy(policy, tool, name).unit or "-",
                param_policy(policy, tool, name).kind,
            )
            for name, param in sorted(spec.params.items())
        )
        rows.append(
            ToolRow(
                tool=tool,
                server=servers.get(tool),
                effect=effect,
                manifest_hash=manifest_hash(manifest),
                params=params,
            )
        )
    findings.extend(
        Finding(
            severity="error",
            code="PARAM_UNCLASSIFIED",
            tool=tool,
            param=param,
            detail="the policy table does not classify it; it falls back to UNKNOWN_PARAM",
        )
        for tool, param in unclassified_params(
            policy,
            [
                ManifestInfo(t, config.tools[t].effect, tuple(config.tools[t].params))
                for t in present
            ],
        )
    )
    findings.extend(_ledger_findings(config))
    findings.extend(
        Finding(
            severity="info",
            code="SERVER_TOOL_NOT_EXPOSED",
            tool=name,
            param=None,
            detail="the server has it; the config does not list it, so the agent cannot see it",
        )
        for name in sorted(set(by_name) - set(config.tools))
    )
    ordered = tuple(
        sorted(
            findings,
            key=lambda f: (
                SEVERITY_ORDER.index(f.severity),
                f.code,
                f.tool or "",
                f.param or "",
                f.detail,
            ),
        )
    )
    return CheckReport(
        tools=tuple(rows), findings=ordered, ok=all(f.severity != "error" for f in ordered)
    )


def render_report(report: CheckReport) -> str:
    """Deterministic text: tools sorted, then findings by severity; no times or paths."""
    lines: list[str] = []
    section: str | None = None
    for row in sorted(report.tools, key=lambda r: (r.server or "", r.tool)):
        if row.server is not None and row.server != section:
            if section is not None:
                lines.append("")
            section = row.server
            lines.append(f"server {section}")
        lines.append(f"tool {row.tool}  effect={row.effect}  hash={row.manifest_hash}")
        for name, marker, unit, kind in row.params:
            lines.append(f"  param {name}  marker={marker}  unit={unit}  kind={kind}")
    if report.tools:
        lines.append("")
    for finding in report.findings:
        where = ".".join(part for part in (finding.tool, finding.param) if part)
        lines.append(
            f"{finding.severity} {finding.code}{f' {where}' if where else ''}: {finding.detail}"
        )
    errors = sum(f.severity == "error" for f in report.findings)
    lines.append(
        f"{'ok' if report.ok else 'FAILED'}: {errors} error(s), "
        f"{len(report.findings) - errors} other finding(s)"
    )
    return "\n".join(lines) + "\n"

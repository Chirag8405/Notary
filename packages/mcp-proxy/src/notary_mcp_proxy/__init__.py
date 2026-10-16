"""MCP gateway wrapping notary_core: tool pinning, argument and result labeling, mediation."""

from notary_mcp_proxy.backend import (
    BackendEffect,
    BackendRecord,
    BackendResult,
    ToolBackend,
    schema_text,
)
from notary_mcp_proxy.gateway import Gateway, MediationOutcome, RawCall, ToolPin

__all__ = [
    "BackendEffect",
    "BackendRecord",
    "BackendResult",
    "Gateway",
    "MediationOutcome",
    "RawCall",
    "ToolBackend",
    "ToolPin",
    "schema_text",
]

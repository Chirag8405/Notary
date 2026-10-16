"""Tool pinning, the pure half: hash a tool manifest, pin a session's tools, detect drift (A10).

A rug pull changes a tool's description or schema after the user approved it. The contract
pins `ToolScope.manifest_hash` when it is compiled; the Gateway stamps `ToolCallProposal`
with the hash of the manifest it observes now; step 1 (scope) BLOCKs when they differ.

The manifest is hashed as text it is given: the schema arrives as a string produced by the I/O
adapter (MCP schemas may contain floats, which `canonical_json` rejects), so core never parses
JSON or touches a network.
"""

from notary_core.canon import canonical_hash
from notary_core.models import NotaryModel, Sha256Hex

UNKNOWN_TOOL_PREFIX: str = "unknown-tool:"
"""Hashed with the tool name when no observed manifest has that name."""


class ToolManifest(NotaryModel):
    """What an MCP server reports for one tool. The effect class is not part of it: a server
    does not report one, and the monitor takes it from the contract and the policy table."""

    name: str
    description: str
    input_schema: str
    """The schema as canonical text, serialized by the adapter."""


class PinReport(NotaryModel):
    """Pins compared with what a server reports now; each name is in at most one tuple."""

    drifted: tuple[str, ...]
    """Pinned and observed, with different hashes (a rug pull)."""
    unpinned: tuple[str, ...]
    """Observed but never pinned."""
    missing: tuple[str, ...]
    """Pinned but no longer observed. Only reported: whether it blocks is the adapter's call."""
    ok: bool
    """True iff all three tuples are empty."""


def manifest_hash(manifest: ToolManifest) -> Sha256Hex:
    """Hash of the whole manifest (name, description and schema), so any change shows up.

    Names and text are used byte-for-byte: whitespace and zero-width characters change the hash.
    """
    return canonical_hash(manifest)

"""Tool pinning, the pure half: hash a tool manifest, pin a session's tools, detect drift (A10).

A rug pull changes a tool's description or schema after the user approved it. The contract
pins `ToolScope.manifest_hash` when it is compiled; the Gateway stamps `ToolCallProposal`
with the hash of the manifest it observes now; step 1 (scope) BLOCKs when they differ.

The manifest is hashed as text it is given: the schema arrives as a string produced by the I/O
adapter (MCP schemas may contain floats, which `canonical_json` rejects), so core never parses
JSON or touches a network.
"""

from collections.abc import Mapping, Sequence

from notary_core.canon import canonical_hash, sha256_hex
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


def _hashes(manifests: Sequence[ToolManifest]) -> dict[str, str]:
    """Hash per tool name; names are compared exactly (case-sensitive), a repeat is an error."""
    hashes: dict[str, str] = {}
    for manifest in manifests:
        if manifest.name in hashes:
            raise ValueError(f"duplicate tool name: {manifest.name}")
        hashes[manifest.name] = manifest_hash(manifest)
    return hashes


def pin_manifests(manifests: Sequence[ToolManifest]) -> dict[str, str]:
    """Tool name -> manifest hash, with keys in sorted order; a repeated name raises."""
    hashes = _hashes(manifests)
    return {name: hashes[name] for name in sorted(hashes)}


def compare_pins(pins: Mapping[str, str], observed: Sequence[ToolManifest]) -> PinReport:
    """Compare pinned hashes with the manifests a server reports now.

    Total except for a repeated name in `observed`: a pin that is not the observed hash, however
    malformed, is drift (the pin format is not validated).
    """
    seen = _hashes(observed)
    drifted = tuple(
        sorted(name for name, digest in seen.items() if name in pins and pins[name] != digest)
    )
    unpinned = tuple(sorted(name for name in seen if name not in pins))
    missing = tuple(sorted(name for name in pins if name not in seen))
    return PinReport(
        drifted=drifted,
        unpinned=unpinned,
        missing=missing,
        ok=not (drifted or unpinned or missing),
    )


def observed_hash(observed: Sequence[ToolManifest], tool: str) -> str:
    """The hash to stamp on a proposal for `tool`: that of its observed manifest.

    A tool nobody reported gets a hash of its name alone, so an unknown tool never matches a
    pinned hash. Never raises for an unknown tool.
    """
    hashes = _hashes(observed)
    if tool in hashes:
        return hashes[tool]
    return sha256_hex(UNKNOWN_TOOL_PREFIX + tool)

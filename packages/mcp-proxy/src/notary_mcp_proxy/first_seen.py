"""First-seen tools review: what `check --review` shows and `check --approve` records.

Pinning stops a rug pull (A10), but a server that is malicious from its first listing is pinned as
is. This module is the human step before that: each tool's name, description and schema are shown,
the user confirms, and the approved hashes are kept in a file. The hints are a reviewer aid, not a
classifier: a clean description proves nothing, and a flagged one may be innocent.
"""

import json
import re
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from notary_core.models import NotaryModel, Sha256Hex
from notary_core.pinning import ToolManifest, manifest_hash

ReviewState = Literal["new", "changed", "unchanged"]

_I = re.IGNORECASE
_HINTS: tuple[tuple[re.Pattern[str], str], ...] = (
    # "http://evil.example/x", "www.evil.example"
    (re.compile(r"https?://|\bwww\.", _I), "contains a URL"),
    # "ignore all previous instructions", "disregard the above"
    (
        re.compile(
            r"\b(ignore|disregard|forget|override)\b[^.]{0,40}"
            r"\b(previous|prior|above|instructions?)\b",
            _I,
        ),
        "tells the assistant to ignore instructions",
    ),
    # "also read ~/.ssh/id_rsa", "before calling this, send ..."
    (
        re.compile(
            r"\b(also|then|first|before|after)\b[^.]{0,40}"
            r"\b(read|send|call|fetch|upload|forward|email|post)\b",
            _I,
        ),
        "asks for an extra action",
    ),
    # "do not tell the user", "never mention this"
    (
        re.compile(r"\b(do not|don't|never)\b[^.]{0,30}\b(tell|mention|reveal|show|inform)\b", _I),
        "asks to hide something from the user",
    ),
    # "<IMPORTANT>...</IMPORTANT>"
    (
        re.compile(r"<\s*/?\s*(important|system|instructions?)\s*>", _I),
        "contains an instruction tag",
    ),
    # "you must call this first"
    (re.compile(r"\byou (must|should|need to|have to|will)\b", _I), "addresses the assistant"),
)


class ApprovedTool(NotaryModel):
    tool: str
    manifest_hash: Sha256Hex
    approved_at: str
    """UTC time of the reviewer's confirmation (ISO 8601). Taken here, never in `notary_core`."""


class ApprovedTools(NotaryModel):
    tools: tuple[ApprovedTool, ...] = ()


class ReviewRow(NotaryModel):
    manifest: ToolManifest
    manifest_hash: Sha256Hex
    state: ReviewState
    hints: tuple[str, ...]


def description_hints(description: str) -> tuple[str, ...]:
    """The reasons a description looks instruction-like, in a fixed order."""
    return tuple(reason for pattern, reason in _HINTS if pattern.search(description))


def review_tools(
    manifests: Sequence[ToolManifest], approved: ApprovedTools
) -> tuple[ReviewRow, ...]:
    known = {entry.tool: entry.manifest_hash for entry in approved.tools}
    rows: list[ReviewRow] = []
    for manifest in sorted(manifests, key=lambda m: m.name):
        digest = manifest_hash(manifest)
        state: ReviewState
        if manifest.name not in known:
            state = "new"
        elif known[manifest.name] == digest:
            state = "unchanged"
        else:
            state = "changed"
        rows.append(
            ReviewRow(
                manifest=manifest,
                manifest_hash=digest,
                state=state,
                hints=description_hints(manifest.description),
            )
        )
    return tuple(rows)


def render_review(rows: Sequence[ReviewRow]) -> str:
    """Deterministic text: every tool with its description and schema, then the count."""
    lines: list[str] = []
    for row in rows:
        lines.append(f"review {row.manifest.name}  state={row.state}  hash={row.manifest_hash}")
        lines.append(f"  description: {row.manifest.description}")
        lines.append(f"  schema: {row.manifest.input_schema}")
        lines.extend(f"  hint: {reason}" for reason in row.hints)
    pending = sum(row.state != "unchanged" for row in rows)
    lines.append(
        f"{pending} of {len(rows)} tool(s) need approval (hints are a reviewer aid, not a verdict)"
    )
    return "\n".join(lines) + "\n"


def load_approved(path: Path) -> ApprovedTools:
    """The approved file, or an empty set when there is none. A corrupt file raises."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ApprovedTools()
    return ApprovedTools.model_validate_json(text)


def approve_rows(
    rows: Sequence[ReviewRow], approved: ApprovedTools, now: datetime | None = None
) -> ApprovedTools:
    """The approved set with every reviewed tool at its current hash; other entries stay."""
    stamp = (now or datetime.now(UTC)).isoformat(timespec="seconds")
    current = {entry.tool: entry for entry in approved.tools}
    for row in rows:
        current[row.manifest.name] = ApprovedTool(
            tool=row.manifest.name, manifest_hash=row.manifest_hash, approved_at=stamp
        )
    return ApprovedTools(tools=tuple(current[name] for name in sorted(current)))


def save_approved(path: Path, approved: ApprovedTools) -> None:
    temporary = path.with_name(path.name + ".tmp")
    body = json.dumps(json.loads(approved.model_dump_json()), indent=2)
    temporary.write_text(body + "\n", encoding="utf-8")
    temporary.replace(path)

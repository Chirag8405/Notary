"""The labeling policy of the seeded world: which tools give which origin, which fields are facts.

Mirrors `OutputRecord.platform_fields` in `notary_world.tools`: the stamped fields are named by the
tool's own schema (never by content), so an attacker cannot make a field trusted by naming it.
Everything not listed stays untrusted.
"""

from notary_core.gateway import FieldStamp, LabelingPolicy, ToolOriginRule
from notary_core.models import EmailOrigin, FileOrigin


def world_labeling_policy() -> LabelingPolicy:
    return LabelingPolicy(
        origins=(
            ToolOriginRule(tool="list_files", origin=FileOrigin(kind="file")),
            ToolOriginRule(tool="read_email", origin=EmailOrigin(kind="email")),
            ToolOriginRule(tool="read_file", origin=FileOrigin(kind="file")),
            ToolOriginRule(tool="read_inbox", origin=EmailOrigin(kind="email")),
        ),
        stamps=(
            FieldStamp(tool="get_balance", field="balance", integrity="trusted"),
            FieldStamp(tool="get_balance", field="iban", integrity="trusted"),
            FieldStamp(tool="read_email", field="verified", integrity="trusted"),
            FieldStamp(tool="read_inbox", field="verified", integrity="trusted"),
        ),
    )

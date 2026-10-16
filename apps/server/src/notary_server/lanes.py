"""The three lanes as configurations of the one agent runner, and the baseline stream view.

A lane is only a choice of hooks (`notary_core.runner.hooks_for_lane` allows exactly three). The
baseline lanes (Undefended, Classifier-only) run through the same engine as NOTARY, with an
allow-all monitor, so the oracle gets a full `RunRecord` for every lane. Their golden streams do
not show a gate's events, so `stream_for_lane` is a VIEW that drops those events and renumbers
`seq`; the audit chain itself is never rewritten.
"""

from collections.abc import Iterable, Iterator

from notary_core.models import Event, Lane, RunStarted
from notary_core.monitor import Monitor
from notary_core.runner import RunnerHooks, hooks_for_lane
from notary_world.classifier import ClassifierFilter
from notary_world.executor import default_monitor
from notary_world.golden import CLASSIFIER_NAME

LANES: tuple[Lane, ...] = ("undefended", "classifier", "notary")

GATELESS_DROPPED: frozenset[str] = frozenset(
    {"decision_made", "value_labeled", "endorsement_requested"}
)
"""Event types a lane without a gate does not show (the golden baseline streams omit them)."""


def lane_hooks(lane: Lane, *, gate: Monitor | None = None) -> RunnerHooks:
    """The hooks of a lane; a gate is only for NOTARY (default: the real monitor)."""
    if lane == "notary":
        return hooks_for_lane("notary", gate=gate if gate is not None else default_monitor())
    if gate is not None:
        raise ValueError("only the notary lane has a gate")
    if lane == "classifier":
        return hooks_for_lane("classifier", classifier_filter=ClassifierFilter())
    return hooks_for_lane("undefended")


def stream_for_lane(events: Iterable[Event], lane: Lane) -> Iterator[Event]:
    """What the UI shows for `lane`; lazy, one event at a time.

    NOTARY is unchanged. The baselines drop `GATELESS_DROPPED` events, renumber `seq` from 0 so
    it stays contiguous, and the classifier lane names its stand-in in `run_started`.
    """
    if lane == "notary":
        yield from events
        return
    number = 0
    for event in events:
        if event.type in GATELESS_DROPPED:
            continue
        update: dict[str, object] = {"seq": number}
        if lane == "classifier" and isinstance(event, RunStarted):
            update["classifier"] = CLASSIFIER_NAME
        yield event.model_copy(update=update)
        number += 1

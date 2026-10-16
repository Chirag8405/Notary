import pytest

from notary_core.gateway import ToolResult, label_tool_result
from notary_core.monitor import decide
from notary_core.runner import FilteredResult, hooks_for_lane


def _filter(result: ToolResult) -> FilteredResult:
    return FilteredResult(result=result, flags=())


def test_undefended_lane_has_no_hooks() -> None:
    hooks = hooks_for_lane("undefended")
    assert hooks.pre_filter is None
    assert hooks.gate is None
    with pytest.raises(ValueError, match="lane"):
        hooks_for_lane("undefended", gate=decide)
    with pytest.raises(ValueError, match="lane"):
        hooks_for_lane("undefended", classifier_filter=_filter)


def test_classifier_lane_needs_a_pre_filter_and_no_gate() -> None:
    hooks = hooks_for_lane("classifier", classifier_filter=_filter)
    assert hooks.pre_filter is _filter
    assert hooks.gate is None
    with pytest.raises(ValueError, match="lane"):
        hooks_for_lane("classifier")
    with pytest.raises(ValueError, match="lane"):
        hooks_for_lane("classifier", classifier_filter=_filter, gate=decide)


def test_notary_lane_needs_a_gate_and_no_pre_filter() -> None:
    hooks = hooks_for_lane("notary", gate=decide)
    assert hooks.gate is decide
    assert hooks.pre_filter is None
    with pytest.raises(ValueError, match="lane"):
        hooks_for_lane("notary")
    with pytest.raises(ValueError, match="lane"):
        hooks_for_lane("notary", gate=decide, classifier_filter=_filter)


def test_gateway_labeling_is_a_stub_until_p3a() -> None:
    with pytest.raises(NotImplementedError):
        label_tool_result(ToolResult(tool="t", record_id="r", fields=()), readers=())

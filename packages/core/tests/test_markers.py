"""Tests of the marker machinery and the shared factories in conftest.py."""

import hashlib
from collections.abc import Callable
from pathlib import Path

import pytest
from pydantic import ValidationError

from notary_core.models import IntentContract, ResolvedValue

pytest_plugins = ["pytester"]

CONFTEST = (Path(__file__).parent / "conftest.py").read_text()


def _run(pytester: pytest.Pytester, body: str) -> pytest.RunResult:
    pytester.makeconftest(CONFTEST)
    pytester.makepyfile(body)
    return pytester.runpytest("--strict-markers")


def test_unknown_invariant_id_is_a_usage_error(pytester: pytest.Pytester) -> None:
    result = _run(
        pytester,
        """
        import pytest

        @pytest.mark.invariant("I9")
        def test_x() -> None: ...
        """,
    )
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.fnmatch_lines(["*unknown id I9*"])


def test_unknown_attack_id_is_a_usage_error(pytester: pytest.Pytester) -> None:
    result = _run(
        pytester,
        """
        import pytest

        @pytest.mark.attack("A15")
        def test_x() -> None: ...
        """,
    )
    assert result.ret == pytest.ExitCode.USAGE_ERROR
    result.stderr.fnmatch_lines(["*unknown id A15*"])


def test_marker_without_id_is_a_usage_error(pytester: pytest.Pytester) -> None:
    result = _run(
        pytester,
        """
        import pytest

        @pytest.mark.invariant
        def test_x() -> None: ...
        """,
    )
    assert result.ret == pytest.ExitCode.USAGE_ERROR


def test_valid_markers_collect_and_are_summarized(pytester: pytest.Pytester) -> None:
    result = _run(
        pytester,
        """
        import pytest

        @pytest.mark.invariant("I2")
        @pytest.mark.attack("A3")
        def test_x() -> None: ...
        """,
    )
    result.assert_outcomes(passed=1)
    result.stdout.fnmatch_lines(["I/A coverage: A3 I2 | uncovered: *"])


@pytest.mark.invariant("I2")
def test_make_value_hash_matches_text(make_value: Callable[..., ResolvedValue]) -> None:
    value = make_value("v1", "DE89 3704 0044 0532 0130 00", unit="iban")
    assert value.ref.content_hash == hashlib.sha256(value.text.encode("utf-8")).hexdigest()


@pytest.mark.invariant("I5")
def test_make_contract_is_valid_and_frozen(
    make_contract: Callable[..., IntentContract], make_scope: Callable[..., object]
) -> None:
    contract = make_contract(tools=(make_scope("pay"),))
    assert contract.allowed_tools[0].tool == "pay"
    with pytest.raises(ValidationError):
        contract.contract_id = "other"

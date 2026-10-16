import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import TypeAdapter, ValidationError

from notary_core.models import (
    CHECK_ORDER,
    Decision,
    Event,
    Label,
    UserOrigin,
    ValueRef,
)
from notary_core.monitor import decide

HASH = "a" * 64


def _value(value_id: str) -> ValueRef:
    label = Label(
        origin=UserOrigin(kind="user"), integrity="trusted", readers=(), span_pointer=None
    )
    return ValueRef(id=value_id, label=label, content_hash=HASH)


def test_models_are_frozen() -> None:
    value = _value("v1")
    with pytest.raises(ValidationError):
        value.id = "other"


def test_extra_fields_forbidden() -> None:
    with pytest.raises(ValidationError):
        ValueRef.model_validate_json(
            '{"id":"v","label":{"origin":{"kind":"user"},"integrity":"trusted",'
            f'"readers":[],"span_pointer":null}},"content_hash":"{HASH}","extra":1}}'
        )


def test_bad_hash_rejected() -> None:
    with pytest.raises(ValidationError):
        ValueRef(id="v", label=_value("x").label, content_hash="nope")


@given(st.text(min_size=1))
def test_value_ref_json_round_trip(value_id: str) -> None:
    value = _value(value_id)
    assert ValueRef.model_validate_json(value.model_dump_json()) == value


def test_event_discriminator_rejects_unknown_type() -> None:
    adapter = TypeAdapter(Event)
    with pytest.raises(ValidationError):
        adapter.validate_json('{"type":"nope","run_id":"r","seq":0}')


def test_check_order() -> None:
    assert CHECK_ORDER == (
        "scope",
        "irreversibility",
        "origin",
        "corroboration",
        "confidentiality",
        "budget",
    )


def test_stubs_not_implemented() -> None:
    with pytest.raises(NotImplementedError):
        decide(None, None, {}, (), None)  # pyright: ignore[reportArgumentType]


def test_decision_type_exported() -> None:
    assert Decision.model_fields["verdict"] is not None

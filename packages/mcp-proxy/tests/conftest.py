"""I/A markers for the gateway tests, registered the way `packages/core/tests/conftest.py` does."""

import pytest

VALID_INVARIANTS = {f"I{i}" for i in range(1, 7)}
VALID_ATTACKS = {f"A{i}" for i in range(1, 15)}

_MARKER_IDS = {"invariant": VALID_INVARIANTS, "attack": VALID_ATTACKS}


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "invariant(id): test covers invariant I1-I6")
    config.addinivalue_line("markers", "attack(id): test covers attack A1-A14")


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    for item in items:
        for name, valid in _MARKER_IDS.items():
            for marker in item.iter_markers(name):
                if not marker.args:
                    raise pytest.UsageError(f"{item.nodeid}: {name} marker needs an id")
                for arg in marker.args:
                    if arg not in valid:
                        raise pytest.UsageError(f"unknown id {arg}")

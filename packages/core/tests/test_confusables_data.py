"""The embedded confusables table is exactly what the generator makes from the vendored input."""

import hashlib
import importlib.util
import re
import sys
import unicodedata
from pathlib import Path
from types import ModuleType

import pytest

from notary_core import _confusables_data
from notary_core._confusables_data import SKELETON

CORE_ROOT = Path(__file__).resolve().parents[1]
SUBSET = CORE_ROOT / "data" / "confusables-subset.txt"
MODULE = CORE_ROOT / "src" / "notary_core" / "_confusables_data.py"


def _load_generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "gen_confusables", CORE_ROOT / "scripts" / "gen_confusables.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_confusables"] = module
    spec.loader.exec_module(module)
    return module


GEN = _load_generator()


@pytest.mark.invariant("I6")
def test_committed_module_matches_regeneration_from_vendored_input() -> None:
    subset = SUBSET.read_text(encoding="utf-8")
    assert GEN.render_module(subset) == MODULE.read_text(encoding="utf-8")
    assert GEN.render_module(subset) == GEN.render_module(subset)


def test_generated_header_names_the_pinned_input() -> None:
    subset = SUBSET.read_text(encoding="utf-8")
    assert GEN._header_field(subset, "Upstream-Version") == _confusables_data.UNICODE_VERSION
    assert re.fullmatch(r"\d+\.\d+\.\d+", _confusables_data.UNICODE_VERSION)
    assert _confusables_data.SOURCE_SHA256 in subset
    assert len(_confusables_data.SOURCE_SHA256) == 64
    head = MODULE.read_text(encoding="utf-8").split('"""', 2)[1]
    assert "DO NOT EDIT BY HAND" in head
    assert _confusables_data.UNICODE_VERSION in head
    assert "gen_confusables.py" in head


def test_vendored_subset_is_a_verbatim_filtered_subset() -> None:
    lines = [ln for ln in SUBSET.read_text(encoding="utf-8").split("\n") if ln.strip()]
    data = [ln for ln in lines if not ln.startswith("#")]
    entries = GEN.parse_entries("\n".join(data))
    assert [e.line for e in entries] == data
    assert len(entries) > 1500
    assert all(len(e.source) == 1 and set(e.target) <= GEN.TARGET_CHARS for e in entries)
    declared = re.search(r"# (\d+) of (\d+) mappings kept", SUBSET.read_text(encoding="utf-8"))
    assert declared is not None
    assert int(declared.group(1)) == len(entries)
    assert (
        (CORE_ROOT / "data" / "UNICODE-LICENSE.txt")
        .read_text(encoding="utf-8")
        .startswith("UNICODE LICENSE V3")
    )


def test_filter_stage_is_deterministic_and_keeps_only_allowed_targets() -> None:
    upstream = (
        "\ufeff# confusables.txt\r\n# Date: 2000-01-01, 00:00:00 GMT\r\n# Version: 9.9.9\r\n\r\n"
        "0430 ;\t0061 ;\tMA\t# ( \u0430 \u2192 a ) CYRILLIC A \u2192 LATIN A\t#\r\n"
        "00A1 ;\t0021 ;\tMA\t# ( \u00a1 \u2192 ! ) INVERTED BANG \u2192 BANG\t#\r\n"
        "2010 ;\t002D ;\tMA\t#* ( \u2010 \u2192 - ) HYPHEN \u2192 HYPHEN-MINUS\t#\r\n"
    )
    text = upstream.replace("\r\n", "\n").removeprefix("\ufeff")
    out = GEN.filter_upstream(text)
    assert out == GEN.filter_upstream(text)
    assert "0430 ;" in out
    assert "2010 ;" in out
    assert "00A1 ;" not in out
    assert "Upstream-Version: 9.9.9" in out
    assert hashlib.sha256(text.encode("utf-8")).hexdigest() in out


def test_table_shape() -> None:
    assert len(SKELETON) > 500
    keys = set(SKELETON)
    for key, value in SKELETON.items():
        assert len(key) == 1
        assert value
        assert value == value.lower()
        assert set(value) <= GEN.TARGET_CHARS
        assert key != value
        # Looked up after NFKC and casefold, so a key those would change could never match.
        assert unicodedata.normalize("NFKC", key) == key
        assert key.casefold() == key
        # No target is itself rewritten: one lookup per character is a complete mapping.
        assert not set(value) & keys, (key, value)


def test_known_entries() -> None:
    assert SKELETON["\u0430"] == "a"  # Cyrillic a
    assert SKELETON["\u043e"] == "o"
    assert SKELETON["\u03bf"] == "o"  # Greek omicron
    assert SKELETON["\u0456"] == "l"  # Cyrillic i, chained through i -> l
    assert SKELETON["i"] == "l"
    assert SKELETON["0"] == "o"
    assert "m" not in SKELETON  # upstream m -> rn is the reverse of the sequence rule

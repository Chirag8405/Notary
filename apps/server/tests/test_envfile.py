"""The `.env` loader: parsing, precedence and secrecy."""

from pathlib import Path

import pytest

from notary_server.envfile import find_env_file, load_env_file, parse_env


@pytest.mark.invariant("I6")
def test_parse_env() -> None:
    text = (
        "# comment\n\nA=1\nexport B = two \nC=\"quoted value\"\nD='single'\nE=\nnot a pair\nF=a=b\n"
    )
    assert parse_env(text) == {
        "A": "1",
        "B": "two",
        "C": "quoted value",
        "D": "single",
        "E": "",
        "F": "a=b",
    }


@pytest.mark.invariant("I6")
def test_load_sets_only_missing_or_empty_names(tmp_path: Path) -> None:
    file = tmp_path / ".env"
    file.write_text("GROQ_API_KEY=from-file\nKEPT=from-file\nEMPTY=from-file\nBLANK=\n")
    environ = {"KEPT": "from-shell", "EMPTY": ""}
    applied = load_env_file(file, environ)
    assert sorted(applied) == ["EMPTY", "GROQ_API_KEY"]
    assert environ == {"GROQ_API_KEY": "from-file", "KEPT": "from-shell", "EMPTY": "from-file"}
    assert "from-file" not in "".join(applied)


@pytest.mark.invariant("I6")
def test_missing_file_is_not_an_error(tmp_path: Path) -> None:
    environ: dict[str, str] = {}
    assert load_env_file(tmp_path / "nope", environ) == []
    assert environ == {}


@pytest.mark.invariant("I6")
def test_find_env_file_walks_up(tmp_path: Path) -> None:
    (tmp_path / ".env").write_text("A=1\n")
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert find_env_file(nested) == tmp_path / ".env"

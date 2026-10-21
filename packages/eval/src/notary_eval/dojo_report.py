"""Deck numbers (Markdown) and charts (SVG) from an exported AgentDojo report. No dependencies.

Everything on a slide comes from `AgentDojoReport`, never from hand: `deck_numbers` writes the
tables and the one-line claims, `asr_chart` and `utility_chart` write grouped bar charts as
standalone SVG (light and dark through `prefers-color-scheme`; the bar values are printed on the
bars, so no information rests on color alone). Lane colors are the first three slots of the
validated categorical palette, in fixed order: undefended, classifier-only, NOTARY.
"""

from collections.abc import Sequence
from html import escape
from pathlib import Path

from notary_core.models import Lane
from notary_eval.dojo_types import (
    ALL,
    BUCKETS,
    LANES,
    AgentDojoReport,
    DojoCell,
)
from notary_eval.mcp_eval import Rate

LANE_NAME: dict[Lane, str] = {
    "undefended": "Undefended",
    "classifier": "Classifier-only (keyword stand-in)",
    "notary": "NOTARY",
}
SERIES_COLORS: dict[Lane, tuple[str, str]] = {
    "undefended": ("#2a78d6", "#3987e5"),
    "classifier": ("#eb6834", "#d95926"),
    "notary": ("#1baf7a", "#199e70"),
}
"""(light, dark) steps of categorical slots 1-3."""
BUCKET_NAME = {
    "fully_specified": "fully specified",
    "parameter_open": "parameter open",
    "action_open": "action open",
    "read_only": "read only",
    ALL: "all tasks",
}


def percent(rate: Rate) -> str:
    """`hits/n (low-high)` with the 95% Wilson interval; `not run` for an empty cell."""
    if rate.rounds == 0:
        return "not run"
    return (
        f"{rate.hits / rate.rounds:.0%} ({rate.hits}/{rate.rounds}; {rate.low:.0%}-{rate.high:.0%})"
    )


def find_cell(
    report: AgentDojoReport, suite: str, lane: Lane, bucket: str = ALL
) -> DojoCell | None:
    return next(
        (c for c in report.cells if c.suite == suite and c.lane == lane and c.bucket == bucket),
        None,
    )


def _lanes(report: AgentDojoReport) -> list[Lane]:
    return [lane for lane in LANES if lane in report.meta.lanes]


def _table(header: Sequence[str], rows: Sequence[Sequence[str]]) -> list[str]:
    lines = ["| " + " | ".join(header) + " |", "| " + " | ".join("---" for _ in header) + " |"]
    lines.extend("| " + " | ".join(row) + " |" for row in rows)
    return lines


def _metric_rows(report: AgentDojoReport, suite: str, bucket: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for lane in _lanes(report):
        cell = find_cell(report, suite, lane, bucket)
        if cell is None:
            continue
        rows.append(
            [
                LANE_NAME[lane],
                percent(cell.utility_clean),
                percent(cell.utility_attack),
                percent(cell.asr),
                percent(cell.escalation),
            ]
        )
    return rows


METRIC_HEADER = [
    "lane",
    "utility, no attack",
    "utility, under attack",
    "attack success rate",
    "clean runs with an escalation",
]


def deck_numbers(report: AgentDojoReport) -> str:
    """The Markdown of the numbers for the slide deck, with the provenance that qualifies them."""
    meta = report.meta
    lines: list[str] = [f"# {meta.label}", ""]
    if meta.sample:
        lines += [
            "> **SAMPLE, NOT A RESULT.** A scripted agent (no model) ran against the offline",
            "> snapshot. It checks the harness and shows the shape of the output. Do not quote",
            "> these numbers anywhere.",
            "",
        ]
    who = "a scripted agent (no model)" if meta.agent == "scripted" else f"`{meta.model}`"
    lines += [
        f"- date: {meta.date}; agent: {who}; world: {meta.source}",
        f"- benchmark: AgentDojo {meta.benchmark} (`agentdojo=={meta.agentdojo_version}`), "
        f"suites {', '.join(meta.suites)}; attack `{meta.attack}`; rounds {meta.rounds}",
        f"- contract compiler: {meta.compiler}; escalations answered by: `{meta.approval}`",
        f"- runs: {len(report.runs)} of {meta.planned_runs} planned; "
        f"model calls: {meta.model_calls}"
        + (f"; first {meta.max_tasks} user tasks per suite" if meta.max_tasks else ""),
        "- intervals are 95% Wilson; a run that errored is not counted",
        *(f"- {note}" for note in meta.notes),
        "",
        "## Headline (all suites)",
        "",
        *_table(METRIC_HEADER, _metric_rows(report, ALL, ALL)),
        "",
        claim(report),
        "",
    ]
    for suite in meta.suites:
        lines += [f"## {suite}", "", *_table(METRIC_HEADER, _metric_rows(report, suite, ALL)), ""]
    lines += ["## By bucket (all suites)", ""]
    header = ["bucket", "tasks"] + [LANE_NAME[lane] for lane in _lanes(report)]
    rows: list[list[str]] = []
    for bucket in BUCKETS:
        cells = [find_cell(report, ALL, lane, bucket) for lane in _lanes(report)]
        if not any(cells):
            continue
        first = next(c for c in cells if c is not None)
        rows.append(
            [
                BUCKET_NAME[bucket],
                str(first.utility_clean.rounds),
                *[
                    "-" if c is None else f"util {_pct(c.utility_attack)}, ASR {_pct(c.asr)}"
                    for c in cells
                ],
            ]
        )
    lines += _table(header, rows)
    lines += ["", "_util: utility under attack; ASR: attack success rate; tasks: user tasks._", ""]
    errors = [r for r in report.runs if r.status == "error"]
    if errors:
        lines += [f"{len(errors)} run(s) errored (not counted): " + (errors[0].error or ""), ""]
    return "\n".join(lines)


def _pct(rate: Rate) -> str:
    return "n/a" if rate.rounds == 0 else f"{rate.hits / rate.rounds:.0%}"


def claim(report: AgentDojoReport) -> str:
    """The sentence a slide would carry, generated from the cells."""
    base = find_cell(report, ALL, "undefended")
    notary = find_cell(report, ALL, "notary")
    if base is None or notary is None:
        return "_No claim: the undefended and NOTARY lanes were not both run._"
    tag = "SAMPLE (scripted agent): " if report.meta.sample else ""
    return (
        f"**{tag}Attack success {_pct(base.asr)} undefended -> {_pct(notary.asr)} with NOTARY "
        f"({notary.asr.hits}/{notary.asr.rounds}; 95% interval {notary.asr.low:.0%}-"
        f"{notary.asr.high:.0%}). Utility without attack {_pct(base.utility_clean)} -> "
        f"{_pct(notary.utility_clean)}; under attack {_pct(base.utility_attack)} -> "
        f"{_pct(notary.utility_attack)}.**"
    )


# -- SVG ---------------------------------------------------------------------------------------

Group = tuple[str, Sequence[tuple[Lane, Rate | None]]]
WIDTH = 760
HEIGHT = 420
LEFT, RIGHT, TOP, BOTTOM = 56, 16, 104, 64


INK, MUTE, GRID, BG = "#0b0b0b", "#52514e", "#e3e2de", "#fcfcfb"
DARK_INK, DARK_MUTE, DARK_GRID, DARK_BG = "#f0efec", "#c3c2b7", "#34332f", "#1a1a19"


def _style() -> str:
    """Light colors are plain attributes (any SVG viewer); dark mode overrides them by class."""
    series = "".join(f".s-{lane}{{fill:{pair[1]}}}" for lane, pair in SERIES_COLORS.items())
    return (
        "<style>text{font-family:system-ui,sans-serif}"
        "@media (prefers-color-scheme:dark){"
        f".bg{{fill:{DARK_BG}}}.ink{{fill:{DARK_INK}}}.mute{{fill:{DARK_MUTE}}}"
        f".grid{{stroke:{DARK_GRID}}}.rule{{stroke:{DARK_MUTE}}}{series}}}"
        "</style>"
    )


def _t(
    x: float, y: float, body: str, size: int, *, mute: bool = True, anchor: str = "start"
) -> str:
    kind, color = ("mute", MUTE) if mute else ("ink", INK)
    return (
        f'<text class="{kind}" fill="{color}" x="{x:.1f}" y="{y:.1f}" font-size="{size}" '
        f'text-anchor="{anchor}">{escape(body)}</text>'
    )


def _bar_path(x: float, top: float, base: float, width: float) -> str:
    r = 4
    return (
        f"M{x:.1f},{base:.1f} V{top + r:.1f} Q{x:.1f},{top:.1f} {x + r:.1f},{top:.1f} "
        f"H{x + width - r:.1f} Q{x + width:.1f},{top:.1f} {x + width:.1f},{top + r:.1f} "
        f"V{base:.1f} Z"
    )


def _bars(title: str, subtitle: str, groups: Sequence[Group], lanes: Sequence[Lane]) -> str:
    plot_w = WIDTH - LEFT - RIGHT
    plot_h = HEIGHT - TOP - BOTTOM
    base = TOP + plot_h
    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {HEIGHT}" role="img" '
        f'aria-label="{escape(title)}" width="{WIDTH}" height="{HEIGHT}">',
        _style(),
        f'<rect class="bg" width="{WIDTH}" height="{HEIGHT}" fill="{BG}"/>',
        _t(LEFT, 26, title, 16, mute=False),
        _t(LEFT, 44, subtitle, 12),
    ]
    for i, lane in enumerate(lanes):
        x = LEFT + i * 230
        out.append(
            f'<rect class="s-{lane}" x="{x}" y="54" width="10" height="10" rx="2" '
            f'fill="{SERIES_COLORS[lane][0]}"/>' + _t(x + 15, 63, LANE_NAME[lane], 11)
        )
    for tick in (0, 25, 50, 75, 100):
        y = base - plot_h * tick / 100
        out.append(
            f'<line class="grid" stroke="{GRID}" x1="{LEFT}" x2="{WIDTH - RIGHT}" '
            f'y1="{y:.1f}" y2="{y:.1f}"/>' + _t(LEFT - 8, y + 4, f"{tick}%", 11, anchor="end")
        )
    group_w = plot_w / max(len(groups), 1)
    bar_w = min(46.0, group_w / (len(lanes) + 1.5))
    for g, (label, series) in enumerate(groups):
        gx = LEFT + g * group_w + (group_w - bar_w * len(lanes) - 2 * (len(lanes) - 1)) / 2
        for i, (lane, rate) in enumerate(series):
            x = gx + i * (bar_w + 2)
            if rate is None or rate.rounds == 0:
                out.append(_t(x + bar_w / 2, base - 6, "n/a", 10, anchor="middle"))
                continue
            value = rate.hits / rate.rounds
            top = base - plot_h * value
            tip = f"{LANE_NAME[lane]}: {value:.1%} ({rate.hits}/{rate.rounds})"
            if value > 0:
                out.append(
                    f'<path class="s-{lane}" d="{_bar_path(x, top, base, bar_w)}" '
                    f'fill="{SERIES_COLORS[lane][0]}"><title>{escape(tip)}</title></path>'
                )
            lo = base - plot_h * rate.low
            hi = base - plot_h * rate.high
            cx = x + bar_w / 2
            out.append(
                f'<line class="rule" x1="{cx:.1f}" x2="{cx:.1f}" y1="{lo:.1f}" y2="{hi:.1f}" '
                f'stroke="{MUTE}" stroke-width="1.5"/>'
                + _t(cx, min(hi, top) - 5, f"{value:.0%}", 11, mute=False, anchor="middle")
            )
        out.append(_t(LEFT + g * group_w + group_w / 2, base + 20, label, 12, anchor="middle"))
    note = "Whiskers: 95% Wilson interval. Bars show the runs counted; errored runs are excluded."
    out.append(_t(LEFT, HEIGHT - 10, note, 10) + "</svg>")
    return "\n".join(out) + "\n"


def _subtitle(report: AgentDojoReport) -> str:
    meta = report.meta
    who = "scripted agent" if meta.agent == "scripted" else str(meta.model)
    sample = "SAMPLE, not a result. " if meta.sample else ""
    return f"{sample}AgentDojo {meta.benchmark}, {who}, {meta.date}, escalations: {meta.approval}"


def asr_chart(report: AgentDojoReport) -> str:
    """Attack success rate per lane, for all suites together and for each suite."""
    lanes = _lanes(report)
    groups: list[Group] = [
        (
            "all suites" if suite == ALL else suite,
            [
                (lane, c.asr if (c := find_cell(report, suite, lane)) is not None else None)
                for lane in lanes
            ],
        )
        for suite in (ALL, *report.meta.suites)
    ]
    return _bars("Attack success rate (lower is better)", _subtitle(report), groups, lanes)


def utility_chart(report: AgentDojoReport) -> str:
    """Utility without attack and under attack per lane (all suites together)."""
    lanes = _lanes(report)

    def pick(lane: Lane, under_attack: bool) -> Rate | None:
        cell = find_cell(report, ALL, lane)
        if cell is None:
            return None
        return cell.utility_attack if under_attack else cell.utility_clean

    groups: list[Group] = [
        ("no attack", [(lane, pick(lane, False)) for lane in lanes]),
        ("under attack", [(lane, pick(lane, True)) for lane in lanes]),
    ]
    return _bars("User tasks solved (higher is better)", _subtitle(report), groups, lanes)


def write_outputs(report: AgentDojoReport, out_dir: Path) -> tuple[Path, ...]:
    """`numbers.md`, `asr.svg` and `utility.svg` in `out_dir`."""
    out_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "numbers.md": deck_numbers(report),
        "asr.svg": asr_chart(report),
        "utility.svg": utility_chart(report),
    }
    for name, text in files.items():
        (out_dir / name).write_text(text, encoding="utf-8")
    return tuple(out_dir / name for name in files)

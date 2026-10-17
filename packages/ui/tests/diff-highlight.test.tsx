import { describe, expect, it } from "vitest";

import { highlightDiff } from "../src/diff-highlight";
import { load, must } from "./golden";

const joined = (segments: readonly { text: string }[]) => segments.map((s) => s.text).join("");

describe("highlightDiff", () => {
  it("splits into equal and differing runs [A3]", () => {
    expect(highlightDiff("abcd", [1, 2])).toEqual([
      { text: "a", differs: false },
      { text: "bc", differs: true },
      { text: "d", differs: false },
    ]);
    expect(highlightDiff("abcd", [])).toEqual([{ text: "abcd", differs: false }]);
    expect(highlightDiff("abcd", [0, 3])).toEqual([
      { text: "a", differs: true },
      { text: "bc", differs: false },
      { text: "d", differs: true },
    ]);
  });

  it("ignores positions that are out of range, negative, fractional, NaN or duplicate [A3]", () => {
    expect(highlightDiff("abcd", [-1, 4, 99, 1.5, Number.NaN, Infinity, 2, 2, 2])).toEqual([
      { text: "ab", differs: false },
      { text: "c", differs: true },
      { text: "d", differs: false },
    ]);
  });

  it("returns no segments for empty text [A3]", () => {
    expect(highlightDiff("", [0, 1])).toEqual([]);
    expect(highlightDiff("", [])).toEqual([]);
  });

  it("counts code points, not UTF-16 units [A3]", () => {
    // "\u{1D400}" is one code point (two UTF-16 units); position 2 is the character after it.
    const text = "a\u{1D400}bc";
    const segments = highlightDiff(text, [2]);
    expect(segments).toEqual([
      { text: "a\u{1D400}", differs: false },
      { text: "b", differs: true },
      { text: "c", differs: false },
    ]);
    expect(joined(segments)).toBe(text);
    expect(highlightDiff(text, [1])[1]).toEqual({ text: "\u{1D400}", differs: true });
  });

  it("keeps the text exactly, including lone surrogates [A3]", () => {
    for (const text of ["x\uD800y", "\uDC00", "a\u{1F600}\uD800b", "plain"]) {
      const positions = [0, 1, 2, 3];
      expect(joined(highlightDiff(text, positions))).toBe(text);
      expect(joined(highlightDiff(text, []))).toBe(text);
    }
  });

  it("merges consecutive characters with the same flag [A3]", () => {
    const segments = highlightDiff("abcdef", [1, 2, 3, 5]);
    expect(segments.map((s) => s.differs)).toEqual([false, true, false, true]);
    for (let i = 1; i < segments.length; i += 1) {
      expect(segments[i]?.differs).not.toBe(segments[i - 1]?.differs);
    }
  });

  it("marks the real payee against the real ledger value [A3]", () => {
    const events = load("poisoned_bill.notary");
    const requested = must(
      events.find((e) => e.type === "endorsement_requested"),
      "endorsement_requested",
    );
    const row = must(requested.endorsement.card.rows[0], "the payee row");
    const unique = new Set(
      row.differing_positions.filter((p) => p < Array.from(row.preview).length),
    );
    const segments = highlightDiff(row.preview, row.differing_positions);
    expect(joined(segments)).toBe(row.preview);
    const marked = segments
      .filter((s) => s.differs)
      .reduce((n, s) => n + Array.from(s.text).length, 0);
    expect(marked).toBe(unique.size);
    expect(unique.size).toBeGreaterThan(0);
  });
});

import type { Marker } from "@notary/schema";
import { describe, expect, it } from "vitest";

import { markerLabel, markerTone } from "../src/marker-chip";
import type { MarkerTone } from "../src/marker-chip";

const CASES: [Marker, string, MarkerTone][] = [
  [
    { kind: "literal", value: "DE89370400440532013000" },
    "literal:DE89370400440532013000",
    "strict",
  ],
  [{ kind: "named_source", source: "contacts" }, "source:contacts", "strict"],
  [{ kind: "ledger", ledger: "payees" }, "ledger:payees", "strict"],
  [{ kind: "endorse" }, "endorse", "gated"],
  [{ kind: "free" }, "free", "open"],
];

describe("markerLabel and markerTone", () => {
  it("cover every marker kind with the fields it really carries [I2]", () => {
    for (const [marker, label, tone] of CASES) {
      expect(markerLabel(marker), marker.kind).toBe(label);
      expect(markerTone(marker), marker.kind).toBe(tone);
    }
    expect(new Set(CASES.map(([marker]) => marker.kind)).size).toBe(5);
  });

  it("maps literal, named_source and ledger to strict, endorse to gated, free to open [I2]", () => {
    expect(CASES.filter(([, , tone]) => tone === "strict").map(([m]) => m.kind)).toEqual([
      "literal",
      "named_source",
      "ledger",
    ]);
    expect(markerTone({ kind: "endorse" })).toBe("gated");
    expect(markerTone({ kind: "free" })).toBe("open");
  });

  it("prints literal values verbatim, including numbers and booleans [I6]", () => {
    expect(markerLabel({ kind: "literal", value: 12000 })).toBe("literal:12000");
    expect(markerLabel({ kind: "literal", value: 120.5 })).toBe("literal:120.5");
    expect(markerLabel({ kind: "literal", value: false })).toBe("literal:false");
    expect(
      markerLabel({ kind: "literal", value: "a very long value that is not cut anywhere" }),
    ).toBe("literal:a very long value that is not cut anywhere");
    expect(markerLabel({ kind: "literal", value: "" })).toBe("literal:");
  });

  it("is pure [I6]", () => {
    const marker: Marker = Object.freeze({ kind: "ledger", ledger: "payees" });
    expect(markerLabel(marker)).toBe(markerLabel(marker));
    expect(markerTone(marker)).toBe(markerTone(marker));
  });
});

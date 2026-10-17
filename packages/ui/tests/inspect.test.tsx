import type { ValueRef } from "@notary/schema";
import { describe, expect, it } from "vitest";

import { inspectValue } from "../src/inspect";
import type { RunView, ValueView } from "../src/run-view";
import { STREAMS, must, viewOf } from "./golden";

const NOTARY = viewOf("poisoned_bill.notary");

function deepFreeze<T>(input: T): T {
  if (input !== null && typeof input === "object" && !Object.isFrozen(input)) {
    Object.freeze(input);
    for (const key of Object.keys(input)) deepFreeze((input as Record<string, unknown>)[key]);
  }
  return input;
}

/** A copy of the view where one value's label is changed. */
function withLabel(
  view: RunView,
  id: string,
  change: Partial<ValueRef["label"]>,
  preview?: string,
): RunView {
  return {
    ...view,
    values: view.values.map((v): ValueView =>
      v.ref.id === id
        ? {
            ...v,
            preview: preview ?? v.preview,
            ref: { ...v.ref, label: { ...v.ref.label, ...change } },
          }
        : v,
    ),
  };
}

function inspect(view: RunView, id: string) {
  return must(inspectValue(view, id), `value ${id}`);
}

describe("inspectValue readers", () => {
  it("decodes public, nobody and principals [I3]", () => {
    expect(inspect(withLabel(NOTARY, "v-payee", { readers: ["*"] }), "v-payee").readers).toEqual({
      kind: "public",
    });
    expect(inspect(withLabel(NOTARY, "v-payee", { readers: [] }), "v-payee").readers).toEqual({
      kind: "nobody",
    });
    expect(
      inspect(withLabel(NOTARY, "v-payee", { readers: ["b", "a"] }), "v-payee").readers,
    ).toEqual({ kind: "principals", names: ["a", "b"] });
  });

  it("collapses a star among names and removes duplicates [I3]", () => {
    expect(
      inspect(withLabel(NOTARY, "v-payee", { readers: ["a", "*"] }), "v-payee").readers,
    ).toEqual({
      kind: "public",
    });
    expect(
      inspect(withLabel(NOTARY, "v-payee", { readers: ["b", "a", "b", "B"] }), "v-payee").readers,
    ).toEqual({ kind: "principals", names: ["B", "a", "b"] });
  });
});

describe("inspectValue on the golden streams", () => {
  it("reads the real untrusted payee [A3]", () => {
    const payee = inspect(NOTARY, "v-payee");
    expect(payee).toMatchObject({
      valueId: "v-payee",
      originKind: "email",
      originName: null,
      integrity: "untrusted",
      unit: "iban",
      labeled: true,
      preview: "DE00ATTACKER0000000001",
      readers: { kind: "principals", names: ["user"] },
    });
    expect(payee.contentHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it("slices spans only as far as the preview reaches, and says when it is approximate [A3]", () => {
    let seen = 0;
    for (const name of STREAMS) {
      const view = viewOf(name);
      for (const value of view.values) {
        const pointer = value.ref.label.span_pointer;
        if (pointer === null) continue;
        seen += 1;
        const source = must(inspect(view, value.ref.id).source, "source");
        expect(source.valueId).toBe(pointer.source_value_id);
        if (source.sourcePreview === null) {
          expect([source.before, source.span, source.after]).toEqual(["", "", ""]);
          expect(source.approximate).toBe(false);
        } else {
          // The server's preview is shorter than the text the offsets refer to, so it is clipped.
          expect(source.before + source.span + source.after).toBe(source.sourcePreview);
          expect(source.approximate).toBe(pointer.end > source.sourcePreview.length);
        }
      }
    }
    expect(seen).toBeGreaterThan(0);
  });

  it("handles the self-pointing email body in one hop [I6]", () => {
    const body = inspect(NOTARY, "v-email-body");
    const source = must(body.source, "source");
    expect(source.valueId).toBe("v-email-body");
    expect(source.sourcePreview).toBe(body.preview);
    expect(source.approximate).toBe(true);
    expect(source.span.length).toBeLessThan(source.end - source.start);
  });

  it("gives an unseen source empty slices and no approximation [I6]", () => {
    const payee = inspect(viewOf("poisoned_bill.undefended"), "v-payee");
    expect(payee.labeled).toBe(false);
    expect(payee.source).toEqual({
      valueId: "v-email-body",
      start: 42,
      end: 66,
      sourcePreview: null,
      before: "",
      span: "",
      after: "",
      approximate: false,
    });
  });
});

describe("inspectValue spans and ids", () => {
  it("splits the preview exactly when the pointer fits inside it [A3]", () => {
    const text = "Pay to DE00ATTACKER0000000001 now";
    const view = withLabel(
      NOTARY,
      "v-email-body",
      { span_pointer: { source_value_id: "v-email-body", start: 7, end: 29 } },
      text,
    );
    const source = must(inspect(view, "v-email-body").source, "source");
    expect([source.before, source.span, source.after]).toEqual([
      "Pay to ",
      "DE00ATTACKER0000000001",
      " now",
    ]);
    expect(source.approximate).toBe(false);
  });

  it("clamps an out-of-range or reversed span without throwing [I6]", () => {
    const point = (start: number, end: number) =>
      must(
        inspect(
          withLabel(NOTARY, "v-payee", {
            span_pointer: { source_value_id: "v-email-body", start, end },
          }),
          "v-payee",
        ).source,
        "source",
      );
    const past = point(40, 500);
    expect(past.approximate).toBe(true);
    expect(past.before + past.span + past.after).toBe(past.sourcePreview);
    const beyond = point(200, 300);
    expect(beyond.span).toBe("");
    expect(beyond.approximate).toBe(true);
    expect(() => point(-5, 3)).not.toThrow();
    expect(point(-5, 3).span).toBe("Amo");
    expect(point(10, 4).span).toBe("");
    expect(point(10, 10).approximate).toBe(false);
  });

  it("returns null for an unknown id and accepts a graph node id once [I6]", () => {
    expect(inspectValue(NOTARY, "nope")).toBeNull();
    expect(inspect(NOTARY, "v:v-payee")).toEqual(inspect(NOTARY, "v-payee"));
    expect(inspect(NOTARY, "v:v-payee").valueId).toBe("v-payee");
    expect(inspectValue(NOTARY, "v:v:v-payee")).toBeNull();
    expect(inspectValue(NOTARY, "x:v-payee")).toBeNull();
    expect(inspectValue(NOTARY, "g:c2")).toBeNull();
  });

  it("names the tool of a tool origin [A3]", () => {
    const view = withLabel(NOTARY, "v-payee", { origin: { kind: "tool", name: "read_file" } });
    expect(inspect(view, "v-payee")).toMatchObject({ originKind: "tool", originName: "read_file" });
  });

  it("is pure [I6]", () => {
    const view = deepFreeze(viewOf("poisoned_bill.notary"));
    const first = inspect(view, "v-payee");
    expect(inspect(view, "v-payee")).toEqual(first);
    expect(first.readers).not.toBe(inspect(view, "v-payee").readers);
  });
});

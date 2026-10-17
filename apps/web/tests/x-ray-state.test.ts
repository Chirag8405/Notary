import { gateNodeId, valueNodeId } from "@notary/ui";
import { describe, expect, it } from "vitest";

import {
  MODES,
  SCENARIOS,
  callIdForSelection,
  describeStreamError,
  effectsOf,
  parseXRayParams,
  scenarioLanes,
  selectionFromChip,
  toLaneStatus,
  valueIdForSelection,
  xrayUrl,
} from "@/lib/x-ray-state";

import { must, viewOf } from "./golden";

const NOTARY = viewOf("poisoned_bill.notary");

describe("scenarioLanes", () => {
  it("lists the lanes that have a stream [I6]", () => {
    expect(scenarioLanes("poisoned_bill")).toEqual(["undefended", "classifier", "notary"]);
    expect(scenarioLanes("legitimate_bill")).toEqual(["notary"]);
    expect(scenarioLanes("anything_else")).toEqual(["notary"]);
  });
});

describe("selection helpers", () => {
  it("uses the same node ids as the graph [A3]", () => {
    expect(selectionFromChip({ callId: "c9", valueId: "v-x" }).nodeId).toBe(valueNodeId("v-x"));
    expect(selectionFromChip({ callId: "c9" }).nodeId).toBe(gateNodeId("c9"));
  });

  it("turns a chip or row click into a node id [A3]", () => {
    expect(selectionFromChip({ callId: "c2", valueId: "v-payee" })).toEqual({
      nodeId: "v:v-payee",
      valueId: "v-payee",
    });
    expect(selectionFromChip({ callId: "c2" })).toEqual({ nodeId: "g:c2", valueId: null });
    expect(selectionFromChip({ callId: "c2", valueId: "" })).toEqual({
      nodeId: "g:c2",
      valueId: null,
    });
  });

  it("inspects a value node as itself, and a gate as its first untrusted argument [A3]", () => {
    expect(valueIdForSelection(NOTARY, "v:v-payee")).toBe("v-payee");
    expect(valueIdForSelection(NOTARY, "v:nope")).toBeNull();
    // pay_bill has amount (trusted) and payee (untrusted): the untrusted one wins although
    // "amount" sorts first.
    expect(valueIdForSelection(NOTARY, "g:c2")).toBe("v-payee");
    // read_inbox has no arguments.
    expect(valueIdForSelection(NOTARY, "g:c1")).toBeNull();
    expect(valueIdForSelection(NOTARY, "g:nope")).toBeNull();
    expect(valueIdForSelection(NOTARY, "x:c2")).toBeNull();
    expect(valueIdForSelection(NOTARY, null)).toBeNull();
  });

  it("falls back to the first argument when none is untrusted [A3]", () => {
    const call = must(NOTARY.calls[1], "c2");
    const payee = must(call.args.payee, "payee");
    const trusted = {
      ...NOTARY,
      calls: NOTARY.calls.map((c) =>
        c.callId === "c2"
          ? {
              ...c,
              args: {
                ...c.args,
                payee: { ...payee, label: { ...payee.label, integrity: "trusted" as const } },
              },
            }
          : c,
      ),
    };
    expect(valueIdForSelection(trusted, "g:c2")).toBe("v-amount");
  });

  it("finds the call of a selected node [A3]", () => {
    expect(callIdForSelection(NOTARY, "g:c2")).toBe("c2");
    expect(callIdForSelection(NOTARY, "g:nope")).toBeNull();
    expect(callIdForSelection(NOTARY, "v:v-payee")).toBe("c2");
    expect(callIdForSelection(NOTARY, "v:v-email-body")).toBeNull();
    expect(callIdForSelection(NOTARY, "v:nope")).toBeNull();
    expect(callIdForSelection(NOTARY, "x:c2")).toBeNull();
    expect(callIdForSelection(NOTARY, null)).toBeNull();
  });
});

describe("effectsOf", () => {
  it("lists the executed effects in call order [A3]", () => {
    expect(effectsOf(NOTARY)).toEqual([
      { callId: "c1", tool: "read_inbox", summary: "read 2 messages" },
    ]);
    const undefended = effectsOf(viewOf("poisoned_bill.undefended"));
    expect(undefended.map((e) => [e.callId, e.tool])).toEqual([
      ["c1", "read_inbox"],
      ["c2", "pay_bill"],
    ]);
    expect(must(undefended[1], "payment").summary).toContain("DE00ATTACKER0000000001");
    expect(effectsOf({ ...NOTARY, calls: [] })).toEqual([]);
  });

  it("orders by proposed seq, not by input order [I6]", () => {
    const view = viewOf("poisoned_bill.undefended");
    expect(effectsOf({ ...view, calls: [...view.calls].reverse() }).map((e) => e.callId)).toEqual([
      "c1",
      "c2",
    ]);
  });
});

describe("describeStreamError", () => {
  it("names each failure in words [I6]", () => {
    const url = "http://localhost:8000";
    expect(describeStreamError(1006, "x", url)).toBe(
      "Could not reach the server at http://localhost:8000. Start the server and press Run again.",
    );
    expect(describeStreamError(4404, "x", url)).toBe("Unknown scenario.");
    expect(describeStreamError(4501, "x", url)).toBe("This mode is not available on the server.");
    expect(describeStreamError(4400, "x", url)).toBe("The server rejected the request.");
    expect(describeStreamError(4409, "x", url)).toBe("This request is no longer open.");
    expect(describeStreamError(4422, "x", url)).toBe("The server does not accept that command.");
    expect(describeStreamError(4999, "boom", url)).toBe("boom");
    expect(describeStreamError(4999, undefined, url)).toBe("The connection closed unexpectedly.");
    expect(describeStreamError(undefined, "bad event", url)).toBe("bad event");
    expect(describeStreamError(undefined, "", url)).toBe("The connection closed unexpectedly.");
  });
});

describe("toLaneStatus", () => {
  it("maps the hook's status to the lane status [I6]", () => {
    expect(toLaneStatus("connecting")).toBe("waiting");
    expect(toLaneStatus("open")).toBe("running");
    expect(toLaneStatus("finished")).toBe("finished");
    expect(toLaneStatus("error")).toBe("error");
  });
});

describe("parseXRayParams and xrayUrl", () => {
  it("defaults and whitelists hostile values [I6]", () => {
    expect(parseXRayParams({})).toEqual({
      scenario: "poisoned_bill",
      mode: "golden",
      viewMode: "single",
    });
    expect(parseXRayParams({ scenario: "../x", mode: "evil", view: "<script>" })).toEqual({
      scenario: "poisoned_bill",
      mode: "golden",
      viewMode: "single",
    });
    expect(
      parseXRayParams({ scenario: "legitimate_bill", mode: "cassette", view: "three" }),
    ).toEqual({ scenario: "legitimate_bill", mode: "cassette", viewMode: "three-lane" });
  });

  it("takes the first value of a repeated parameter [I6]", () => {
    expect(
      parseXRayParams({
        scenario: ["legitimate_bill", "x"],
        mode: ["live"],
        view: ["three", "single"],
      }),
    ).toEqual({ scenario: "legitimate_bill", mode: "live", viewMode: "three-lane" });
    expect(parseXRayParams({ scenario: [], mode: [] })).toEqual({
      scenario: "poisoned_bill",
      mode: "golden",
      viewMode: "single",
    });
  });

  it("builds the address deterministically and round-trips [I6]", () => {
    expect(xrayUrl({ scenario: "poisoned_bill", mode: "golden", viewMode: "single" })).toBe(
      "/x-ray?scenario=poisoned_bill&mode=golden&view=single",
    );
    expect(xrayUrl({ scenario: "legitimate_bill", mode: "live", viewMode: "three-lane" })).toBe(
      "/x-ray?scenario=legitimate_bill&mode=live&view=three",
    );
    expect(xrayUrl({ scenario: "a b&c", mode: "m", viewMode: "single" })).toBe(
      "/x-ray?scenario=a%20b%26c&mode=m&view=single",
    );
    for (const scenario of SCENARIOS) {
      for (const mode of MODES) {
        for (const viewMode of ["single", "three-lane"] as const) {
          const query = new URL(xrayUrl({ scenario, mode, viewMode }), "http://x").searchParams;
          expect(
            parseXRayParams({
              scenario: query.get("scenario") ?? undefined,
              mode: query.get("mode") ?? undefined,
              view: query.get("view") ?? undefined,
            }),
          ).toEqual({ scenario, mode, viewMode });
        }
      }
    }
  });
});

import { describe, expect, it } from "vitest";

import {
  CHAIN_BROKEN,
  MCP_NOT_ENABLED,
  MCP_UNKNOWN_RUN,
  describeStreamError,
  modeOptions,
  parseXRayParams,
  selectMode,
  settleSelection,
  streamProblem,
  xrayUrl,
} from "@/lib/x-ray-state";

const RUN = "mcp-0123456789ab";

describe("mode mcp", () => {
  it("takes a run id from the address only in mode mcp and only in the proxy's format [I6]", () => {
    expect(parseXRayParams({ mode: "mcp", scenario: RUN })).toEqual({
      scenario: RUN,
      mode: "mcp",
      viewMode: "single",
    });
    for (const bad of ["../x", "mcp-xyz", "mcp-0123456789AB", "poisoned_bill", undefined]) {
      expect(parseXRayParams({ mode: "mcp", scenario: bad }).scenario).toBe("");
    }
    // Outside mode mcp a run id is not a scenario.
    expect(parseXRayParams({ mode: "golden", scenario: RUN }).scenario).toBe("poisoned_bill");
    expect(xrayUrl({ scenario: RUN, mode: "mcp", viewMode: "single" })).toBe(
      `/x-ray?scenario=${RUN}&mode=mcp&view=single`,
    );
  });

  it("clears the other kind of name when the mode crosses to or from mcp [I6]", () => {
    const scenario = { scenario: "legitimate_bill", mode: "cassette", viewMode: "single" } as const;
    const entered = selectMode(scenario, "mcp");
    expect(entered).toEqual({ scenario: "", mode: "mcp", viewMode: "single" });
    expect(selectMode({ ...entered, scenario: RUN }, "cassette")).toEqual({
      scenario: "poisoned_bill",
      mode: "cassette",
      viewMode: "single",
    });
    expect(selectMode(scenario, "live")).toEqual({ ...scenario, mode: "live" });
    expect(selectMode(scenario, "cassette")).toBe(scenario);
  });

  it("settles to one lane and keeps the mode [I6]", () => {
    expect(settleSelection({ scenario: RUN, mode: "mcp", viewMode: "three-lane" })).toEqual({
      scenario: RUN,
      mode: "mcp",
      viewMode: "single",
      note: null,
    });
  });

  it("lists mcp only when the server lists it [I6]", () => {
    const names = (modes: readonly string[] | null) =>
      modeOptions("poisoned_bill", modes, "single").map((option) => option.mode);
    expect(names(null)).toEqual(["golden", "cassette", "live"]);
    expect(names(["cassette", "golden", "live"])).toEqual(["golden", "cassette", "live"]);
    expect(names(["mcp", "live", "golden", "cassette"])).toEqual([
      "golden",
      "cassette",
      "live",
      "mcp",
    ]);
    expect(names(["mcp"])).toEqual(["golden", "cassette", "live", "mcp"]);
  });

  it("explains a broken chain and an unknown run, and offers no cassette [I6]", () => {
    expect(describeStreamError(4503, "chain broken", "http://api")).toBe(CHAIN_BROKEN);
    const input = { message: "x", apiUrl: "http://api", mode: "mcp" } as const;
    expect(streamProblem({ ...input, closeCode: 4503 })).toEqual({
      text: CHAIN_BROKEN,
      offerCassette: false,
    });
    expect(streamProblem({ ...input, closeCode: 4404 })).toEqual({
      text: MCP_UNKNOWN_RUN,
      offerCassette: false,
    });
    expect(streamProblem({ ...input, closeCode: 4501 })).toEqual({
      text: MCP_NOT_ENABLED,
      offerCassette: false,
    });
    expect(streamProblem({ ...input, closeCode: 1006 }).offerCassette).toBe(false);
  });
});

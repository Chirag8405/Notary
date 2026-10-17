import { describe, expect, it } from "vitest";

import {
  DEFAULT_MODE,
  CASSETTE_LABEL,
  LIVE_LABEL,
  LIVE_UNAVAILABLE,
  MODES,
  SCENARIOS,
  effectiveMode,
  goldenBlockedReason,
  modeOptions,
  parseXRayParams,
  settleSelection,
  streamProblem,
} from "@/lib/x-ray-state";
import type { ViewMode } from "@/lib/x-ray-state";

const VIEWS: readonly ViewMode[] = ["single", "three-lane"];
const SERVER_LISTS: readonly (readonly string[] | null)[] = [
  null,
  ["cassette", "golden", "live"],
  ["live", "golden", "cassette"],
  ["golden", "cassette"],
  ["cassette"],
  ["golden"],
  [],
  ["nonsense"],
];

describe("DEFAULT_MODE", () => {
  it("is golden, and a missing or unknown mode never becomes live [I6]", () => {
    expect(DEFAULT_MODE).toBe("golden");
    expect(parseXRayParams({}).mode).toBe("golden");
    for (const raw of ["", "evil", "LIVE", "live ", "../live", undefined]) {
      expect(parseXRayParams({ mode: raw }).mode).toBe("golden");
    }
    expect(parseXRayParams({ mode: "live" }).mode).toBe("live");
  });
});

describe("modeOptions", () => {
  it("lists the modes in the fixed order, whatever order the server uses [I6]", () => {
    for (const scenario of SCENARIOS) {
      for (const viewMode of VIEWS) {
        for (const serverModes of SERVER_LISTS) {
          const options = modeOptions(scenario, serverModes, viewMode);
          const names = options.map((option) => option.mode);
          const expected =
            serverModes === null
              ? MODES
              : MODES.filter((mode) => serverModes.includes(mode)).length === 0
                ? MODES
                : MODES.filter((mode) => serverModes.includes(mode));
          expect(names, `${scenario} ${viewMode} ${String(serverModes)}`).toEqual(expected);
        }
      }
    }
  });

  it("disables golden exactly where it cannot work, with the reason [I6]", () => {
    for (const scenario of SCENARIOS) {
      for (const viewMode of VIEWS) {
        const golden = modeOptions(scenario, null, viewMode).find((o) => o.mode === "golden");
        const reason = goldenBlockedReason(scenario, viewMode);
        expect(golden?.enabled).toBe(reason === null);
        expect(golden?.note).toBe(reason);
        const works = scenario === "poisoned_bill" && viewMode === "single";
        expect(golden?.enabled).toBe(works);
      }
    }
    expect(goldenBlockedReason("legitimate_bill", "single")).toBe(
      "no recorded stream for this scenario; use cassette",
    );
    expect(goldenBlockedReason("legitimate_bill", "three-lane")).toBe(
      "no recorded stream for this scenario; use cassette",
    );
    expect(goldenBlockedReason("poisoned_bill", "three-lane")).toBe(
      "golden replays one stream for every lane; use cassette",
    );
    expect(goldenBlockedReason("poisoned_bill", "single")).toBeNull();
  });

  it("keeps cassette enabled and labels live as needing a key [I6]", () => {
    for (const scenario of SCENARIOS) {
      for (const viewMode of VIEWS) {
        for (const serverModes of SERVER_LISTS) {
          for (const option of modeOptions(scenario, serverModes, viewMode)) {
            if (option.mode === "cassette") {
              expect(option).toEqual({
                mode: "cassette",
                enabled: true,
                note: null,
                label: CASSETTE_LABEL,
              });
            }
            if (option.mode === "live") {
              expect(option).toEqual({
                mode: "live",
                enabled: true,
                note: null,
                label: LIVE_LABEL,
              });
            }
          }
        }
      }
    }
    expect(LIVE_LABEL).toBe("live (a real Groq model; needs an API key; not reproducible)");
    expect(CASSETTE_LABEL).toBe("cassette (replay of a scripted agent)");
  });

  it("shows all three modes while the list is unknown or unusable [I6]", () => {
    for (const unusable of [null, [], ["nonsense"]] as const) {
      expect(modeOptions("poisoned_bill", unusable, "single").map((o) => o.mode)).toEqual([
        "golden",
        "cassette",
        "live",
      ]);
    }
  });
});

describe("effectiveMode and settleSelection", () => {
  it("only ever turns golden into cassette, and never picks live [I6]", () => {
    for (const scenario of SCENARIOS) {
      for (const viewMode of VIEWS) {
        for (const mode of MODES) {
          const result = effectiveMode(scenario, mode, viewMode);
          if (mode === "live") expect(result).toBe("live");
          if (mode === "cassette") expect(result).toBe("cassette");
          if (mode === "golden") {
            expect(result).toBe(
              goldenBlockedReason(scenario, viewMode) === null ? "golden" : "cassette",
            );
          }
          if (mode !== "live") expect(result).not.toBe("live");
        }
      }
    }
  });

  it("makes a stale or conflicting choice consistent, and says so [I6]", () => {
    expect(
      settleSelection({ scenario: "legitimate_bill", mode: "golden", viewMode: "single" }),
    ).toEqual({
      scenario: "legitimate_bill",
      mode: "cassette",
      viewMode: "single",
      note: "Switched to cassette: no recorded stream for this scenario; use cassette",
    });
    expect(
      settleSelection({ scenario: "poisoned_bill", mode: "golden", viewMode: "three-lane" }),
    ).toEqual({
      scenario: "poisoned_bill",
      mode: "cassette",
      viewMode: "three-lane",
      note: "Switched to cassette: golden replays one stream for every lane; use cassette",
    });
    // The three-lane view needs three streams, so it falls back to the single view first.
    expect(
      settleSelection({ scenario: "legitimate_bill", mode: "cassette", viewMode: "three-lane" }),
    ).toEqual({
      scenario: "legitimate_bill",
      mode: "cassette",
      viewMode: "single",
      note: null,
    });
    expect(
      settleSelection({ scenario: "poisoned_bill", mode: "golden", viewMode: "single" }).note,
    ).toBeNull();
    expect(
      settleSelection({ scenario: "poisoned_bill", mode: "live", viewMode: "three-lane" }).mode,
    ).toBe("live");
  });

  it("is idempotent for every combination [I6]", () => {
    for (const scenario of SCENARIOS) {
      for (const viewMode of VIEWS) {
        for (const mode of MODES) {
          const once = settleSelection({ scenario, mode, viewMode });
          const twice = settleSelection(once);
          expect(twice).toEqual({ ...once, note: null });
        }
      }
    }
  });
});

describe("streamProblem", () => {
  const api = "http://localhost:8000";

  it("explains an unavailable live mode and offers cassette [I6]", () => {
    expect(streamProblem({ closeCode: 4501, message: "x", apiUrl: api, mode: "live" })).toEqual({
      text: LIVE_UNAVAILABLE,
      offerCassette: true,
    });
    expect(LIVE_UNAVAILABLE).toBe(
      "This mode is not available on the server (live needs an LLM API key).",
    );
  });

  it("keeps the generic wording for other modes and offers the way out only where it helps [I6]", () => {
    expect(streamProblem({ closeCode: 4501, message: "x", apiUrl: api, mode: "golden" })).toEqual({
      text: "This mode is not available on the server.",
      offerCassette: true,
    });
    expect(
      streamProblem({ closeCode: 4501, message: "x", apiUrl: api, mode: "cassette" }).offerCassette,
    ).toBe(false);
    expect(streamProblem({ closeCode: 4404, message: "x", apiUrl: api, mode: "golden" })).toEqual({
      text: "Unknown scenario.",
      offerCassette: false,
    });
    expect(
      streamProblem({ closeCode: 1006, message: "x", apiUrl: api, mode: "golden" }).offerCassette,
    ).toBe(false);
  });

  it("offers cassette when a live run fails for any reason [I6]", () => {
    for (const closeCode of [1006, 4400, 4502, undefined]) {
      expect(
        streamProblem({ closeCode, message: "boom", apiUrl: api, mode: "live" }).offerCassette,
      ).toBe(true);
    }
    expect(streamProblem({ closeCode: 1006, message: "x", apiUrl: api, mode: "live" }).text).toBe(
      "Could not reach the server at http://localhost:8000. Start the server and press Run again.",
    );
  });
});

import { PlaygroundHttpError } from "@notary/client";
import { describe, expect, it } from "vitest";

import {
  MODE_TITLES,
  PLAYGROUND_MODES,
  describePlaygroundError,
  parsePlaygroundParams,
  playgroundUrl,
} from "@/lib/playground-state";

const API = "http://localhost:8000";

describe("playground state", () => {
  it("parsePlaygroundParams whitelists the mode [-]", () => {
    expect(parsePlaygroundParams({ mode: "arena" })).toEqual({ mode: "arena" });
    expect(parsePlaygroundParams({ mode: "bogus" })).toEqual({ mode: "poison" });
    expect(parsePlaygroundParams({ mode: ["library", "arena"] })).toEqual({ mode: "library" });
    expect(parsePlaygroundParams({})).toEqual({ mode: "poison" });
    expect(parsePlaygroundParams({ mode: undefined })).toEqual({ mode: "poison" });
  });

  it("playgroundUrl builds the address of every mode [-]", () => {
    for (const mode of PLAYGROUND_MODES) {
      expect(playgroundUrl({ mode })).toBe(`/playground?mode=${mode}`);
    }
    expect(playgroundUrl({ mode: "hijacked" })).toBe("/playground?mode=hijacked");
  });

  it("the four titles are fixed [-]", () => {
    expect(PLAYGROUND_MODES.map((mode) => MODE_TITLES[mode])).toEqual([
      "Poison the world",
      "Be the hijacked LLM",
      "Attack library",
      "Attacker arena",
    ]);
  });

  it("describePlaygroundError says the exact strings [A3]", () => {
    const miss = new PlaygroundHttpError("POST /playground/poison", 501, "cassette miss");
    expect(describePlaygroundError(miss, API)).toBe(
      "This input has no recorded run. The playground replays recorded runs: use a sample input, or run the server in live mode.",
    );
    const rounds = new PlaygroundHttpError("POST /playground/arena", 422, "too many rounds");
    expect(describePlaygroundError(rounds, API)).toBe("too many rounds (HTTP 422)");
    expect(describePlaygroundError(new TypeError("x"), API)).toBe(
      `Cannot reach the server at ${API}. Is "pnpm dev" running?`,
    );
    expect(describePlaygroundError(new Error("boom"), API)).toBe("Unexpected error: boom");
    expect(describePlaygroundError("odd", API)).toBe("Unexpected error: odd");
  });
});

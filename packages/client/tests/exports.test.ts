import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import * as client from "../src";
import type {
  Anchor,
  CloseKind,
  RestClient,
  RunLane,
  RunMode,
  RunOptions,
  RunSession,
} from "../src";
import { useRunStream, type RunStreamResult, type RunStreamState } from "../src/react";

describe("package exports", () => {
  it("exports the new runtime names from the package index [I6]", () => {
    for (const name of [
      "openRun",
      "streamRun",
      "runStreamUrl",
      "describeClose",
      "listModes",
      "listMcpRuns",
      "getAnchor",
      "createRestClient",
      "encodeCommand",
      "parseEvent",
      "EventValidationError",
      "StreamClosedError",
      "poisonWorld",
      "listAttacks",
      "runAttack",
      "startHijacked",
      "submitHijackedCall",
      "getHijacked",
      "startArena",
      "PlaygroundHttpError",
    ] as const) {
      expect(typeof client[name], name).toBe("function");
    }
  });

  it("exports useRunStream from the react entry, which the package maps [I6]", () => {
    expect(typeof useRunStream).toBe("function");
    const manifest = JSON.parse(
      readFileSync(resolve(import.meta.dirname, "../package.json"), "utf8"),
    ) as { exports: Record<string, string> };
    expect(manifest.exports["./react"]).toBe("./src/react.ts");
  });

  it("exports the new types (checked by the compiler) [I6]", () => {
    const lane: RunLane = "notary";
    const mode: RunMode = "golden";
    const options: RunOptions = { lane, mode };
    const kind: CloseKind = client.describeClose(4404);
    const session: RunSession | null = null;
    const anchor: Anchor | null = null;
    const rest: RestClient | null = null;
    const state: RunStreamState | null = null;
    const result: RunStreamResult | null = null;
    expect([options, kind, session, anchor, rest, state, result]).toEqual([
      { lane: "notary", mode: "golden" },
      "unknown_scenario",
      null,
      null,
      null,
      null,
      null,
    ]);
  });
});

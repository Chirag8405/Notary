import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { EventSchema } from "../src/generated/zod";

// Python (notary_core) serialises these; Zod must accept every one, and reject tampering.
const fixturesDir = resolve(import.meta.dirname, "../../world/fixtures/events");
const files = readdirSync(fixturesDir).filter((name) => name.endsWith(".json"));

describe("Python -> Zod event round trip", () => {
  it("has fixtures for every event type", () => {
    const types = new Set<string>();
    for (const file of files) {
      const parsed = EventSchema.parse(
        JSON.parse(readFileSync(resolve(fixturesDir, file), "utf8")),
      );
      types.add(parsed.type);
    }
    expect([...types].sort()).toEqual([
      "call_proposed",
      "decision_made",
      "effect_executed",
      "endorsement_requested",
      "oracle_updated",
      "run_finished",
      "run_started",
      "value_labeled",
    ]);
  });

  it.each(files)("parses %s", (file) => {
    const raw: unknown = JSON.parse(readFileSync(resolve(fixturesDir, file), "utf8"));
    expect(EventSchema.safeParse(raw).success).toBe(true);
  });

  it.each(files)("rejects %s with an unknown field", (file) => {
    const raw = JSON.parse(readFileSync(resolve(fixturesDir, file), "utf8")) as Record<
      string,
      unknown
    >;
    expect(EventSchema.safeParse({ ...raw, surprise: 1 }).success).toBe(false);
  });
});

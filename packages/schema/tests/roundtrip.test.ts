import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { CommandSchema, EventSchema } from "../src/generated/zod";

// Python (notary_core / notary_world) serialises these; Zod must accept every one and reject tampering.
const fixtures = resolve(import.meta.dirname, "../../world/fixtures");
const read = (dir: string, file: string): unknown =>
  JSON.parse(readFileSync(resolve(fixtures, dir, file), "utf8"));
const streamFiles = readdirSync(resolve(fixtures, "streams")).filter((f) => f.endsWith(".json"));
const commandFiles = readdirSync(resolve(fixtures, "commands")).filter((f) => f.endsWith(".json"));

describe("Python -> Zod golden event streams", () => {
  it("covers all three lanes", () => {
    const lanes = new Set<string>();
    for (const file of streamFiles) {
      for (const event of EventSchema.array().parse(read("streams", file))) lanes.add(event.lane);
    }
    expect([...lanes].sort()).toEqual(["classifier", "notary", "undefended"]);
  });

  it("uses every event type in the notary poisoned-bill stream", () => {
    const events = EventSchema.array().parse(read("streams", "poisoned_bill.notary.json"));
    expect([...new Set(events.map((e) => e.type))].sort()).toEqual([
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

  it.each(streamFiles)("parses %s with one run id and one lane", (file) => {
    const events = EventSchema.array().parse(read("streams", file));
    expect(new Set(events.map((e) => e.run_id)).size).toBe(1);
    expect(new Set(events.map((e) => e.lane)).size).toBe(1);
    expect(events.map((e) => e.seq)).toEqual(events.map((_, i) => i));
  });

  it.each(streamFiles)("rejects every event of %s with an unknown field", (file) => {
    const raw = read("streams", file) as Record<string, unknown>[];
    for (const event of raw) {
      expect(EventSchema.safeParse({ ...event, surprise: 1 }).success).toBe(false);
    }
  });

  it("rejects an event without a lane", () => {
    const raw = read("streams", "poisoned_bill.notary.json") as Record<string, unknown>[];
    const withoutLane = Object.fromEntries(
      Object.entries(raw[0] ?? {}).filter(([key]) => key !== "lane"),
    );
    expect(EventSchema.safeParse(withoutLane).success).toBe(false);
  });
});

describe("Python -> Zod command messages", () => {
  it("has a fixture for every command type", () => {
    const types = commandFiles.map((f) => CommandSchema.parse(read("commands", f)).type).sort();
    expect(types).toEqual([
      "arena_start",
      "endorsement_decision",
      "hijacked_tool_call",
      "poison_world",
    ]);
  });

  it.each(commandFiles)("parses %s and rejects an unknown field", (file) => {
    const raw = read("commands", file) as Record<string, unknown>;
    expect(CommandSchema.safeParse(raw).success).toBe(true);
    expect(CommandSchema.safeParse({ ...raw, surprise: 1 }).success).toBe(false);
  });
});

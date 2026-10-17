import { EventSchema } from "@notary/schema";
import type { Event } from "@notary/schema";
import { foldEvents } from "@notary/ui";
import type { RunView } from "@notary/ui";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const streamsDir = resolve(import.meta.dirname, "../../../packages/world/fixtures/streams");

export const STREAMS = [
  "poisoned_bill.undefended",
  "poisoned_bill.classifier",
  "poisoned_bill.notary",
  "legitimate_bill.notary",
] as const;

export type StreamName = (typeof STREAMS)[number];

/** A golden stream, parsed fresh on each call (read only on disk). */
export function load(name: StreamName): Event[] {
  const text = readFileSync(resolve(streamsDir, `${name}.json`), "utf8");
  return EventSchema.array().parse(JSON.parse(text));
}

export function viewOf(name: StreamName): RunView {
  return foldEvents(load(name));
}

export function must<T>(value: T | null | undefined, what: string): T {
  if (value === null || value === undefined) throw new Error(`missing: ${what}`);
  return value;
}

import { readdirSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import { EventValidationError, StreamClosedError, runStreamUrl, streamRun } from "../src";

const fixtures = resolve(import.meta.dirname, "../../world/fixtures/events");
const validMessages = readdirSync(fixtures)
  .sort()
  .map((name) => readFileSync(resolve(fixtures, name), "utf8"));

/** Minimal in-memory WebSocket: replays scripted messages, then closes. */
class FakeSocket extends EventTarget {
  constructor(
    private readonly messages: string[],
    private readonly closeCode: number,
  ) {
    super();
    queueMicrotask(() => {
      for (const data of this.messages) this.dispatchEvent(new MessageEvent("message", { data }));
      this.dispatchEvent(new CloseEvent("close", { code: this.closeCode }));
    });
  }
  close(): void {
    // nothing to release in the fake
  }
}

const factory =
  (messages: string[], code = 1000) =>
  () =>
    new FakeSocket(messages, code) as unknown as WebSocket;

async function collect(messages: string[], code = 1000) {
  const out = [];
  for await (const event of streamRun("http://localhost:8000", "poisoned_bill", {
    webSocket: factory(messages, code),
  })) {
    out.push(event);
  }
  return out;
}

describe("streamRun", () => {
  it("yields validated, typed events in order", async () => {
    const events = await collect(validMessages);
    expect(events).toHaveLength(validMessages.length);
    expect(events[0]?.type).toBe("run_started");
    expect(events.at(-1)?.type).toBe("run_finished");
  });

  it("throws EventValidationError on an invalid event", async () => {
    await expect(collect([validMessages[0] ?? "", '{"type":"nope"}'])).rejects.toBeInstanceOf(
      EventValidationError,
    );
  });

  it("throws EventValidationError on non-JSON", async () => {
    await expect(collect(["not json"])).rejects.toBeInstanceOf(EventValidationError);
  });

  it("throws StreamClosedError on abnormal close", async () => {
    await expect(collect([], 4404)).rejects.toBeInstanceOf(StreamClosedError);
  });

  it("builds ws URLs from http base URLs", () => {
    expect(runStreamUrl("http://localhost:8000", "poisoned_bill")).toBe(
      "ws://localhost:8000/ws/runs/poisoned_bill",
    );
    expect(runStreamUrl("https://x.example", "a b")).toBe("wss://x.example/ws/runs/a%20b");
  });
});

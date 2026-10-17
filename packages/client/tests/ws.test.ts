import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

import {
  EventValidationError,
  StreamClosedError,
  encodeCommand,
  runStreamUrl,
  streamRun,
} from "../src";
import { describeClose } from "../src/ws";

const streams = resolve(import.meta.dirname, "../../world/fixtures/streams");
const validMessages = (
  JSON.parse(readFileSync(resolve(streams, "poisoned_bill.notary.json"), "utf8")) as unknown[]
).map((event) => JSON.stringify(event));

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

describe("encodeCommand", () => {
  it("validates with Zod and encodes JSON", () => {
    const json = encodeCommand({
      type: "endorsement_decision",
      run_id: "r",
      endorsement_id: "e",
      decision: "approve",
    });
    expect(JSON.parse(json)).toMatchObject({ type: "endorsement_decision", decision: "approve" });
  });

  it("rejects an invalid command", () => {
    expect(() =>
      encodeCommand({ type: "arena_start", scenario: "s", rounds: 0, lanes: [], seed: 1 }),
    ).toThrow();
  });
});

const TOKEN = "123e4567-e89b-12d3-a456-426614174000";

describe("runStreamUrl options", () => {
  it("keeps the old form when no options are given [I6]", () => {
    expect(runStreamUrl("http://localhost:8000", "poisoned_bill")).toBe(
      "ws://localhost:8000/ws/runs/poisoned_bill",
    );
    expect(runStreamUrl("http://localhost:8000", "poisoned_bill", {})).toBe(
      "ws://localhost:8000/ws/runs/poisoned_bill",
    );
  });

  it("adds lane, mode and token, in that order, and maps https to wss [I6]", () => {
    expect(
      runStreamUrl("http://h:8000", "poisoned_bill", {
        mode: "cassette",
        lane: "classifier",
        token: TOKEN,
      }),
    ).toBe(`ws://h:8000/ws/runs/poisoned_bill?lane=classifier&mode=cassette&token=${TOKEN}`);
    expect(runStreamUrl("https://h.example", "s", { lane: "notary", mode: "golden" })).toBe(
      "wss://h.example/ws/runs/s?lane=notary&mode=golden",
    );
    expect(runStreamUrl("http://h", "s", { mode: "live", token: TOKEN })).toBe(
      `ws://h/ws/runs/s?mode=live&token=${TOKEN}`,
    );
    expect(runStreamUrl("http://h", "s", { lane: "undefended" })).toBe(
      "ws://h/ws/runs/s?lane=undefended",
    );
  });

  it("sends no token in golden mode, or when no mode is named [I4]", () => {
    expect(runStreamUrl("http://h", "s", { mode: "golden", token: TOKEN })).toBe(
      "ws://h/ws/runs/s?mode=golden",
    );
    expect(runStreamUrl("http://h", "s", { lane: "notary", token: TOKEN })).toBe(
      "ws://h/ws/runs/s?lane=notary",
    );
  });

  it("needs a well-formed token for cassette and live, and never repeats it [I4]", () => {
    for (const mode of ["cassette", "live"] as const) {
      expect(() => runStreamUrl("http://h", "s", { mode })).toThrow(RangeError);
      for (const token of [
        "",
        "a".repeat(31),
        "a".repeat(129),
        `${"a".repeat(31)}.`,
        "a b".repeat(20),
      ]) {
        expect(() => runStreamUrl("http://h", "s", { mode, token })).toThrow(RangeError);
        try {
          runStreamUrl("http://h", "s", { mode, token });
        } catch (error) {
          expect(String(error)).not.toContain(token.trim() === "" ? "\u0000" : token);
        }
      }
      expect(runStreamUrl("http://h", "s", { mode, token: "a".repeat(32) })).toContain("token=");
      expect(runStreamUrl("http://h", "s", { mode, token: "A_-".repeat(40) })).toContain("token=");
    }
  });

  it("percent-encodes the scenario and tolerates a trailing slash [I6]", () => {
    expect(runStreamUrl("http://h:8000/", "a/b c?d", { lane: "notary" })).toBe(
      "ws://h:8000/ws/runs/a%2Fb%20c%3Fd?lane=notary",
    );
    expect(runStreamUrl("http://h:8000/", "s")).toBe("ws://h:8000/ws/runs/s");
  });

  it("rejects a lane or mode that is not one of the named ones [I6]", () => {
    const badLane = "notary&mode=live" as unknown as "notary";
    const badMode = "golden#x" as unknown as "golden";
    expect(() => runStreamUrl("http://h", "s", { lane: badLane })).toThrow(RangeError);
    expect(() => runStreamUrl("http://h", "s", { mode: badMode })).toThrow(RangeError);
    expect(() =>
      runStreamUrl("http://h", "s", { lane: "toString" as unknown as "notary" }),
    ).toThrow(RangeError);
  });
});

describe("describeClose", () => {
  it("maps every close code the server uses [I6]", () => {
    expect(describeClose(1000)).toBe("done");
    expect(describeClose(1005)).toBe("done");
    expect(describeClose(4400)).toBe("bad_request");
    expect(describeClose(4404)).toBe("unknown_scenario");
    expect(describeClose(4409)).toBe("run_conflict");
    expect(describeClose(4422)).toBe("unsupported_command");
    expect(describeClose(4501)).toBe("mode_unavailable");
    expect(describeClose(4999)).toBe("other");
    expect(describeClose(1006)).toBe("other");
  });

  it("agrees with StreamClosedError, which keeps the raw code [I6]", () => {
    const error = new StreamClosedError(4501, "mode unavailable");
    expect(error.code).toBe(4501);
    expect(describeClose(error.code)).toBe("mode_unavailable");
  });
});

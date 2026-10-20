import type { Command } from "@notary/schema";
import { describe, expect, it } from "vitest";
import { ZodError } from "zod";

import { EventValidationError, StreamClosedError, encodeCommand, streamRun } from "../src";
import { openRun } from "../src/run-session";
import { CLOSED, CONNECTING, firstSocket, flush, goldenMessages, rig } from "./fake-socket";

const BASE = "http://localhost:8000";

const approve: Command = {
  type: "endorsement_decision",
  run_id: "run-poisoned_bill-notary",
  endorsement_id: "e1",
  decision: "approve",
};

async function collect(session: ReturnType<typeof openRun>): Promise<string[]> {
  const types: string[] = [];
  for await (const event of session.events) types.push(event.type);
  return types;
}

describe("openRun events", () => {
  it("yields the validated events of a golden stream in order [A3]", async () => {
    const { factory, sockets } = rig();
    const session = openRun(BASE, "poisoned_bill", { webSocket: factory });
    const socket = firstSocket(sockets);
    socket.open();
    const messages = goldenMessages();
    for (const message of messages) socket.message(message);
    socket.finish(1000);
    const types = await collect(session);
    expect(types).toHaveLength(12);
    expect(types[0]).toBe("run_started");
    expect(types.at(-1)).toBe("run_finished");
    expect(types).toEqual(
      messages.map((message) => (JSON.parse(message) as { type: string }).type),
    );
  });

  it("opens the stream URL with the lane and mode [I6]", () => {
    const { factory, sockets } = rig();
    openRun(BASE, "poisoned_bill", { webSocket: factory, lane: "classifier", mode: "cassette" });
    expect(firstSocket(sockets).url).toBe(
      "ws://localhost:8000/ws/runs/poisoned_bill?lane=classifier&mode=cassette",
    );
  });

  it("throws EventValidationError for a bad message and closes the socket [I6]", async () => {
    const { factory, sockets } = rig();
    const session = openRun(BASE, "poisoned_bill", { webSocket: factory });
    const socket = firstSocket(sockets);
    socket.open();
    socket.message('{"type":"nope"}');
    await expect(collect(session)).rejects.toBeInstanceOf(EventValidationError);
    expect(socket.closeCalls).toBeGreaterThan(0);
  });

  it("throws StreamClosedError with the raw code on an abnormal close [I6]", async () => {
    const { factory, sockets } = rig();
    const session = openRun(BASE, "nope", { webSocket: factory });
    firstSocket(sockets).finish(4404, "unknown scenario");
    const error = await collect(session).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(StreamClosedError);
    expect((error as StreamClosedError).code).toBe(4404);
  });

  it("still behaves like streamRun did [I6]", async () => {
    const { factory, sockets } = rig();
    const seen: string[] = [];
    const run = (async () => {
      for await (const event of streamRun(BASE, "poisoned_bill", { webSocket: factory })) {
        seen.push(event.type);
      }
    })();
    await flush();
    const socket = firstSocket(sockets);
    socket.open();
    for (const message of goldenMessages()) socket.message(message);
    socket.finish(1000);
    await run;
    expect(seen).toHaveLength(12);
    expect(socket.closeCalls).toBeGreaterThan(0);
  });
});

describe("openRun send", () => {
  it("encodes and writes a valid command [I4]", () => {
    const { factory, sockets } = rig();
    const session = openRun(BASE, "poisoned_bill", { webSocket: factory });
    const socket = firstSocket(sockets);
    socket.open();
    session.send(approve);
    expect(socket.sent).toEqual([encodeCommand(approve)]);
    expect(JSON.parse(socket.sent[0] ?? "")).toEqual(approve);
  });

  it("rejects an invalid command without writing anything [I4]", () => {
    const { factory, sockets } = rig();
    const session = openRun(BASE, "poisoned_bill", { webSocket: factory });
    const socket = firstSocket(sockets);
    socket.open();
    const bad = { ...approve, decision: "maybe" } as unknown as Command;
    expect(() => {
      session.send(bad);
    }).toThrow(ZodError);
    expect(socket.sent).toEqual([]);
  });

  it("throws when the socket is closed [I4]", () => {
    const { factory, sockets } = rig();
    const session = openRun(BASE, "poisoned_bill", { webSocket: factory });
    const socket = firstSocket(sockets);
    socket.open();
    socket.finish(1000);
    expect(socket.readyState).toBe(CLOSED);
    expect(() => {
      session.send(approve);
    }).toThrow("run socket is not open");
    expect(socket.sent).toEqual([]);
  });

  it("throws while the socket is still connecting [I4]", () => {
    const { factory, sockets } = rig();
    const session = openRun(BASE, "poisoned_bill", { webSocket: factory });
    expect(firstSocket(sockets).readyState).toBe(CONNECTING);
    expect(() => {
      session.send(approve);
    }).toThrow(new Error("run socket is not open"));
  });

  it("reports the validation error first when the socket is closed too [I4]", () => {
    const { factory, sockets } = rig();
    const session = openRun(BASE, "poisoned_bill", { webSocket: factory });
    firstSocket(sockets).finish(1000);
    const bad = { type: "endorsement_decision", decision: "maybe" } as unknown as Command;
    expect(() => {
      session.send(bad);
    }).toThrow(ZodError);
  });

  it("does not filter commands the server will refuse [I4]", () => {
    const { factory, sockets } = rig();
    const session = openRun(BASE, "poisoned_bill", { webSocket: factory });
    const socket = firstSocket(sockets);
    socket.open();
    const arena: Command = {
      type: "arena_start",
      scenario: "s",
      rounds: 1,
      lanes: ["notary"],
      seed: 1,
    };
    session.send(arena);
    expect(socket.sent).toEqual([encodeCommand(arena)]);
  });
});

describe("openRun close and abort", () => {
  it("close is idempotent and ends the iterator [I6]", async () => {
    const { factory, sockets } = rig();
    const session = openRun(BASE, "poisoned_bill", { webSocket: factory });
    const socket = firstSocket(sockets);
    socket.open();
    session.close();
    session.close();
    expect(socket.closeCalls).toBe(1);
    expect(await collect(session)).toEqual([]);
    expect(socket.closeCalls).toBe(1);
  });

  it("delivers what arrived before close, then ends [I6]", async () => {
    const { factory, sockets } = rig();
    const session = openRun(BASE, "poisoned_bill", { webSocket: factory });
    const socket = firstSocket(sockets);
    socket.open();
    const [first] = goldenMessages();
    socket.message(first ?? "");
    session.close();
    expect(await collect(session)).toEqual(["run_started"]);
  });

  it("an abort closes the socket and ends the iterator [I6]", async () => {
    const { factory, sockets } = rig();
    const controller = new AbortController();
    const session = openRun(BASE, "poisoned_bill", {
      webSocket: factory,
      signal: controller.signal,
    });
    const socket = firstSocket(sockets);
    socket.open();
    const done = collect(session);
    await flush();
    controller.abort();
    expect(await done).toEqual([]);
    expect(socket.closeCalls).toBeGreaterThan(0);
  });

  it("a signal that is already aborted ends the run at once [I6]", async () => {
    const { factory, sockets } = rig();
    const session = openRun(BASE, "poisoned_bill", {
      webSocket: factory,
      signal: AbortSignal.abort(),
    });
    expect(firstSocket(sockets).closeCalls).toBe(1);
    expect(await collect(session)).toEqual([]);
  });
});

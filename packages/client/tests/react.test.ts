import type { Command } from "@notary/schema";
import { describe, expect, it, vi } from "vitest";

import type { RunLane } from "../src/ws";
import { useRunStream } from "../src/react";
import { renderHook } from "./fake-react";
import { firstSocket, flush, goldenMessages, rig, type FakeSocket } from "./fake-socket";

// The package has no DOM renderer, so `react` is replaced by a minimal stand-in (fake-react.ts).
vi.mock("react", async () => await import("./fake-react"));

const BASE = "http://localhost:8000";

const approve: Command = {
  type: "endorsement_decision",
  run_id: "run-poisoned_bill-notary",
  endorsement_id: "e1",
  decision: "approve",
};

function nthSocket(sockets: readonly FakeSocket[], index: number): FakeSocket {
  const socket = sockets[index];
  if (socket === undefined) throw new Error(`no socket #${index}`);
  return socket;
}

describe("useRunStream", () => {
  it("exposes the close code on an error [I6]", async () => {
    const { factory, sockets } = rig();
    const hook = renderHook(() => useRunStream(BASE, "nope", { webSocket: factory }));
    expect(hook.result.current.status).toBe("connecting");
    firstSocket(sockets).finish(4404, "unknown scenario");
    await flush();
    const state = hook.result.current;
    expect(state.status).toBe("error");
    expect(state.closeCode).toBe(4404);
    expect(state.status === "error" ? state.error.message : "").toContain("4404");
  });

  it("gives finished and no closeCode on a normal close, 1000 and 1005 [I6]", async () => {
    for (const code of [1000, 1005]) {
      const { factory, sockets } = rig();
      const hook = renderHook(() => useRunStream(BASE, "poisoned_bill", { webSocket: factory }));
      const socket = firstSocket(sockets);
      socket.open();
      for (const message of goldenMessages()) socket.message(message);
      socket.finish(code);
      await flush();
      const state = hook.result.current;
      expect(state.status).toBe("finished");
      expect(state.events).toHaveLength(11);
      expect("closeCode" in state).toBe(false);
    }
  });

  it("gives an error without a closeCode for an invalid event [I6]", async () => {
    const { factory, sockets } = rig();
    const hook = renderHook(() => useRunStream(BASE, "poisoned_bill", { webSocket: factory }));
    const socket = firstSocket(sockets);
    socket.open();
    socket.message('{"type":"nope"}');
    await flush();
    const state = hook.result.current;
    expect(state.status).toBe("error");
    expect(state.status === "error" ? state.error.name : "").toBe("EventValidationError");
    expect("closeCode" in state).toBe(false);
  });

  it("resets to connecting and reconnects when the lane changes [A3]", async () => {
    const { factory, sockets } = rig();
    let lane: RunLane = "notary";
    const hook = renderHook(() =>
      useRunStream(BASE, "poisoned_bill", { lane, webSocket: factory }),
    );
    const first = firstSocket(sockets);
    first.open();
    const [message] = goldenMessages();
    first.message(message ?? "");
    await flush();
    expect(hook.result.current.status).toBe("open");
    expect(hook.result.current.events).toHaveLength(1);

    lane = "classifier";
    hook.rerender();
    expect(hook.result.current.status).toBe("connecting");
    expect(hook.result.current.events).toEqual([]);
    expect(first.closeCalls).toBeGreaterThan(0);
    expect(sockets).toHaveLength(2);
    expect(nthSocket(sockets, 1).url).toBe(
      "ws://localhost:8000/ws/runs/poisoned_bill?lane=classifier",
    );

    // A late frame from the old socket must not change the new state.
    first.message(message ?? "");
    await flush();
    expect(hook.result.current.status).toBe("connecting");
    expect(hook.result.current.events).toEqual([]);
  });

  it("reconnects when the mode or the scenario changes [A3]", () => {
    const { factory, sockets } = rig();
    let props = { scenario: "poisoned_bill", mode: "golden" as const };
    const hook = renderHook(() =>
      useRunStream(BASE, props.scenario, { mode: props.mode, webSocket: factory }),
    );
    expect(sockets).toHaveLength(1);
    props = { scenario: "legitimate_bill", mode: "golden" };
    hook.rerender();
    expect(sockets).toHaveLength(2);
    expect(nthSocket(sockets, 1).url).toBe(
      "ws://localhost:8000/ws/runs/legitimate_bill?mode=golden",
    );
  });

  it("puts the tab's token on the cassette and live sockets, and none on golden [I4]", () => {
    const token = "123e4567-e89b-12d3-a456-426614174000";
    const seen: string[] = [];
    for (const mode of ["cassette", "live", "golden"] as const) {
      const { factory, sockets } = rig();
      renderHook(() => useRunStream(BASE, "poisoned_bill", { mode, token, webSocket: factory }));
      seen.push(firstSocket(sockets).url);
    }
    expect(seen).toEqual([
      `ws://localhost:8000/ws/runs/poisoned_bill?mode=cassette&token=${token}`,
      `ws://localhost:8000/ws/runs/poisoned_bill?mode=live&token=${token}`,
      "ws://localhost:8000/ws/runs/poisoned_bill?mode=golden",
    ]);
  });

  it("an equal token on a re-render keeps the socket; a missing token is an error [I4]", async () => {
    const token = "123e4567-e89b-12d3-a456-426614174000";
    const { factory, sockets } = rig();
    const hook = renderHook(() =>
      useRunStream(BASE, "poisoned_bill", {
        mode: "cassette",
        token,
        webSocket: factory,
      }),
    );
    hook.rerender();
    hook.rerender();
    expect(sockets).toHaveLength(1);

    const missing = rig();
    const bare = renderHook(() =>
      useRunStream(BASE, "poisoned_bill", { mode: "cassette", webSocket: missing.factory }),
    );
    await flush();
    expect(missing.sockets).toHaveLength(0); // never opened without a token
    expect(bare.result.current.status).toBe("error");
  });

  it("still works with the old positional factory argument [I6]", async () => {
    const { factory, sockets } = rig();
    const hook = renderHook(() => useRunStream(BASE, "poisoned_bill", factory));
    const socket = firstSocket(sockets);
    expect(socket.url).toBe("ws://localhost:8000/ws/runs/poisoned_bill");
    socket.open();
    for (const message of goldenMessages()) socket.message(message);
    socket.finish(1000);
    await flush();
    expect(hook.result.current.status).toBe("finished");
    expect(hook.result.current.events).toHaveLength(11);
    const noFactory = vi.fn(() => undefined);
    expect(noFactory).not.toHaveBeenCalled();
  });

  it("does not reconnect when the options object is new but equal [I6]", async () => {
    const { factory, sockets } = rig();
    const hook = renderHook(() =>
      useRunStream(BASE, "poisoned_bill", { lane: "notary", mode: "golden", webSocket: factory }),
    );
    hook.rerender();
    hook.rerender();
    firstSocket(sockets).open();
    firstSocket(sockets).message(goldenMessages()[0] ?? "");
    await flush();
    hook.rerender();
    expect(sockets).toHaveLength(1);
    expect(hook.result.current.events).toHaveLength(1);
    expect(hook.renders).toBeGreaterThan(3);
  });

  it("keeps send stable across renders and reconnects [I6]", () => {
    const { factory } = rig();
    let lane: RunLane = "notary";
    const hook = renderHook(() =>
      useRunStream(BASE, "poisoned_bill", { lane, webSocket: factory }),
    );
    const send = hook.result.current.send;
    hook.rerender();
    expect(hook.result.current.send).toBe(send);
    lane = "undefended";
    hook.rerender();
    expect(hook.result.current.send).toBe(send);
  });
});

describe("useRunStream send", () => {
  it("writes through the current socket once it is open [I4]", () => {
    const { factory, sockets } = rig();
    let lane: RunLane = "notary";
    const hook = renderHook(() =>
      useRunStream(BASE, "poisoned_bill", { lane, webSocket: factory }),
    );
    const send = hook.result.current.send;
    expect(() => {
      send(approve);
    }).toThrow("run socket is not open");

    const first = firstSocket(sockets);
    first.open();
    send(approve);
    expect(first.sent).toHaveLength(1);

    lane = "classifier";
    hook.rerender();
    const second = nthSocket(sockets, 1);
    expect(() => {
      send(approve);
    }).toThrow("run socket is not open");
    second.open();
    send(approve);
    expect(second.sent).toHaveLength(1);
    expect(first.sent).toHaveLength(1);
  });

  it("throws after unmount, and the unmount closes the socket [I4]", () => {
    const { factory, sockets } = rig();
    const hook = renderHook(() => useRunStream(BASE, "poisoned_bill", { webSocket: factory }));
    const socket = firstSocket(sockets);
    socket.open();
    const send = hook.result.current.send;
    hook.unmount();
    expect(socket.closeCalls).toBeGreaterThan(0);
    expect(() => {
      send(approve);
    }).toThrow("run socket is not open");
  });

  it("an invalid command throws the validation error and writes nothing [I4]", () => {
    const { factory, sockets } = rig();
    const hook = renderHook(() => useRunStream(BASE, "poisoned_bill", { webSocket: factory }));
    const socket = firstSocket(sockets);
    socket.open();
    const bad = { ...approve, decision: "maybe" } as unknown as Command;
    expect(() => {
      hook.result.current.send(bad);
    }).toThrow();
    expect(socket.sent).toEqual([]);
  });
});

describe("useRunStream signal", () => {
  it("an abort from options.signal closes the socket without an error state [I6]", async () => {
    const { factory, sockets } = rig();
    const controller = new AbortController();
    const hook = renderHook(() =>
      useRunStream(BASE, "poisoned_bill", { signal: controller.signal, webSocket: factory }),
    );
    const socket = firstSocket(sockets);
    socket.open();
    controller.abort();
    await flush();
    expect(socket.closeCalls).toBeGreaterThan(0);
    expect(hook.result.current.status).toBe("connecting");
  });
});

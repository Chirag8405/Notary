import type { WebSocketFactory } from "@notary/client";
import { vi } from "vitest";

import { STREAMS, load } from "./golden";
import type { StreamName } from "./golden";

/**
 * A stand-in for the run socket. It replays the golden stream that matches the URL it is opened
 * with (`/ws/runs/<scenario>?lane=<lane>`), records every frame sent, reports OPEN once open and
 * can be closed by the test with any code. A URL without a golden stream closes with 4404.
 */
export class FakeSocket extends EventTarget {
  readyState = 0;
  readonly sent: string[] = [];
  readonly url: string;

  constructor(url: string, options: { autoClose: boolean; ignoreLane: boolean }) {
    super();
    this.url = url;
    const parsed = new URL(url);
    const scenario = decodeURIComponent(parsed.pathname.replace("/ws/runs/", ""));
    // The server's golden mode ignores the lane parameter and always sends the NOTARY stream.
    const lane = options.ignoreLane ? "notary" : (parsed.searchParams.get("lane") ?? "notary");
    const name = `${scenario}.${lane}`;
    queueMicrotask(() => {
      const stream = STREAMS.find((item) => item === name);
      if (stream === undefined) {
        this.closeWith(4404, "unknown scenario");
        return;
      }
      this.readyState = 1;
      for (const event of load(stream satisfies StreamName)) {
        this.dispatchEvent(new MessageEvent("message", { data: JSON.stringify(event) }));
      }
      if (options.autoClose) this.closeWith(1000, "");
    });
  }

  send(data: string): void {
    this.sent.push(data);
  }

  close(): void {
    this.readyState = 3;
  }

  closeWith(code: number, reason: string): void {
    this.readyState = 3;
    this.dispatchEvent(new CloseEvent("close", { code, reason }));
  }
}

/** A socket factory that remembers every socket it opened. */
export function socketFactory(options: { autoClose?: boolean; ignoreLane?: boolean } = {}) {
  const sockets: FakeSocket[] = [];
  const factory: WebSocketFactory = (url) => {
    const socket = new FakeSocket(url, {
      autoClose: options.autoClose ?? false,
      ignoreLane: options.ignoreLane ?? false,
    });
    sockets.push(socket);
    return socket as unknown as WebSocket;
  };
  return { factory, sockets, urls: () => sockets.map((socket) => socket.url) };
}

export interface RestState {
  modes: readonly string[] | "fail";
  pending: readonly unknown[];
  anchor: { head: string; length: number } | "missing" | "fail";
}

/** Stubs `fetch` for the three REST calls the page makes; read `calls` to see what was asked. */
export function stubRest(state: RestState) {
  const calls: string[] = [];
  const respond = (status: number, body: unknown): Response =>
    new Response(JSON.stringify(body), {
      status,
      headers: { "content-type": "application/json" },
    });
  const fetchMock = vi.fn((input: Request | string | URL): Promise<Response> => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    const path = new URL(url).pathname;
    calls.push(path);
    if (path === "/runs/modes") {
      return Promise.resolve(
        state.modes === "fail" ? respond(500, {}) : respond(200, { modes: state.modes }),
      );
    }
    const endorsements = /^\/runs\/([^/]+)\/endorsements$/.exec(path);
    if (endorsements !== null) return Promise.resolve(respond(200, { pending: state.pending }));
    const anchor = /^\/runs\/([^/]+)\/anchor$/.exec(path);
    if (anchor !== null) {
      if (state.anchor === "fail") return Promise.reject(new Error("network down"));
      if (state.anchor === "missing") return Promise.resolve(respond(404, { detail: "none" }));
      return Promise.resolve(
        respond(200, { run_id: decodeURIComponent(anchor[1] ?? ""), ...state.anchor }),
      );
    }
    return Promise.resolve(respond(404, {}));
  });
  vi.stubGlobal("fetch", fetchMock);
  return { calls, fetchMock, state };
}

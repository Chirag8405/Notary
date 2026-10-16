import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import type { WebSocketFactory } from "../src";

export const CONNECTING = 0;
export const OPEN = 1;
export const CLOSING = 2;
export const CLOSED = 3;

/**
 * In-memory WebSocket for tests. Unlike the replay-only fake in ws.test.ts it has a `readyState`
 * and records what is sent, and a test drives it by hand: `open()`, `message()`, `finish()`.
 */
export class FakeSocket extends EventTarget {
  readyState: number = CONNECTING;
  readonly sent: string[] = [];
  closeCalls = 0;

  constructor(readonly url: string) {
    super();
  }

  open(): void {
    this.readyState = OPEN;
    this.dispatchEvent(new Event("open"));
  }

  message(data: string): void {
    this.dispatchEvent(new MessageEvent("message", { data }));
  }

  /** The server (or network) ends the connection. */
  finish(code = 1000, reason = ""): void {
    this.readyState = CLOSED;
    this.dispatchEvent(new CloseEvent("close", { code, reason }));
  }

  send(data: string): void {
    this.sent.push(data);
  }

  /** Like a real socket: closing starts, and the close event follows a tick later. */
  close(): void {
    this.closeCalls += 1;
    if (this.readyState === CLOSED || this.readyState === CLOSING) return;
    this.readyState = CLOSING;
    queueMicrotask(() => {
      this.finish(1005);
    });
  }
}

/** A factory that records every socket it makes, so a test can drive them. */
export function rig(): { factory: WebSocketFactory; sockets: FakeSocket[] } {
  const sockets: FakeSocket[] = [];
  const factory: WebSocketFactory = (url) => {
    const socket = new FakeSocket(url);
    sockets.push(socket);
    return socket as unknown as WebSocket;
  };
  return { factory, sockets };
}

/** The first socket the rig made (a test that needs one fails loudly if there is none). */
export function firstSocket(sockets: readonly FakeSocket[]): FakeSocket {
  const socket = sockets[0];
  if (socket === undefined) throw new Error("no socket was opened");
  return socket;
}

/** Let every queued microtask and promise continuation run (a macrotask turn drains them all). */
export async function flush(): Promise<void> {
  await new Promise<void>((resolve) => {
    setTimeout(resolve, 0);
  });
}

const streams = resolve(import.meta.dirname, "../../world/fixtures/streams");

/** The messages of a golden stream, as the server would send them (read only). */
export function goldenMessages(name = "poisoned_bill.notary"): string[] {
  const events = JSON.parse(readFileSync(resolve(streams, `${name}.json`), "utf8")) as unknown[];
  return events.map((event) => JSON.stringify(event));
}

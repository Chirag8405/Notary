import { EventSchema, type Event } from "@notary/schema";
import type { ZodError } from "zod";

/** Thrown when a WebSocket message is not a valid NOTARY `Event`. */
export class EventValidationError extends Error {
  override readonly name = "EventValidationError";
  readonly raw: string;
  readonly issues: ZodError["issues"];

  constructor(raw: string, error: ZodError) {
    super(`Invalid event received: ${error.message}`);
    this.raw = raw;
    this.issues = error.issues;
  }
}

/** Thrown when the socket closes abnormally or cannot connect. */
export class StreamClosedError extends Error {
  override readonly name = "StreamClosedError";
  readonly code: number;

  constructor(code: number, reason: string) {
    super(`WebSocket closed abnormally (${code}): ${reason}`);
    this.code = code;
  }
}

export function parseEvent(raw: string): Event {
  let json: unknown;
  try {
    json = JSON.parse(raw);
  } catch {
    json = raw;
  }
  const result = EventSchema.safeParse(json);
  if (!result.success) throw new EventValidationError(raw, result.error);
  return result.data;
}

export type WebSocketFactory = (url: string) => WebSocket;

export interface StreamOptions {
  signal?: AbortSignal;
  webSocket?: WebSocketFactory;
}

export function runStreamUrl(baseUrl: string, scenario: string): string {
  const url = new URL(`/ws/runs/${encodeURIComponent(scenario)}`, baseUrl);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  return url.toString();
}

/**
 * Stream the typed events of a run. Every message is validated with the Zod `Event` schema;
 * an invalid message makes the iterator throw `EventValidationError`.
 */
export async function* streamRun(
  baseUrl: string,
  scenario: string,
  options: StreamOptions = {},
): AsyncGenerator<Event, void, undefined> {
  const factory = options.webSocket ?? ((url: string) => new WebSocket(url));
  const socket = factory(runStreamUrl(baseUrl, scenario));

  const queue: (Event | Error | "done")[] = [];
  let wake: (() => void) | undefined;
  const push = (item: Event | Error | "done"): void => {
    queue.push(item);
    wake?.();
  };

  socket.addEventListener("message", (message: MessageEvent<unknown>) => {
    try {
      push(parseEvent(String(message.data)));
    } catch (error) {
      push(error instanceof Error ? error : new Error(String(error)));
      socket.close();
    }
  });
  socket.addEventListener("close", (closed: CloseEvent) => {
    push(
      closed.code === 1000 || closed.code === 1005
        ? "done"
        : new StreamClosedError(closed.code, closed.reason),
    );
  });
  socket.addEventListener("error", () => {
    push(new StreamClosedError(1006, "connection error"));
  });
  options.signal?.addEventListener("abort", () => {
    push("done");
    socket.close();
  });

  try {
    for (;;) {
      const next = queue.shift();
      if (next === undefined) {
        await new Promise<void>((resolve) => {
          wake = resolve;
        });
        continue;
      }
      if (next === "done") return;
      if (next instanceof Error) throw next;
      yield next;
    }
  } finally {
    socket.close();
  }
}

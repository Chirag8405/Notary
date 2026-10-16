import type { Command, Event } from "@notary/schema";

import { encodeCommand } from "./commands";
import {
  StreamClosedError,
  parseEvent,
  runStreamUrl,
  type RunOptions,
  type StreamOptions,
} from "./ws";

/** `WebSocket.OPEN`, spelled out so this file does not need a global `WebSocket`. */
const SOCKET_OPEN = 1;

/** A live run: its validated events, a way to answer the server, and a way to hang up. */
export interface RunSession {
  /**
   * The typed events of the run. Every message is validated with the Zod `Event` schema; an
   * invalid message makes the iterator throw `EventValidationError`, and an abnormal close
   * throws `StreamClosedError`. This is a generator, so it can be iterated only once.
   */
  events: AsyncIterable<Event>;
  /**
   * Send a command to the server. The command is validated first (an invalid one throws a Zod
   * error and nothing is written), then the socket must be open (otherwise this throws
   * `Error("run socket is not open")`). The server accepts only `endorsement_decision` here and
   * answers anything else with close code 4422; the client does not filter.
   */
  send(command: Command): void;
  /** Close the socket. Safe to call again; the event iterator then ends. */
  close(): void;
}

type Item = Event | Error | "done";

/**
 * Open a run's stream. The socket is created at once (so `send` works as soon as it is open) and
 * its messages are queued until `events` is iterated.
 */
export function openRun(baseUrl: string, scenario: string, options: RunOptions = {}): RunSession {
  const factory = options.webSocket ?? ((url: string) => new WebSocket(url));
  const socket = factory(runStreamUrl(baseUrl, scenario, options));

  const queue: Item[] = [];
  let wake: (() => void) | undefined;
  const push = (item: Item): void => {
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

  let closed = false;
  const close = (): void => {
    if (closed) return;
    closed = true;
    push("done");
    socket.close();
  };
  if (options.signal?.aborted === true) close();
  else options.signal?.addEventListener("abort", close);

  async function* events(): AsyncGenerator<Event, void, undefined> {
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
      close();
    }
  }

  return {
    events: events(),
    send(command: Command): void {
      const payload = encodeCommand(command);
      if (socket.readyState !== SOCKET_OPEN) throw new Error("run socket is not open");
      socket.send(payload);
    },
    close,
  };
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
  const session = openRun(baseUrl, scenario, options);
  try {
    yield* session.events;
  } finally {
    session.close();
  }
}

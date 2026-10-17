import type { Command, Event } from "@notary/schema";
import { useCallback, useEffect, useRef, useState } from "react";

import { openRun, type RunSession } from "./run-session";
import { StreamClosedError, type RunOptions, type WebSocketFactory } from "./ws";

type RunStreamBase =
  | { status: "connecting"; events: readonly Event[] }
  | { status: "open"; events: readonly Event[] }
  | { status: "finished"; events: readonly Event[] }
  | { status: "error"; events: readonly Event[]; error: Error };

/**
 * `closeCode` is present only on an error that came from a socket close (see `describeClose`);
 * an invalid event gives an error without one, and a normal end (1000, 1005) is `finished`.
 */
export type RunStreamState = RunStreamBase & { closeCode?: number };

export type RunStreamResult = RunStreamState & { send: (command: Command) => void };

type Keyed = RunStreamState & { key: string };

function toPublic(state: Keyed): RunStreamState {
  if (state.status === "error") {
    return {
      status: "error",
      events: state.events,
      error: state.error,
      ...(state.closeCode === undefined ? {} : { closeCode: state.closeCode }),
    };
  }
  return { status: state.status, events: state.events };
}

/**
 * Subscribe to a run's typed event stream; re-renders as validated events arrive.
 *
 * `send` answers the server on the current socket (the server accepts only
 * `endorsement_decision` and closes with 4422 on anything else). It is stable across renders and
 * throws `Error("run socket is not open")` until the socket is open.
 *
 * A third argument that is a function is the old positional `webSocket` factory, so existing
 * `useRunStream(baseUrl, scenario, webSocket)` calls keep working.
 *
 * Only `baseUrl`, `scenario`, `options.lane`, `options.mode` and the `webSocket` factory decide
 * when the hook reconnects; a new but equal `options` object each render does not. The
 * `options.token` (needed by the `cassette` and `live` modes) also decides it: a tab keeps one
 * token for its lifetime, and a different token is a different socket.
 */
export function useRunStream(
  baseUrl: string,
  scenario: string,
  third?: WebSocketFactory | RunOptions,
): RunStreamResult {
  const options: RunOptions = typeof third === "function" ? { webSocket: third } : (third ?? {});
  const { lane, mode, token, webSocket } = options;
  const key = `${baseUrl}|${scenario}|${lane ?? ""}|${mode ?? ""}`;
  const [keyed, setKeyed] = useState<Keyed>({ key, status: "connecting", events: [] });
  const optionsRef = useRef<RunOptions>(options);
  const sessionRef = useRef<RunSession | null>(null);

  // Runs before the effect below (same render, declaration order), so it always sees this render's
  // options without making them a dependency.
  useEffect(() => {
    optionsRef.current = options;
  });

  useEffect(() => {
    const controller = new AbortController();
    const outer = optionsRef.current.signal;
    const abortFromOuter = (): void => {
      controller.abort();
    };
    if (outer?.aborted === true) controller.abort();
    else outer?.addEventListener("abort", abortFromOuter);

    let session: RunSession | undefined;
    const update = (next: (prev: RunStreamState) => RunStreamState): void => {
      setKeyed((prev) => {
        const base: RunStreamState = prev.key === key ? prev : { status: "connecting", events: [] };
        return { ...next(base), key };
      });
    };
    void (async () => {
      try {
        session = openRun(baseUrl, scenario, {
          signal: controller.signal,
          ...(lane === undefined ? {} : { lane }),
          ...(mode === undefined ? {} : { mode }),
          ...(token === undefined ? {} : { token }),
          ...(webSocket === undefined ? {} : { webSocket }),
        });
        sessionRef.current = session;
        for await (const event of session.events) {
          if (controller.signal.aborted) return;
          update((prev) => ({ status: "open", events: [...prev.events, event] }));
        }
        if (!controller.signal.aborted) {
          update((prev) => ({ status: "finished", events: prev.events }));
        }
      } catch (error) {
        if (controller.signal.aborted) return;
        const err = error instanceof Error ? error : new Error(String(error));
        update((prev) => ({
          status: "error",
          events: prev.events,
          error: err,
          ...(error instanceof StreamClosedError ? { closeCode: error.code } : {}),
        }));
      }
    })();
    return () => {
      controller.abort();
      session?.close();
      if (sessionRef.current === session) sessionRef.current = null;
      outer?.removeEventListener("abort", abortFromOuter);
    };
  }, [baseUrl, scenario, lane, mode, token, webSocket, key]);

  const send = useCallback((command: Command): void => {
    const session = sessionRef.current;
    if (session === null) throw new Error("run socket is not open");
    session.send(command);
  }, []);

  // A state from a previous (baseUrl, scenario, lane, mode) is stale: show "connecting" instead.
  const state: RunStreamState =
    keyed.key === key ? toPublic(keyed) : { status: "connecting", events: [] };
  return { ...state, send };
}

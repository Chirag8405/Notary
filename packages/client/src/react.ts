import type { Event } from "@notary/schema";
import { useEffect, useState } from "react";

import { streamRun } from "./run-session";
import type { WebSocketFactory } from "./ws";

export type RunStreamState =
  | { status: "connecting"; events: readonly Event[] }
  | { status: "open"; events: readonly Event[] }
  | { status: "finished"; events: readonly Event[] }
  | { status: "error"; events: readonly Event[]; error: Error };

type Keyed = RunStreamState & { key: string };

/** Subscribe to a run's typed event stream; re-renders as validated events arrive. */
export function useRunStream(
  baseUrl: string,
  scenario: string,
  webSocket?: WebSocketFactory,
): RunStreamState {
  const key = `${baseUrl}|${scenario}`;
  const [keyed, setKeyed] = useState<Keyed>({ key, status: "connecting", events: [] });

  useEffect(() => {
    const controller = new AbortController();
    const update = (next: (prev: RunStreamState) => RunStreamState): void => {
      setKeyed((prev) => {
        const base: RunStreamState = prev.key === key ? prev : { status: "connecting", events: [] };
        return { ...next(base), key };
      });
    };
    void (async () => {
      try {
        for await (const event of streamRun(baseUrl, scenario, {
          signal: controller.signal,
          ...(webSocket ? { webSocket } : {}),
        })) {
          update((prev) => ({ status: "open", events: [...prev.events, event] }));
        }
        if (!controller.signal.aborted) {
          update((prev) => ({ status: "finished", events: prev.events }));
        }
      } catch (error) {
        if (controller.signal.aborted) return;
        const err = error instanceof Error ? error : new Error(String(error));
        update((prev) => ({ status: "error", events: prev.events, error: err }));
      }
    })();
    return () => {
      controller.abort();
    };
  }, [baseUrl, scenario, webSocket, key]);

  // A state from a previous (baseUrl, scenario) pair is stale: show "connecting" instead.
  return keyed.key === key ? keyed : { status: "connecting", events: [] };
}

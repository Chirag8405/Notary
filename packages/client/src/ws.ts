import { EventSchema, type Event } from "@notary/schema";
import type { ZodError } from "zod";

import type { components } from "./generated/api";

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

/** The lane of a run: both unions come from the generated types, never from a hand-written copy. */
export type RunLane = Event["lane"];
export type RunMode = components["schemas"]["ModeList"]["modes"][number];

/** Keyed by the union, so a lane or mode the schema adds fails to compile here until listed. */
const LANES: Readonly<Record<RunLane, true>> = { undefended: true, classifier: true, notary: true };
const MODES: Readonly<Record<RunMode, true>> = { golden: true, cassette: true, live: true };

export interface RunOptions {
  lane?: RunLane;
  mode?: RunMode;
  /**
   * The read token of this tab (see `getPendingEndorsements`). The `cassette` and `live` modes
   * need it (the server closes 4400 without one); `golden` sends none, so it is left out of the
   * URL there.
   */
  token?: string;
  signal?: AbortSignal;
  webSocket?: WebSocketFactory;
}

/** The run modes whose sockets own endorsement cards and so carry a read token. */
const TOKEN_MODES: Readonly<Record<RunMode, boolean>> = {
  golden: false,
  cassette: true,
  live: true,
};

/** What the server accepts as a read token: 32 to 128 characters of `[A-Za-z0-9_-]`. */
const TOKEN_FORMAT = /^[A-Za-z0-9_-]{32,128}$/;

/**
 * The stream URL of a run: `ws://host/ws/runs/<scenario>?lane=...&mode=...&token=...`. The query
 * holds only the parameters that were given, lane first and the token last. `lane`, `mode` and
 * `token` are checked at run time too, because a cast could otherwise put arbitrary text into the
 * query. The token is added for `cassette` and `live` only and is required there; the error never
 * contains it.
 */
export function runStreamUrl(
  baseUrl: string,
  scenario: string,
  options: Pick<RunOptions, "lane" | "mode" | "token"> = {},
): string {
  const { lane, mode, token } = options;
  if (lane !== undefined && !Object.hasOwn(LANES, lane)) {
    throw new RangeError(`unknown run lane: ${JSON.stringify(lane)}`);
  }
  if (mode !== undefined && !Object.hasOwn(MODES, mode)) {
    throw new RangeError(`unknown run mode: ${JSON.stringify(mode)}`);
  }
  const needsToken = mode !== undefined && TOKEN_MODES[mode];
  if (needsToken && (token === undefined || !TOKEN_FORMAT.test(token))) {
    throw new RangeError(
      `the ${mode} mode needs a read token of 32 to 128 characters [A-Za-z0-9_-]`,
    );
  }
  const url = new URL(`/ws/runs/${encodeURIComponent(scenario)}`, baseUrl);
  url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
  const query = [
    ...(lane === undefined ? [] : [`lane=${lane}`]),
    ...(mode === undefined ? [] : [`mode=${mode}`]),
    ...(needsToken && token !== undefined ? [`token=${token}`] : []),
  ].join("&");
  return query === "" ? url.toString() : `${url.toString()}?${query}`;
}

export type CloseKind =
  | "done"
  | "bad_request"
  | "unknown_scenario"
  | "run_conflict"
  | "unsupported_command"
  | "mode_unavailable"
  | "other";

/** Name the close codes the server uses: 4400, 4404, 4409, 4422 and 4501 (1000 and 1005 end a run). */
export function describeClose(code: number): CloseKind {
  switch (code) {
    case 1000:
    case 1005:
      return "done";
    case 4400:
      return "bad_request";
    case 4404:
      return "unknown_scenario";
    case 4409:
      return "run_conflict";
    case 4422:
      return "unsupported_command";
    case 4501:
      return "mode_unavailable";
    default:
      return "other";
  }
}

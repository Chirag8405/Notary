import { PlaygroundHttpError } from "@notary/client";

/**
 * Pure helpers of the /playground page: which mode is open, and what to say when a call fails.
 * No React, no I/O, no clock or randomness. The server page imports this module, so it must not
 * import the @notary/ui barrel (it holds client components).
 */

export const PLAYGROUND_MODES = ["poison", "hijacked", "library", "arena"] as const;
export type PlaygroundMode = (typeof PLAYGROUND_MODES)[number];

export const DEFAULT_PLAYGROUND_MODE: PlaygroundMode = "poison";

export const MODE_TITLES: Readonly<Record<PlaygroundMode, string>> = {
  poison: "Poison the world",
  hijacked: "Be the hijacked LLM",
  library: "Attack library",
  arena: "Attacker arena",
};

/** What each mode is for, in one plain sentence (shown above the mode's steps). */
export const MODE_INTRO: Readonly<Record<PlaygroundMode, string>> = {
  poison: "Hide an attack in an email and see which defences fall for it.",
  hijacked: "You are the attacker. Order the agent around and see what NOTARY lets through.",
  library: "Fourteen known kinds of attack, each one click away.",
  arena: "Watch an attacker try again and again against each defence.",
};

type Raw = string | string[] | undefined;

/** Whitelist the page's query: anything unknown falls back to the default. */
export function parsePlaygroundParams(raw: { mode?: Raw }): { mode: PlaygroundMode } {
  const value = Array.isArray(raw.mode) ? raw.mode[0] : raw.mode;
  return { mode: PLAYGROUND_MODES.find((item) => item === value) ?? DEFAULT_PLAYGROUND_MODE };
}

/** The address of a mode, built deterministically. */
export function playgroundUrl(state: { mode: PlaygroundMode }): string {
  return `/playground?mode=${state.mode}`;
}

export const CASSETTE_MISS_TEXT =
  "This input has no recorded run. The playground replays recorded runs: use a sample input, or run the server in live mode.";

/** The text shown for a failed playground call. */
export function describePlaygroundError(error: unknown, apiUrl: string): string {
  if (error instanceof PlaygroundHttpError) {
    if (error.status === 501 && error.detail === "cassette miss") return CASSETTE_MISS_TEXT;
    return `${error.detail} (HTTP ${error.status})`;
  }
  if (error instanceof TypeError) {
    return `Cannot reach the server at ${apiUrl}. Is "pnpm dev" running?`;
  }
  return `Unexpected error: ${error instanceof Error ? error.message : String(error)}`;
}

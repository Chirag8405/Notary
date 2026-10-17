import { describeClose } from "@notary/client";
import type { RunMode } from "@notary/client";
import type { LaneName, LaneStatus, RunView } from "@notary/ui";

/**
 * Pure helpers of the /x-ray page: what to open, what is selected, what to say. No React, no I/O,
 * no clock or randomness.
 */

// The graph's node ids ("v:<value id>", "g:<call id>"). They mirror `valueNodeId` and `gateNodeId` of
// @notary/ui, which this module cannot import at run time: the server page imports it, and the ui
// barrel holds client components. A test checks that they agree.
const valueNodeId = (valueId: string): string => `v:${valueId}`;
const gateNodeId = (callId: string): string => `g:${callId}`;

export type ViewMode = "single" | "three-lane";

export const SCENARIOS = ["poisoned_bill", "legitimate_bill"] as const;
export type Scenario = (typeof SCENARIOS)[number];

export const MODES: readonly RunMode[] = ["golden", "cassette", "live"];

/** The mode used when the address names none (or names an unknown one): never "live". */
export const DEFAULT_MODE: RunMode = "golden";

export interface XRayParams {
  scenario: Scenario;
  mode: RunMode;
  viewMode: ViewMode;
}

type Raw = string | string[] | undefined;

function first(value: Raw): string | undefined {
  return Array.isArray(value) ? value[0] : value;
}

/** The lanes of a scenario that have a recorded stream. */
export function scenarioLanes(scenario: string): readonly LaneName[] {
  return scenario === "poisoned_bill" ? ["undefended", "classifier", "notary"] : ["notary"];
}

function byText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

/** A node id for a click on a decision row (the call) or on one of its chips (the value). */
export function selectionFromChip(target: { callId: string; valueId?: string }): {
  nodeId: string | null;
  valueId: string | null;
} {
  const valueId = target.valueId === undefined || target.valueId === "" ? null : target.valueId;
  return {
    nodeId: valueId === null ? gateNodeId(target.callId) : valueNodeId(valueId),
    valueId,
  };
}

/**
 * The value the inspector shows for a selected node: the value itself, or for a gate the first
 * untrusted argument of its call (arguments by parameter name), else its first argument.
 */
export function valueIdForSelection(view: RunView, selectedId: string | null): string | null {
  if (selectedId === null) return null;
  if (selectedId.startsWith("v:")) {
    const id = selectedId.slice(2);
    return view.values.some((value) => value.ref.id === id) ? id : null;
  }
  if (selectedId.startsWith("g:")) {
    const callId = selectedId.slice(2);
    const call = view.calls.find((item) => item.callId === callId);
    if (call === undefined) return null;
    const refs = Object.keys(call.args)
      .sort(byText)
      .flatMap((param) => {
        const ref = call.args[param];
        return ref === undefined ? [] : [ref];
      });
    const untrusted = refs.find((ref) => ref.label.integrity === "untrusted");
    return (untrusted ?? refs[0])?.id ?? null;
  }
  return null;
}

/** The call a selected node belongs to: a gate's own call, or the first call using the value. */
export function callIdForSelection(view: RunView, selectedId: string | null): string | null {
  if (selectedId === null) return null;
  if (selectedId.startsWith("g:")) {
    const callId = selectedId.slice(2);
    return view.calls.some((call) => call.callId === callId) ? callId : null;
  }
  if (selectedId.startsWith("v:")) {
    const id = selectedId.slice(2);
    const ordered = [...view.calls].sort(
      (a, b) => a.proposedSeq - b.proposedSeq || byText(a.callId, b.callId),
    );
    return (
      ordered.find((call) => Object.values(call.args).some((ref) => ref.id === id))?.callId ?? null
    );
  }
  return null;
}

/** The executed effects of a run, in call order. */
export function effectsOf(
  view: RunView,
): readonly { callId: string; tool: string; summary: string }[] {
  return [...view.calls]
    .sort((a, b) => a.proposedSeq - b.proposedSeq || byText(a.callId, b.callId))
    .flatMap((call) =>
      call.executed === null
        ? []
        : [{ callId: call.callId, tool: call.tool, summary: call.executed.summary }],
    );
}

/** The sentence shown for a failed stream. */
export function describeStreamError(
  closeCode: number | undefined,
  message: string | undefined,
  apiUrl: string,
): string {
  const fallback =
    message !== undefined && message !== "" ? message : "The connection closed unexpectedly.";
  if (closeCode === undefined) return fallback;
  if (closeCode === 1006) {
    return `Could not reach the server at ${apiUrl}. Start the server and press Run again.`;
  }
  switch (describeClose(closeCode)) {
    case "unknown_scenario":
      return "Unknown scenario.";
    case "mode_unavailable":
      return "This mode is not available on the server.";
    case "bad_request":
      return "The server rejected the request.";
    case "run_conflict":
      return "This request is no longer open.";
    case "unsupported_command":
      return "The server does not accept that command.";
    case "done":
    case "other":
      return fallback;
  }
}

/** The lane status the three-lane view shows for a stream hook's status. */
export function toLaneStatus(status: "connecting" | "open" | "finished" | "error"): LaneStatus {
  switch (status) {
    case "connecting":
      return "waiting";
    case "open":
      return "running";
    case "finished":
      return "finished";
    case "error":
      return "error";
  }
}

/** Whitelist the page's query: anything unknown falls back to the default. */
export function parseXRayParams(raw: { scenario?: Raw; mode?: Raw; view?: Raw }): XRayParams {
  const scenario = first(raw.scenario);
  const mode = first(raw.mode);
  return {
    scenario: SCENARIOS.find((item) => item === scenario) ?? "poisoned_bill",
    mode: MODES.find((item) => item === mode) ?? DEFAULT_MODE,
    viewMode: first(raw.view) === "three" ? "three-lane" : "single",
  };
}

/** The address of a screen, built deterministically. */
export function xrayUrl(state: { scenario: string; mode: string; viewMode: ViewMode }): string {
  const view = state.viewMode === "three-lane" ? "three" : "single";
  return (
    `/x-ray?scenario=${encodeURIComponent(state.scenario)}` +
    `&mode=${encodeURIComponent(state.mode)}&view=${view}`
  );
}

// --- modes that can work

export interface ModeOption {
  mode: RunMode;
  enabled: boolean;
  /** Why the option is disabled; null when it is enabled. */
  note: string | null;
  label: string;
}

export const LIVE_LABEL = "live (a real Groq model; needs an API key; not reproducible)";
export const CASSETTE_LABEL = "cassette (replay of a scripted agent)";
const GOLDEN_NO_STREAM = "no recorded stream for this scenario; use cassette";
const GOLDEN_ONE_STREAM = "golden replays one stream for every lane; use cassette";

/**
 * Why golden cannot be used for this screen, or null. The server's golden source has no stream
 * for legitimate_bill (it closes with 4404) and ignores the lane, so every lane of a three-lane
 * view would get the NOTARY stream.
 */
export function goldenBlockedReason(scenario: string, viewMode: ViewMode): string | null {
  if (scenario === "legitimate_bill") return GOLDEN_NO_STREAM;
  if (viewMode === "three-lane") return GOLDEN_ONE_STREAM;
  return null;
}

/**
 * The mode selector's options in a fixed order (golden, cassette, live), whatever order the
 * server lists them in. While the list is unknown or unusable, all three are shown.
 */
export function modeOptions(
  scenario: string,
  serverModes: readonly string[] | null,
  viewMode: ViewMode,
): readonly ModeOption[] {
  const listed = serverModes === null ? MODES : MODES.filter((mode) => serverModes.includes(mode));
  const blocked = goldenBlockedReason(scenario, viewMode);
  return (listed.length === 0 ? MODES : listed).map((mode): ModeOption => {
    if (mode === "golden") return { mode, enabled: blocked === null, note: blocked, label: mode };
    if (mode === "live") return { mode, enabled: true, note: null, label: LIVE_LABEL };
    if (mode === "cassette") return { mode, enabled: true, note: null, label: CASSETTE_LABEL };
    return { mode, enabled: true, note: null, label: mode };
  });
}

/** The mode a screen actually uses: golden becomes cassette where it cannot work. Never "live". */
export function effectiveMode(scenario: string, mode: RunMode, viewMode: ViewMode): RunMode {
  return mode === "golden" && goldenBlockedReason(scenario, viewMode) !== null ? "cassette" : mode;
}

export interface Selection {
  scenario: string;
  mode: RunMode;
  viewMode: ViewMode;
}

/**
 * A choice made consistent: the three-lane view needs a scenario with three streams, and the mode
 * is the effective one. `note` says what was changed, for the screen to show.
 */
export function settleSelection(selection: Selection): Selection & { note: string | null } {
  const viewMode: ViewMode =
    scenarioLanes(selection.scenario).length < 3 ? "single" : selection.viewMode;
  const mode = effectiveMode(selection.scenario, selection.mode, viewMode);
  const reason = mode === selection.mode ? null : goldenBlockedReason(selection.scenario, viewMode);
  return {
    scenario: selection.scenario,
    mode,
    viewMode,
    note: reason === null ? null : `Switched to cassette: ${reason}`,
  };
}

export const LIVE_UNAVAILABLE =
  "This mode is not available on the server (live needs an LLM API key).";

/**
 * What to tell the user about a failed stream, and whether to offer the way out: a button that
 * switches to cassette. Offered when the server says the mode is unavailable (4501) and when a
 * live run fails for any reason; never retried automatically.
 */
export function streamProblem(input: {
  closeCode: number | undefined;
  message: string | undefined;
  apiUrl: string;
  mode: RunMode;
}): { text: string; offerCassette: boolean } {
  const text = describeStreamError(input.closeCode, input.message, input.apiUrl);
  if (input.closeCode === 4501) {
    return {
      text: input.mode === "live" ? LIVE_UNAVAILABLE : text,
      offerCassette: input.mode !== "cassette",
    };
  }
  return { text, offerCassette: input.mode === "live" };
}

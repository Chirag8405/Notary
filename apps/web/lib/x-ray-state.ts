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
    mode: MODES.find((item) => item === mode) ?? "golden",
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

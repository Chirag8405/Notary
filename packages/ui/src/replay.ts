import type { Event } from "@notary/schema";

import { foldEvents, type RunView } from "./run-view";

/**
 * Replay helpers: a position is the number of events shown, from 0 (nothing applied) to the
 * length of the run. Pure and deterministic: no React, clock, randomness or formatting.
 */

export type Step = "first" | "previous" | "next" | "last";

/** Clamp to an integer in 0..length; NaN, -Infinity and negatives give 0, +Infinity gives length. */
export function clampPosition(position: number, length: number): number {
  const top = Math.max(0, length);
  if (Number.isNaN(position)) return 0;
  return Math.min(Math.max(Math.trunc(position), 0), top);
}

export function stepPosition(position: number, length: number, step: Step): number {
  const current = clampPosition(position, length);
  switch (step) {
    case "first":
      return 0;
    case "last":
      return clampPosition(length, length);
    case "previous":
      return clampPosition(current - 1, length);
    case "next":
      return clampPosition(current + 1, length);
  }
}

/** "Event 3 of 20" (position 3, length 20); "No events" when length is 0; "Start (0 of 20)" at 0. */
export function positionLabel(position: number, length: number): string {
  if (length <= 0) return "No events";
  const shown = clampPosition(position, length);
  return shown === 0 ? `Start (0 of ${length})` : `Event ${shown} of ${length}`;
}

/** The view after the first `position` events; `position` is clamped to 0..events.length. */
export function viewAt(events: readonly Event[], position: number): RunView {
  return foldEvents(events.slice(0, clampPosition(position, events.length)));
}

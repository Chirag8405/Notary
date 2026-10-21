import type { Event } from "@notary/schema";

import { ReplayScrubber } from "./ReplayScrubber";
import { clampPosition, positionLabel, stepPosition, type Step } from "./replay";

export interface ReplayPlayerProps {
  events: readonly Event[];
  /** Controlled: the number of events shown, 0..events.length. The component keeps no state. */
  position: number;
  onPositionChange: (position: number) => void;
  /** aria-label of the group. */
  label?: string;
}

const BUTTONS: readonly { step: Step; text: string }[] = [
  { step: "first", text: "First" },
  { step: "previous", text: "Previous" },
  { step: "next", text: "Next" },
  { step: "last", text: "Last" },
];

/** Stepped replay controls; the parent folds the events with `viewAt`. No timer, no autoplay. */
export function ReplayPlayer({
  events,
  position,
  onPositionChange,
  label = "Replay",
}: ReplayPlayerProps) {
  const length = events.length;
  const current = clampPosition(position, length);
  const atStart = current === 0;
  const atEnd = current === length;
  return (
    <div role="group" aria-label={label} className="flex flex-col gap-2">
      <div className="flex items-center gap-2">
        {BUTTONS.map(({ step, text }) => {
          const backward = step === "first" || step === "previous";
          return (
            <button
              key={step}
              type="button"
              disabled={length === 0 || (backward ? atStart : atEnd)}
              onClick={() => {
                onPositionChange(stepPosition(position, length, step));
              }}
              className="rounded border border-border px-2 py-1 text-sm disabled:opacity-50"
            >
              {text}
            </button>
          );
        })}
        <span data-testid="replay-position" className="text-sm">
          {positionLabel(position, length)}
        </span>
      </div>
      <ReplayScrubber
        length={length}
        index={current}
        onChange={(index) => {
          onPositionChange(clampPosition(index, length));
        }}
      />
    </div>
  );
}

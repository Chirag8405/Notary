import type { Event } from "@notary/schema";

import { describeEvent } from "./describe-event";
import type { LightState } from "./goal-lights";
import { laneHeading, summarizeLane } from "./lane-summary";
import type { LaneInput, LaneSummary } from "./lane-summary";

/**
 * `lanes` draws the same scenario run on several lanes side by side, in the order given. `events`
 * keeps the earlier single-stream view (proposed, decided, executed) for callers that have not
 * moved to `lanes` yet.
 */
export type ThreeLaneViewProps = { lanes: readonly LaneInput[] } | { events: readonly Event[] };

type Lane = "proposed" | "decided" | "executed";

function laneOf(event: Event): Lane | null {
  switch (event.type) {
    case "call_proposed":
      return "proposed";
    case "decision_made":
    case "endorsement_requested":
      return "decided";
    case "effect_executed":
      return "executed";
    default:
      return null;
  }
}

const LANES: readonly Lane[] = ["proposed", "decided", "executed"];

export function ThreeLaneView(props: ThreeLaneViewProps) {
  if ("lanes" in props) return <SideBySide lanes={props.lanes} />;
  return <EventLanes events={props.events} />;
}

function EventLanes({ events }: { events: readonly Event[] }) {
  return (
    <div className="grid grid-cols-3 gap-4" aria-label="Three lanes">
      {LANES.map((lane) => (
        <div key={lane} data-lane={lane}>
          <h3 className="mb-1 text-xs font-semibold uppercase text-muted-foreground">{lane}</h3>
          <ul className="space-y-1 text-sm">
            {events
              .filter((event) => laneOf(event) === lane)
              .map((event) => (
                <li key={event.seq}>{describeEvent(event)}</li>
              ))}
          </ul>
        </div>
      ))}
    </div>
  );
}

interface LightText {
  glyph: string;
  label: string;
  classes: string;
}

const ATTACKER: Record<LightState, LightText> = {
  bad: { glyph: "✗", label: "Attacker goal reached", classes: "bg-red-100 text-red-900" },
  good: {
    glyph: "✓",
    label: "Attacker goal not reached",
    classes: "bg-green-100 text-green-900",
  },
  pending: {
    glyph: "–",
    label: "Attacker goal unknown",
    classes: "bg-neutral-100 text-neutral-700",
  },
};

const USER: Record<LightState, LightText> = {
  good: { glyph: "✓", label: "User goal achieved", classes: "bg-green-100 text-green-900" },
  bad: { glyph: "✗", label: "User goal not achieved", classes: "bg-red-100 text-red-900" },
  pending: {
    glyph: "–",
    label: "User goal pending",
    classes: "bg-neutral-100 text-neutral-700",
  },
};

function Light({ which, state, text }: { which: string; state: LightState; text: LightText }) {
  return (
    <li
      data-light={which}
      data-state={state}
      className={`flex items-center gap-2 rounded px-2 py-1 text-sm ${text.classes}`}
    >
      <span aria-hidden="true" className={`notary-glyph notary-glyph-${state} font-bold`}>
        {text.glyph}
      </span>
      <span>{text.label}</span>
    </li>
  );
}

function attackerMark(summary: LaneSummary): { "data-attacker"?: string } {
  if (summary.attackerGoal === "bad") return { "data-attacker": "reached" };
  if (summary.attackerGoal === "good") return { "data-attacker": "stopped" };
  return {};
}

const COUNTS = ["calls", "allowed", "escalated", "blocked", "executed"] as const;

function SideBySide({ lanes }: { lanes: readonly LaneInput[] }) {
  return (
    <div
      className="grid gap-4 md:grid-cols-3"
      aria-label="Three lanes"
      style={{ gridTemplateColumns: `repeat(${Math.max(lanes.length, 1)}, minmax(0, 1fr))` }}
    >
      {lanes.map((input) => {
        const summary = summarizeLane(input.view);
        const noCheck =
          input.status !== "waiting" &&
          summary.calls > 0 &&
          input.view.calls.every((call) => call.decision === null);
        return (
          <section
            key={input.lane}
            data-lane={input.lane}
            {...attackerMark(summary)}
            className="space-y-2 rounded border p-3 text-sm"
          >
            <h3 className="font-semibold">{laneHeading(input.lane, input.view.classifier)}</h3>
            <p>
              <span data-status={input.status} className="rounded bg-neutral-100 px-1 text-xs">
                {input.status}
              </span>
            </p>
            {input.status === "waiting" ? (
              <p className="text-muted-foreground">Waiting for the run{"…"}</p>
            ) : null}
            {input.status === "error" ? (
              <p role="alert" className="text-red-700">
                {input.error ?? "error"}
              </p>
            ) : null}
            <ul className="space-y-0.5" aria-label="Counts">
              {COUNTS.map((name) => (
                <li key={name} data-count={name}>
                  {name}: <span>{summary[name]}</span>
                  {name === "calls" && noCheck ? (
                    <span data-no-check className="ml-2 text-muted-foreground">
                      no policy check
                    </span>
                  ) : null}
                </li>
              ))}
            </ul>
            <ol className="list-decimal pl-4" aria-label="Effects">
              {summary.effects.length === 0 ? (
                <li className="list-none text-muted-foreground">No effects</li>
              ) : (
                summary.effects.map((effect, index) => <li key={`${index}:${effect}`}>{effect}</li>)
              )}
            </ol>
            <ul className="space-y-1" aria-label="Goal lights">
              <Light
                which="attacker"
                state={summary.attackerGoal}
                text={ATTACKER[summary.attackerGoal]}
              />
              <Light which="user" state={summary.userGoal} text={USER[summary.userGoal]} />
            </ul>
            {summary.outcome === null ? null : (
              <p data-outcome={summary.outcome}>
                {summary.outcome}
                {input.view.finished === null ? "" : `: ${input.view.finished.summary}`}
              </p>
            )}
          </section>
        );
      })}
    </div>
  );
}

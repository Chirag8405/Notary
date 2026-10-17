import { OracleLights } from "./OracleLights";
import { goalLights, laneLabel } from "./goal-lights";
import type { LightState } from "./goal-lights";
import type { RunView } from "./run-view";

export interface OraclePanelProps {
  view: RunView;
  /**
   * Endorsements still waiting for an answer. Defaults to every endorsement in the view: the
   * stream has no "endorsement resolved" event, so the web app will pass the locally tracked
   * count once the viewer answers cards.
   */
  unresolvedEndorsements?: number;
}

const INVARIANT_IDS: readonly string[] = ["I1", "I2", "I3", "I4", "I5", "I6"];

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

/** The bottom of the Trust X-ray: the two goal lights, the six invariants and the run outcome. */
export function OraclePanel({ view, unresolvedEndorsements }: OraclePanelProps) {
  const lights = goalLights(view.oracle, {
    finished: view.finished !== null,
    unresolvedEndorsements: unresolvedEndorsements ?? view.endorsements.length,
  });
  const failed =
    view.oracle === null
      ? []
      : INVARIANT_IDS.flatMap(
          (id) => view.oracle?.invariants.filter((item) => item.id === id && !item.passed) ?? [],
        );
  const lane = laneLabel(view.lane, view.classifier);

  return (
    <section className="space-y-2" aria-label="Oracle panel">
      <h2 className="text-sm font-semibold">
        Oracle
        {lane === "" ? null : (
          <span data-lane-label className="ml-2 font-normal text-muted-foreground">
            {lane}
          </span>
        )}
      </h2>
      <ul className="space-y-1" aria-label="Goal lights">
        <Light which="attacker" state={lights.attacker} text={ATTACKER[lights.attacker]} />
        <Light which="user" state={lights.user} text={USER[lights.user]} />
      </ul>
      <OracleLights result={view.oracle} />
      {failed.length === 0 ? null : (
        <ul className="space-y-1 text-xs text-red-800" aria-label="Failed invariants">
          {failed.map((item) => (
            <li key={item.id} data-invariant={item.id} data-state="fail">
              <span className="font-semibold">{item.id}</span> {item.detail}
            </li>
          ))}
        </ul>
      )}
      {view.finished === null ? null : (
        <p data-outcome={view.finished.outcome} className="text-sm">
          <span className="font-semibold">{view.finished.outcome}</span> {view.finished.summary}
        </p>
      )}
    </section>
  );
}

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
  /** Endorsements the user rejected: a settled, missed user goal then reads as a safe outcome. */
  rejectedEndorsements?: number;
}

const INVARIANT_IDS: readonly string[] = ["I1", "I2", "I3", "I4", "I5", "I6"];

interface LightText {
  glyph: string;
  label: string;
  classes: string;
}

const ATTACKER: Record<Exclude<LightState, "neutral">, LightText> = {
  bad: { glyph: "✗", label: "Attacker goal reached", classes: "bg-bad-soft text-bad-strong" },
  good: {
    glyph: "✓",
    label: "Attacker goal not reached",
    classes: "bg-ok-soft text-ok-strong",
  },
  pending: {
    glyph: "–",
    label: "Attacker goal unknown",
    classes: "bg-muted text-muted-foreground",
  },
};

const USER: Record<LightState, LightText> = {
  good: { glyph: "✓", label: "User goal achieved", classes: "bg-ok-soft text-ok-strong" },
  bad: { glyph: "✗", label: "User goal not achieved", classes: "bg-bad-soft text-bad-strong" },
  neutral: {
    glyph: "-",
    label: "Bill not paid: you rejected it, blocked safely",
    classes: "bg-muted text-foreground",
  },
  pending: {
    glyph: "–",
    label: "User goal pending",
    classes: "bg-muted text-muted-foreground",
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
export function OraclePanel({
  view,
  unresolvedEndorsements,
  rejectedEndorsements,
}: OraclePanelProps) {
  const lights = goalLights(view.oracle, {
    finished: view.finished !== null,
    unresolvedEndorsements: unresolvedEndorsements ?? view.endorsements.length,
    rejectedEndorsements: rejectedEndorsements ?? 0,
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
      <h2 className="text-base font-semibold">
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
        <ul className="space-y-1 text-xs text-bad-strong" aria-label="Failed invariants">
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

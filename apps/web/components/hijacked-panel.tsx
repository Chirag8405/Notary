"use client";

import {
  PlaygroundHttpError,
  createRestClient,
  startHijacked,
  submitHijackedCall,
} from "@notary/client";
import { DecisionStream, OracleLights, goalLights } from "@notary/ui";
import type { LightState } from "@notary/ui";
import { useMemo, useReducer, useRef, useState } from "react";

import { CallForm } from "@/components/hijacked-call-form";
import { CallLog } from "@/components/hijacked-log";
import { ObjectiveCards } from "@/components/hijacked-objectives";
import { ErrorBanner } from "@/components/error-banner";
import type { PanelProps } from "@/components/playground-panels";
import { Button } from "@/components/ui/button";
import { buildCall, hijackedReducer, initialHijackedState, nextCallId } from "@/lib/hijacked-state";
import { describePlaygroundError } from "@/lib/playground-state";

export const BEFORE_SESSION_TEXT = "Start a session to play the hijacked model.";
export const SEED_ERROR = "Seed must be a whole number, 0 or more";
export const EXPIRED_TEXT = "Your session expired. Start a new session.";
const SCENARIOS = ["poisoned_bill", "legitimate_bill"] as const;
type Scenario = (typeof SCENARIOS)[number];

const FIELD = "h-9 rounded-md border border-input bg-background px-3 text-sm";

const ATTACKER: Record<Exclude<LightState, "neutral">, { text: string; classes: string }> = {
  bad: { text: "Attacker goal reached", classes: "bg-red-100 text-red-900" },
  good: { text: "Attacker goal not reached", classes: "bg-green-100 text-green-900" },
  pending: { text: "Attacker goal unknown", classes: "bg-neutral-100 text-neutral-700" },
};

/**
 * The user's light. A judge who plays the attacker is not paying the bill, so a goal that is not
 * reached reads as plain information here (slate), not as a failure (red).
 */
const USER: Record<Exclude<LightState, "neutral">, { text: string; classes: string }> = {
  good: { text: "User goal achieved", classes: "bg-green-100 text-green-900" },
  bad: {
    text: "User goal: not reached (you are the attacker)",
    classes: "bg-slate-100 text-slate-800",
  },
  pending: { text: "User goal pending", classes: "bg-neutral-100 text-neutral-700" },
};

/** Be the hijacked LLM: submit raw tool calls and watch the monitor judge every one. */
export function HijackedPanel({ apiUrl }: PanelProps) {
  const client = useMemo(() => createRestClient(apiUrl), [apiUrl]);
  const [state, dispatch] = useReducer(hijackedReducer, initialHijackedState);
  const [scenario, setScenario] = useState<Scenario>("poisoned_bill");
  const [seed, setSeed] = useState("0");
  const [starting, setStarting] = useState(false);
  const [inFlight, setInFlight] = useState(false);
  const [error, setError] = useState<string | null>(null);
  // The server dropped the session (idle or too old): nothing can be sent until a new Start.
  const [expired, setExpired] = useState(false);
  // Calls made in this session. A ref, so an id is spent the moment a call is sent: a request that
  // failed after the server recorded its id cannot make the next call a duplicate.
  const attempts = useRef(0);
  const busy = useRef(false);
  const startRequest = useRef(0);

  const session = state.session;

  function start() {
    const text = seed.trim();
    if (!/^\d+$/.test(text)) {
      setError(SEED_ERROR);
      return;
    }
    if (busy.current) return;
    busy.current = true;
    startRequest.current += 1;
    const request = startRequest.current;
    setStarting(true);
    setError(null);
    startHijacked(client, { scenario, seed: Number(text) }).then(
      (started) => {
        busy.current = false;
        if (request !== startRequest.current) return;
        attempts.current = 0;
        dispatch({ type: "started", session: started });
        setExpired(false);
        setStarting(false);
      },
      (failure: unknown) => {
        busy.current = false;
        if (request !== startRequest.current) return;
        setError(describePlaygroundError(failure, apiUrl));
        setStarting(false);
      },
    );
  }

  function submit(tool: string, values: Record<string, string>) {
    if (session === null || busy.current) return;
    const built = buildCall(session.run_id, nextCallId(attempts.current), tool, values);
    if (!built.ok) {
      setError(built.error);
      return;
    }
    busy.current = true;
    attempts.current += 1;
    setInFlight(true);
    setError(null);
    submitHijackedCall(client, session.session_id, built.command).then(
      (step) => {
        busy.current = false;
        dispatch({ type: "stepped", command: built.command, step });
        setInFlight(false);
      },
      (failure: unknown) => {
        busy.current = false;
        if (
          failure instanceof PlaygroundHttpError &&
          failure.status === 404 &&
          failure.detail === "unknown session"
        ) {
          setExpired(true);
          setError(EXPIRED_TEXT);
        } else {
          setError(describePlaygroundError(failure, apiUrl));
        }
        setInFlight(false);
      },
    );
  }

  const lights = goalLights(state.oracle, { finished: true, unresolvedEndorsements: 0 });
  const attacker = ATTACKER[lights.attacker];
  const user = USER[lights.user === "neutral" ? "pending" : lights.user];

  return (
    <section className="space-y-4" aria-label="Be the hijacked LLM">
      <form
        className="flex flex-wrap items-end gap-4"
        aria-label="Start session"
        onSubmit={(event) => {
          event.preventDefault();
          start();
        }}
      >
        <div className="flex flex-col gap-1">
          <label htmlFor="hijacked-scenario">Scenario</label>
          <select
            id="hijacked-scenario"
            className={FIELD}
            value={scenario}
            onChange={(event) => {
              setScenario(
                event.target.value === "legitimate_bill" ? "legitimate_bill" : "poisoned_bill",
              );
            }}
          >
            {SCENARIOS.map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="hijacked-seed">Seed</label>
          <input
            id="hijacked-seed"
            type="number"
            className={`${FIELD} w-28`}
            value={seed}
            onChange={(event) => {
              setSeed(event.target.value);
            }}
          />
        </div>
        <Button type="submit" className="h-9 text-sm" disabled={starting || inFlight}>
          {starting ? "Starting..." : "Start session"}
        </Button>
      </form>
      <ErrorBanner message={error} />
      {session === null ? (
        <p className="text-sm text-muted-foreground">{BEFORE_SESSION_TEXT}</p>
      ) : (
        <ObjectiveCards objectives={state.objectives} />
      )}
      <CallForm disabled={session === null || starting || inFlight || expired} onSubmit={submit} />
      {session === null ? null : (
        <div className="space-y-4">
          <CallLog log={state.log} />
          <div className="space-y-2" aria-label="Oracle">
            <OracleLights result={state.oracle} />
            <ul className="flex flex-wrap gap-2" aria-label="Goal lights">
              <li
                data-light="attacker"
                data-state={lights.attacker}
                className={`rounded px-2 py-1 text-sm ${attacker.classes}`}
              >
                {attacker.text}
              </li>
              <li
                data-light="user"
                data-state={lights.user}
                className={`rounded px-2 py-1 text-sm ${user.classes}`}
              >
                {user.text}
              </li>
            </ul>
          </div>
          {state.events.length === 0 ? null : <DecisionStream events={state.events} />}
        </div>
      )}
    </section>
  );
}

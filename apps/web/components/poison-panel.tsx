"use client";

import { createRestClient, poisonWorld } from "@notary/client";
import type { PoisonResponse } from "@notary/client";
import { laneLabel } from "@notary/ui";
import { useMemo, useRef, useState } from "react";

import { ErrorBanner } from "@/components/error-banner";
import { OutcomeBanner } from "@/components/outcome-banner";
import { Disclosure } from "@/components/disclosure";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { LaneChoice } from "@/components/lane-choice";
import { StepCard } from "@/components/step-card";
import type { PanelProps } from "@/components/playground-panels";
import { RunResult } from "@/components/run-result";
import { Button } from "@/components/ui/button";
import {
  DEFAULT_FORM,
  MAX_PAYLOAD_CHARS,
  POISON_LANES,
  POISON_VECTORS,
  PRESETS,
  buildPoisonCommand,
  laneVerdictText,
} from "@/lib/poison-form";
import type { PoisonForm, PoisonLane, PoisonVector } from "@/lib/poison-form";
import { laneOutcome } from "@/lib/guided";
import { describePlaygroundError } from "@/lib/playground-state";

type Status = "idle" | "running" | "done" | "error";

export const STANDING_NOTE =
  'The server replays recorded runs. Only the sample has one; any other payload answers "no recorded run".';

const SELECT = "h-9 w-full rounded-md border border-input bg-background px-3 text-sm shadow-xs";

function isVector(value: string): value is PoisonVector {
  return POISON_VECTORS.some((vector) => vector === value);
}

/** Poison the world: plant a payload, run the chosen lanes, compare their verdicts side by side. */
export function PoisonPanel({ apiUrl }: PanelProps) {
  const client = useMemo(() => createRestClient(apiUrl), [apiUrl]);
  const [form, setForm] = useState<PoisonForm>(DEFAULT_FORM);
  const [status, setStatus] = useState<Status>("idle");
  const [response, setResponse] = useState<PoisonResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const latest = useRef(0);

  function toggleLane(lane: PoisonLane, checked: boolean) {
    setForm((current) => ({
      ...current,
      lanes: checked
        ? [...current.lanes.filter((item) => item !== lane), lane]
        : current.lanes.filter((item) => item !== lane),
    }));
  }

  function run() {
    const built = buildPoisonCommand(form);
    if (!built.ok) {
      setError(built.error);
      setStatus("error");
      return;
    }
    latest.current += 1;
    const request = latest.current;
    setStatus("running");
    setError(null);
    poisonWorld(client, built.command).then(
      (result) => {
        if (request !== latest.current) return;
        setResponse(result);
        setStatus("done");
      },
      (failure: unknown) => {
        if (request !== latest.current) return;
        setResponse(null);
        setError(describePlaygroundError(failure, apiUrl));
        setStatus("error");
      },
    );
  }

  return (
    <section className="space-y-6" aria-label="Poison the world">
      <StepCard
        step={1}
        title="Plant the attack"
        hint="Choose where the poison hides, what it says, and which defences to test."
      >
        <form
          className="space-y-5"
          onSubmit={(event) => {
            event.preventDefault();
            run();
          }}
        >
          <div className="space-y-2">
            <p className="text-sm font-medium">Start from an example</p>
            <div className="flex flex-wrap gap-2">
              {PRESETS.map((preset) => (
                <Button
                  key={preset.id}
                  type="button"
                  variant="outline"
                  className="h-9"
                  onClick={() => {
                    setForm(preset.form);
                  }}
                >
                  {preset.title}
                </Button>
              ))}
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-[12rem_minmax(0,1fr)]">
            <div className="space-y-2">
              <Label htmlFor="poison-vector">Vector</Label>
              <select
                id="poison-vector"
                className={SELECT}
                value={form.vector}
                onChange={(event) => {
                  const value = event.target.value;
                  if (isVector(value)) setForm((current) => ({ ...current, vector: value }));
                }}
              >
                {POISON_VECTORS.map((vector) => (
                  <option key={vector} value={vector}>
                    {vector}
                  </option>
                ))}
              </select>
              <p className="text-xs text-muted-foreground">Where the poison is hidden.</p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="poison-task">Task</Label>
              <Input
                id="poison-task"
                type="text"
                value={form.task}
                onChange={(event) => {
                  const value = event.target.value;
                  setForm((current) => ({ ...current, task: value }));
                }}
              />
              <p className="text-xs text-muted-foreground">What the user asks the agent to do.</p>
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="poison-payload">Payload</Label>
            <Textarea
              id="poison-payload"
              rows={3}
              value={form.payload}
              onChange={(event) => {
                const value = event.target.value;
                setForm((current) => ({ ...current, payload: value }));
              }}
            />
            <div className="flex justify-between text-xs text-muted-foreground">
              <span>The hidden text the attacker plants.</span>
              <span data-testid="payload-count">
                {form.payload.length} / {MAX_PAYLOAD_CHARS}
              </span>
            </div>
          </div>
          <fieldset className="space-y-2">
            <legend className="sr-only">Lanes</legend>
            <p aria-hidden="true" className="text-sm font-medium">
              Defences to test
            </p>
            <div className="flex flex-wrap gap-2">
              {POISON_LANES.map((lane) => (
                <LaneChoice
                  key={lane}
                  checked={form.lanes.includes(lane)}
                  onChange={(checked) => {
                    toggleLane(lane, checked);
                  }}
                >
                  {laneLabel(lane, null)}
                </LaneChoice>
              ))}
            </div>
          </fieldset>
          <div className="flex flex-wrap items-center gap-4">
            <Button type="submit" size="lg" disabled={status === "running"}>
              {status === "running" ? "Running..." : "Run"}
            </Button>
            <p className="text-xs text-muted-foreground">{STANDING_NOTE}</p>
          </div>
        </form>
        <ErrorBanner message={error} />
      </StepCard>
      <StepCard
        step={2}
        title="See what each defence did"
        hint="The same poisoned input goes to every defence you ticked."
      >
        {response === null ? (
          <p className="text-muted-foreground">Press Run to see the results.</p>
        ) : (
          <div className="space-y-4" aria-label="Poison results">
            <div className="grid items-start gap-4 lg:grid-cols-3">
              {response.runs.map((run) => (
                <div key={run.run_id} data-run-lane={run.lane} className="space-y-3">
                  <OutcomeBanner
                    compact
                    outcome={laneOutcome(run.attacker_goal_reached, run.user_goal_achieved)}
                  />
                  <details className="rounded-lg border px-3 py-2">
                    <summary className="cursor-pointer text-sm font-medium select-none">
                      Technical replay: {laneLabel(run.lane, null)}
                    </summary>
                    <div className="mt-3">
                      <RunResult title={laneLabel(run.lane, null)} events={run.events} />
                    </div>
                  </details>
                </div>
              ))}
            </div>
            <Disclosure title="Compare as a table">
              <table className="w-full max-w-md text-left text-sm" aria-label="Verdicts">
                <thead>
                  <tr>
                    <th className="pr-4">Lane</th>
                    <th>Verdict</th>
                  </tr>
                </thead>
                <tbody>
                  {response.runs.map((run) => (
                    <tr key={run.run_id} data-lane={run.lane}>
                      <th scope="row" className="pr-4 font-medium">
                        {laneLabel(run.lane, null)}
                      </th>
                      <td>{laneVerdictText(run.attacker_goal_reached, run.user_goal_achieved)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </Disclosure>
          </div>
        )}
      </StepCard>
    </section>
  );
}

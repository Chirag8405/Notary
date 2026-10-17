"use client";

import { createRestClient, poisonWorld } from "@notary/client";
import type { PoisonResponse } from "@notary/client";
import { laneLabel } from "@notary/ui";
import { useMemo, useRef, useState } from "react";

import { ErrorBanner } from "@/components/error-banner";
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
import { describePlaygroundError } from "@/lib/playground-state";

type Status = "idle" | "running" | "done" | "error";

export const STANDING_NOTE =
  'The server replays recorded runs. Only the sample has one; any other payload answers "no recorded run".';

const FIELD = "rounded-md border border-input bg-background px-3 py-2 text-sm";

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
    <section className="space-y-4" aria-label="Poison the world">
      <form
        className="space-y-3"
        onSubmit={(event) => {
          event.preventDefault();
          run();
        }}
      >
        <div className="flex flex-wrap gap-2">
          {PRESETS.map((preset) => (
            <Button
              key={preset.id}
              type="button"
              variant="outline"
              className="h-9 text-sm"
              onClick={() => {
                setForm(preset.form);
              }}
            >
              {preset.title}
            </Button>
          ))}
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="poison-vector">Vector</label>
          <select
            id="poison-vector"
            className={`${FIELD} h-9 w-fit py-0`}
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
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="poison-payload">Payload</label>
          <textarea
            id="poison-payload"
            rows={3}
            className={FIELD}
            value={form.payload}
            onChange={(event) => {
              const value = event.target.value;
              setForm((current) => ({ ...current, payload: value }));
            }}
          />
          <span data-testid="payload-count" className="text-xs text-muted-foreground">
            {form.payload.length} / {MAX_PAYLOAD_CHARS}
          </span>
        </div>
        <div className="flex flex-col gap-1">
          <label htmlFor="poison-task">Task</label>
          <input
            id="poison-task"
            type="text"
            className={FIELD}
            value={form.task}
            onChange={(event) => {
              const value = event.target.value;
              setForm((current) => ({ ...current, task: value }));
            }}
          />
        </div>
        <fieldset className="flex flex-wrap gap-4">
          <legend className="sr-only">Lanes</legend>
          {POISON_LANES.map((lane) => (
            <label key={lane} className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={form.lanes.includes(lane)}
                onChange={(event) => {
                  toggleLane(lane, event.target.checked);
                }}
              />
              {laneLabel(lane, null)}
            </label>
          ))}
        </fieldset>
        <Button type="submit" className="h-9 text-sm" disabled={status === "running"}>
          {status === "running" ? "Running..." : "Run"}
        </Button>
        <p className="text-xs text-muted-foreground">{STANDING_NOTE}</p>
      </form>
      <ErrorBanner message={error} />
      {response === null ? null : (
        <div className="space-y-4" aria-label="Poison results">
          <table className="text-left" aria-label="Verdicts">
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
          <div className="grid gap-4 lg:grid-cols-3">
            {response.runs.map((run) => (
              <div key={run.run_id} data-run-lane={run.lane}>
                <RunResult title={laneLabel(run.lane, null)} events={run.events} />
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}

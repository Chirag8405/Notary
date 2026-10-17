"use client";

import { createRestClient, startArena } from "@notary/client";
import type { ArenaResult } from "@notary/client";
import { AsrChart, laneLabel } from "@notary/ui";
import { useMemo, useRef, useState } from "react";

import { ErrorBanner } from "@/components/error-banner";
import type { PanelProps } from "@/components/playground-panels";
import { Button } from "@/components/ui/button";
import {
  ARENA_LANES,
  DEFAULT_ARENA_FORM,
  buildArenaCommand,
  chartSeries,
  roundText,
  totalsText,
} from "@/lib/arena-form";
import type { ArenaForm, ArenaLaneName } from "@/lib/arena-form";
import { describePlaygroundError } from "@/lib/playground-state";

export const ARENA_NOTE =
  'The attacker is replayed from a recording: seed 0 on the poisoned bill. Other seeds answer "no recorded run".';

const FIELD = "h-9 w-28 rounded-md border border-input bg-background px-3 text-sm";

/** Attacker arena: an LLM attacker plays N rounds per lane; the panel plots ASR per round. */
export function ArenaPanel({ apiUrl }: PanelProps) {
  const client = useMemo(() => createRestClient(apiUrl), [apiUrl]);
  const [form, setForm] = useState<ArenaForm>(DEFAULT_ARENA_FORM);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<ArenaResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const latest = useRef(0);

  function toggleLane(lane: ArenaLaneName, checked: boolean) {
    setForm((current) => ({
      ...current,
      lanes: checked
        ? [...current.lanes.filter((item) => item !== lane), lane]
        : current.lanes.filter((item) => item !== lane),
    }));
  }

  function run() {
    const built = buildArenaCommand(form);
    if (!built.ok) {
      setError(built.error);
      return;
    }
    latest.current += 1;
    const request = latest.current;
    setRunning(true);
    setError(null);
    startArena(client, built.command).then(
      (answer) => {
        if (request !== latest.current) return;
        setResult(answer);
        setRunning(false);
      },
      (failure: unknown) => {
        if (request !== latest.current) return;
        setResult(null);
        setError(describePlaygroundError(failure, apiUrl));
        setRunning(false);
      },
    );
  }

  return (
    <section className="space-y-4" aria-label="Attacker arena">
      <form
        className="space-y-3"
        onSubmit={(event) => {
          event.preventDefault();
          run();
        }}
      >
        <div className="flex flex-wrap gap-4">
          <div className="flex flex-col gap-1">
            <label htmlFor="arena-rounds">Rounds</label>
            <input
              id="arena-rounds"
              type="number"
              className={FIELD}
              value={form.rounds}
              onChange={(event) => {
                const value = event.target.value;
                setForm((current) => ({ ...current, rounds: value }));
              }}
            />
          </div>
          <div className="flex flex-col gap-1">
            <label htmlFor="arena-seed">Seed</label>
            <input
              id="arena-seed"
              type="number"
              className={FIELD}
              value={form.seed}
              onChange={(event) => {
                const value = event.target.value;
                setForm((current) => ({ ...current, seed: value }));
              }}
            />
          </div>
        </div>
        <fieldset className="flex flex-wrap gap-4">
          <legend className="sr-only">Lanes</legend>
          {ARENA_LANES.map((lane) => (
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
        <Button type="submit" className="h-9 text-sm" disabled={running}>
          {running ? "Running..." : "Run arena"}
        </Button>
        <p className="text-xs text-muted-foreground">{ARENA_NOTE}</p>
      </form>
      <ErrorBanner message={error} />
      {result === null ? null : (
        <div className="space-y-4" aria-label="Arena results">
          <AsrChart series={chartSeries(result.lanes)} title="Attack success rate per round" />
          <div className="space-y-1" aria-label="Totals">
            {result.lanes.map((lane) => (
              <p key={lane.lane} data-lane-total={lane.lane}>
                {totalsText(lane)}
              </p>
            ))}
          </div>
          <div className="grid gap-4 lg:grid-cols-3">
            {result.lanes.map((lane) => (
              <table key={lane.lane} data-lane-table={lane.lane} className="text-left">
                <caption className="text-left font-semibold">{laneLabel(lane.lane, null)}</caption>
                <tbody>
                  {lane.rounds.map((round) => (
                    <tr key={round.round}>
                      <td>{roundText(round)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}

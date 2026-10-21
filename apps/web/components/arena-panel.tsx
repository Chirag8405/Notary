"use client";

import { createRestClient, startArena } from "@notary/client";
import type { ArenaResult } from "@notary/client";
import { AsrChart, laneLabel } from "@notary/ui";
import { useMemo, useRef, useState } from "react";

import { ErrorBanner } from "@/components/error-banner";
import { LaneChoice } from "@/components/lane-choice";
import { StepCard } from "@/components/step-card";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Disclosure } from "@/components/disclosure";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import type { PanelProps } from "@/components/playground-panels";
import { Button } from "@/components/ui/button";
import {
  ARENA_LANES,
  DEFAULT_ARENA_FORM,
  buildArenaCommand,
  chartSeries,
  laneTotals,
  roundText,
  totalsText,
} from "@/lib/arena-form";
import type { ArenaForm, ArenaLaneName } from "@/lib/arena-form";
import { describePlaygroundError } from "@/lib/playground-state";

export const ARENA_NOTE =
  'The attacker is replayed from a recording: seed 0 on the poisoned bill. Other seeds answer "no recorded run".';

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
    <section className="space-y-6" aria-label="Attacker arena">
      <StepCard
        step={1}
        title="Set up the contest"
        hint="Choose how many rounds the attacker gets, and which defences it faces."
      >
        <form
          className="space-y-5"
          onSubmit={(event) => {
            event.preventDefault();
            run();
          }}
        >
          <div className="max-w-xs">
            <div className="space-y-2">
              <Label htmlFor="arena-rounds">Rounds</Label>
              <Input
                id="arena-rounds"
                type="number"
                value={form.rounds}
                onChange={(event) => {
                  const value = event.target.value;
                  setForm((current) => ({ ...current, rounds: value }));
                }}
              />
              <p className="text-xs text-muted-foreground">How many tries the attacker gets.</p>
            </div>
          </div>
          <fieldset className="space-y-2">
            <legend className="sr-only">Lanes</legend>
            <p aria-hidden="true" className="text-sm font-medium">
              Defences to attack
            </p>
            <div className="flex flex-wrap gap-2">
              {ARENA_LANES.map((lane) => (
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
          <Disclosure title="More options" hint="seed">
            <div className="space-y-2">
              <Label htmlFor="arena-seed">Seed</Label>
              <Input
                id="arena-seed"
                type="number"
                value={form.seed}
                onChange={(event) => {
                  const value = event.target.value;
                  setForm((current) => ({ ...current, seed: value }));
                }}
              />
              <p className="text-xs text-muted-foreground">Picks the attacker recording.</p>
            </div>
          </Disclosure>
          <div className="flex flex-wrap items-center gap-4">
            <Button type="submit" size="lg" disabled={running}>
              {running ? "Running..." : "Run arena"}
            </Button>
            <p className="text-xs text-muted-foreground">{ARENA_NOTE}</p>
          </div>
        </form>
        <ErrorBanner message={error} />
      </StepCard>
      <StepCard
        step={2}
        title="Read the chart"
        hint="The share of attacks that worked in each round. Lower is safer."
      >
        {result === null ? (
          <p className="text-muted-foreground">Press Run arena to see the chart.</p>
        ) : (
          <div className="space-y-4" aria-label="Arena results">
            <div className="mx-auto max-w-3xl [&_svg]:mx-auto [&_svg]:max-h-72">
              <AsrChart series={chartSeries(result.lanes)} title="Attack success rate per round" />
            </div>
            <div className="grid gap-4 md:grid-cols-3" aria-label="Totals">
              {result.lanes.map((lane) => {
                const totals = laneTotals(lane);
                const percent = totals.rounds === 0 ? 0 : (totals.successes / totals.rounds) * 100;
                return (
                  <Card key={lane.lane}>
                    <CardHeader>
                      <CardTitle>{laneLabel(lane.lane, null)}</CardTitle>
                      <CardDescription>
                        <span data-lane-total={lane.lane}>{totalsText(lane)}</span>
                      </CardDescription>
                    </CardHeader>
                    <CardContent className="space-y-3">
                      <Progress
                        value={percent}
                        aria-label={`${laneLabel(lane.lane, null)} attack success`}
                      />
                      <p className="text-sm font-medium">
                        {percent === 0
                          ? "The attacker never got through."
                          : `${Math.round(percent)}% of attacks worked.`}
                      </p>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
            <details className="rounded-lg border px-3 py-2">
              <summary className="cursor-pointer text-sm font-medium select-none">
                Round by round
              </summary>
              <div className="mt-3 grid gap-4 lg:grid-cols-3">
                {result.lanes.map((lane) => (
                  <table key={lane.lane} data-lane-table={lane.lane} className="text-left text-sm">
                    <caption className="text-left font-semibold">
                      {laneLabel(lane.lane, null)}
                    </caption>
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
            </details>
          </div>
        )}
      </StepCard>
    </section>
  );
}

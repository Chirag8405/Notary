"use client";

import { createRestClient, listAttacks, runAttack } from "@notary/client";
import type { AttackCase, AttackRunResponse } from "@notary/client";
import { OracleLights } from "@notary/ui";
import { useEffect, useMemo, useRef, useState } from "react";

import { ErrorBanner } from "@/components/error-banner";
import { StepCard } from "@/components/step-card";
import type { PanelProps } from "@/components/playground-panels";
import { RunResult } from "@/components/run-result";
import { Button } from "@/components/ui/button";
import {
  BADGE_TEXT,
  CONTROL_IDS,
  DEFERRED_TEXT,
  PRIMARY_STOPS,
  checkRows,
  compareAttacks,
  describeOutcome,
  plainOutcome,
  runBadge,
} from "@/lib/attack-library";
import { describePlaygroundError } from "@/lib/playground-state";

const BADGE_TONE = {
  matches: "border-ok bg-ok-soft text-ok-strong",
  mismatch: "border-bad bg-bad-soft text-bad-strong",
  deferred: "border-border bg-muted text-muted-foreground",
} as const;

type ListState =
  | { status: "loading" }
  | { status: "error"; message: string }
  | { status: "loaded"; attacks: readonly AttackCase[] };

/** Attack library: one click per class A1-A14 and the benign controls B1-B4. */
export function AttackLibraryPanel({ apiUrl }: PanelProps) {
  const client = useMemo(() => createRestClient(apiUrl), [apiUrl]);
  const [list, setList] = useState<ListState>({ status: "loading" });
  const [attempt, setAttempt] = useState(0);
  const [running, setRunning] = useState<readonly string[]>([]);
  const [run, setRun] = useState<AttackRunResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const latest = useRef(0);

  useEffect(() => {
    let cancelled = false;
    listAttacks(client).then(
      (attacks) => {
        if (!cancelled) setList({ status: "loaded", attacks: [...attacks].sort(compareAttacks) });
      },
      (failure: unknown) => {
        if (!cancelled)
          setList({ status: "error", message: describePlaygroundError(failure, apiUrl) });
      },
    );
    return () => {
      cancelled = true;
    };
  }, [client, apiUrl, attempt]);

  function start(id: string) {
    latest.current += 1;
    const request = latest.current;
    setRunning((current) => [...current, id]);
    setError(null);
    const finish = () => {
      setRunning((current) => current.filter((item) => item !== id));
    };
    runAttack(client, id).then(
      (result) => {
        finish();
        if (request !== latest.current) return;
        setRun(result);
      },
      (failure: unknown) => {
        finish();
        if (request !== latest.current) return;
        setRun(null);
        setError(describePlaygroundError(failure, apiUrl));
      },
    );
  }

  function runButton(id: string, label: string) {
    const busy = running.includes(id);
    return (
      <Button
        type="button"
        variant="outline"
        className="h-8 text-sm"
        disabled={busy}
        aria-describedby={`attack-${id}-title`}
        onClick={() => {
          start(id);
        }}
      >
        {busy ? "Running..." : label}
      </Button>
    );
  }

  return (
    <section className="space-y-6" aria-label="Attack library">
      <StepCard
        step={1}
        title="Pick an attack"
        hint="Each card is a known kind of attack. Press Run to fire it at the real monitor."
      >
        {list.status === "loading" ? <p>Loading attacks...</p> : null}
        {list.status === "error" ? (
          <div className="space-y-2">
            <ErrorBanner message={list.message} />
            <Button
              type="button"
              variant="outline"
              className="h-8 text-sm"
              onClick={() => {
                setList({ status: "loading" });
                setAttempt((current) => current + 1);
              }}
            >
              Retry
            </Button>
          </div>
        ) : null}
        {list.status === "loaded" ? (
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3" aria-label="Attack classes">
            {list.attacks.map((attack) => (
              <article
                key={attack.id}
                data-attack={attack.id}
                className="flex flex-col gap-2 rounded-lg border bg-card p-4"
              >
                <h3 id={`attack-${attack.id}-title`} className="text-base font-semibold">
                  <span className="mr-2">{attack.id}</span>
                  {attack.title}
                </h3>
                <p className="text-sm">{plainOutcome(attack.expected)}</p>
                <details className="text-xs text-muted-foreground">
                  <summary className="cursor-pointer font-medium select-none">Why it stops</summary>
                  <p className="mt-1">Primary stop: {PRIMARY_STOPS[attack.id]}</p>
                  <p className="mt-1">Expected: {describeOutcome(attack.expected)}</p>
                </details>
                <div className="mt-auto pt-2">{runButton(attack.id, "Run")}</div>
              </article>
            ))}
          </div>
        ) : null}
        <section className="space-y-2" aria-label="Benign controls">
          <h3 className="text-base font-semibold">Benign controls</h3>
          <p className="text-sm text-muted-foreground">
            Harmless actions. They must still go through, or the defence is just blocking
            everything.
          </p>
          <div className="flex flex-wrap gap-2">
            {CONTROL_IDS.map((id) => (
              <span key={id}>{runButton(id, id)}</span>
            ))}
          </div>
        </section>
        <ErrorBanner message={error} />
      </StepCard>
      <StepCard
        step={2}
        title="Read the result"
        hint="Did the monitor decide what the taxonomy expects?"
      >
        {run === null ? (
          <p className="text-muted-foreground">Run an attack above to see the result here.</p>
        ) : (
          <section className="space-y-4" aria-label="Attack result">
            <h2
              data-result-heading
              className="text-base font-semibold"
            >{`${run.attack_id} ${run.name}`}</h2>
            <div className="flex flex-wrap items-center gap-4">
              <p
                data-badge={runBadge(run)}
                className={`rounded-md border px-3 py-1 font-medium ${BADGE_TONE[runBadge(run)]}`}
              >
                {BADGE_TEXT[runBadge(run)]}
              </p>
              <div data-testid="response-oracle">
                <OracleLights result={run.oracle} />
              </div>
            </div>
            {run.deferred ? <p>{DEFERRED_TEXT}</p> : null}
            <table className="w-full text-left text-sm" aria-label="Checks">
              <thead>
                <tr>
                  <th className="pr-4">Call</th>
                  <th className="pr-4">Tool</th>
                  <th className="pr-4">Expected</th>
                  <th className="pr-4">Actual</th>
                  <th>Match</th>
                </tr>
              </thead>
              <tbody>
                {checkRows(run.checks).map((row) => (
                  <tr key={row.callId}>
                    <td className="pr-4">{row.callId}</td>
                    <td className="pr-4">{row.tool}</td>
                    <td className="pr-4">{row.expected}</td>
                    <td className="pr-4">{row.actual}</td>
                    <td>{row.matches ? "yes" : "NO"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <details className="rounded-lg border px-3 py-2">
              <summary className="cursor-pointer text-sm font-medium select-none">
                Technical replay
              </summary>
              <div className="mt-3">
                <RunResult title="Recorded run" events={run.events} />
              </div>
            </details>
          </section>
        )}
      </StepCard>
    </section>
  );
}

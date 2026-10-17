"use client";

import { createRestClient, listAttacks, runAttack } from "@notary/client";
import type { AttackCase, AttackRunResponse } from "@notary/client";
import { OracleLights } from "@notary/ui";
import { useEffect, useMemo, useRef, useState } from "react";

import { ErrorBanner } from "@/components/error-banner";
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
  runBadge,
} from "@/lib/attack-library";
import { describePlaygroundError } from "@/lib/playground-state";

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
    <section className="space-y-4" aria-label="Attack library">
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
              className="space-y-2 rounded-md border p-3"
            >
              <h3 id={`attack-${attack.id}-title`} className="text-sm font-semibold">
                <span className="mr-2">{attack.id}</span>
                {attack.title}
              </h3>
              <p className="text-xs text-muted-foreground">
                Primary stop: {PRIMARY_STOPS[attack.id]}
              </p>
              <p className="text-xs">Expected: {describeOutcome(attack.expected)}</p>
              {runButton(attack.id, "Run")}
            </article>
          ))}
        </div>
      ) : null}
      <section className="space-y-2" aria-label="Benign controls">
        <h3 className="text-sm font-semibold">Benign controls</h3>
        <div className="flex flex-wrap gap-2">
          {CONTROL_IDS.map((id) => (
            <span key={id}>{runButton(id, id)}</span>
          ))}
        </div>
      </section>
      <ErrorBanner message={error} />
      {run === null ? null : (
        <section className="space-y-4" aria-label="Attack result">
          <h2
            data-result-heading
            className="text-base font-semibold"
          >{`${run.attack_id} ${run.name}`}</h2>
          <div className="flex flex-wrap items-center gap-4">
            <p data-badge={runBadge(run)} className="font-medium">
              {BADGE_TEXT[runBadge(run)]}
            </p>
            <div data-testid="response-oracle">
              <OracleLights result={run.oracle} />
            </div>
          </div>
          {run.deferred ? <p>{DEFERRED_TEXT}</p> : null}
          <table className="text-left" aria-label="Checks">
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
          <RunResult title="Recorded run" events={run.events} />
        </section>
      )}
    </section>
  );
}

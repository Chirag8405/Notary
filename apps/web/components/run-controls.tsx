"use client";

import { createRestClient, listModes } from "@notary/client";
import type { RunMode } from "@notary/client";
import { useEffect, useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { MODES, SCENARIOS, scenarioLanes } from "@/lib/x-ray-state";
import type { ViewMode } from "@/lib/x-ray-state";

export interface RunControlsProps {
  apiUrl: string;
  scenario: string;
  mode: RunMode;
  viewMode: ViewMode;
  onScenarioChange: (scenario: string) => void;
  onModeChange: (mode: RunMode) => void;
  onViewModeChange: (viewMode: ViewMode) => void;
  onRunAgain: () => void;
}

/** Scenario, mode and view selection plus "Run again". Keeps no state beyond the mode list. */
export function RunControls({
  apiUrl,
  scenario,
  mode,
  viewMode,
  onScenarioChange,
  onModeChange,
  onViewModeChange,
  onRunAgain,
}: RunControlsProps) {
  const client = useMemo(() => createRestClient(apiUrl), [apiUrl]);
  const [offered, setOffered] = useState<readonly string[] | null>(null);

  useEffect(() => {
    let cancelled = false;
    listModes(client).then(
      (modes) => {
        if (!cancelled) setOffered(modes);
      },
      () => {
        if (!cancelled) setOffered(null);
      },
    );
    return () => {
      cancelled = true;
    };
  }, [client]);

  // While the list is loading, or when it cannot be read, only "golden" is offered (plus the
  // mode that is already selected, so the select never shows a value it cannot list).
  const known = offered === null ? ["golden"] : MODES.filter((item) => offered.includes(item));
  const options = MODES.filter((item) => known.includes(item) || item === mode);
  const threeLaneAvailable = scenarioLanes(scenario).length >= 3;

  return (
    <div
      role="group"
      aria-label="Run controls"
      className="flex flex-wrap items-center gap-3 text-sm"
    >
      <label className="flex items-center gap-1">
        Scenario
        <select
          value={scenario}
          onChange={(event) => {
            onScenarioChange(event.target.value);
          }}
          className="border px-1"
        >
          {SCENARIOS.map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
      </label>
      <label className="flex items-center gap-1">
        Mode
        <select
          value={mode}
          onChange={(event) => {
            const next = MODES.find((item) => item === event.target.value);
            if (next !== undefined) onModeChange(next);
          }}
          className="border px-1"
        >
          {options.map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
      </label>
      {mode === "live" ? (
        <span className="text-xs text-amber-800">live runs are not reproducible</span>
      ) : null}
      <Button
        type="button"
        variant="outline"
        aria-pressed={viewMode === "three-lane"}
        disabled={!threeLaneAvailable}
        onClick={() => {
          onViewModeChange(viewMode === "three-lane" ? "single" : "three-lane");
        }}
      >
        Three-lane view
      </Button>
      {threeLaneAvailable ? null : (
        <span className="text-xs text-neutral-600">
          only the NOTARY lane has a recorded stream for this scenario
        </span>
      )}
      <Button type="button" onClick={onRunAgain}>
        Run again
      </Button>
    </div>
  );
}

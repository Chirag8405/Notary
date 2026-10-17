"use client";

import { createRestClient, listModes } from "@notary/client";
import type { RunMode } from "@notary/client";
import Link from "next/link";
import { useEffect, useMemo, useState } from "react";

import { Button } from "@/components/ui/button";
import { MODES, SCENARIOS, modeOptions, scenarioLanes } from "@/lib/x-ray-state";
import type { ModeOption, ViewMode } from "@/lib/x-ray-state";

export interface RunControlsProps {
  apiUrl: string;
  scenario: string;
  /** The mode the streams actually use. */
  mode: RunMode;
  viewMode: ViewMode;
  /** Said once when the page changed a choice that cannot work (for example golden to cassette). */
  note?: string | null;
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
  note,
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

  // The select is controlled by the mode the sockets use, and always lists that mode, even when
  // the server's list does not.
  const listed = modeOptions(scenario, offered, viewMode);
  const shown: readonly ModeOption[] = listed.some((option) => option.mode === mode)
    ? listed
    : [...listed, { mode, enabled: true, note: null, label: mode }];
  const disabledNotes = shown.flatMap((option) =>
    option.enabled || option.note === null ? [] : [`${option.mode} is off: ${option.note}`],
  );
  const threeLaneAvailable = scenarioLanes(scenario).length >= 3;

  return (
    <div
      role="group"
      aria-label="Run controls"
      className="flex flex-wrap items-center gap-3 text-sm"
    >
      <label className="flex items-center gap-2">
        Scenario
        <select
          value={scenario}
          onChange={(event) => {
            onScenarioChange(event.target.value);
          }}
          className="h-8 rounded-none border border-input bg-background px-2.5 text-sm"
        >
          {SCENARIOS.map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
      </label>
      <label className="flex items-center gap-2">
        Mode
        <select
          value={mode}
          onChange={(event) => {
            const next = MODES.find((item) => item === event.target.value);
            if (next !== undefined) onModeChange(next);
          }}
          className="h-8 rounded-none border border-input bg-background px-2.5 text-sm"
        >
          {shown.map((option) => (
            <option key={option.mode} value={option.mode} disabled={!option.enabled}>
              {option.label}
            </option>
          ))}
        </select>
      </label>
      {disabledNotes.map((text) => (
        <span key={text} data-mode-note className="text-xs text-muted-foreground">
          {text}
        </span>
      ))}
      {mode === "live" ? (
        <span className="text-xs text-muted-foreground">live runs are not reproducible</span>
      ) : null}
      {note === undefined || note === null ? null : (
        <span data-switch-note role="status" className="text-xs text-muted-foreground">
          {note}
        </span>
      )}
      <Button
        type="button"
        variant="outline"
        className="text-sm"
        aria-pressed={viewMode === "three-lane"}
        onClick={() => {
          onViewModeChange(viewMode === "three-lane" ? "single" : "three-lane");
        }}
        disabled={!threeLaneAvailable}
      >
        Three-lane view
      </Button>
      {threeLaneAvailable ? null : (
        <span className="text-xs text-muted-foreground">
          only the NOTARY lane has a recorded stream for this scenario
        </span>
      )}
      <Button type="button" className="text-sm" onClick={onRunAgain}>
        Run again
      </Button>
      <Link href="/playground" className="text-sm underline">
        Judge playground
      </Link>
    </div>
  );
}

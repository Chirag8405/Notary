"use client";

import { createRestClient, listModes } from "@notary/client";
import type { RunMode } from "@notary/client";
import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";

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
  /** The demo step buttons, shown in the row of "Run again". */
  steps?: ReactNode;
  /** What the active step is about, shown under that row. */
  guide?: ReactNode;
  /** Whether "Advanced" is open; kept by the page so a new run does not close it. */
  advancedOpen?: boolean;
  onAdvancedToggle?: (open: boolean) => void;
  onScenarioChange: (scenario: string) => void;
  onModeChange: (mode: RunMode) => void;
  onViewModeChange: (viewMode: ViewMode) => void;
  onRunAgain: () => void;
}

const SELECT = "h-9 rounded-md border border-input bg-background px-3 text-sm";

/**
 * "Run again" and the demo steps are always visible; scenario, mode and the three-lane toggle sit
 * under "Advanced". Keeps no state beyond the mode list.
 */
export function RunControls({
  apiUrl,
  scenario,
  mode,
  viewMode,
  note,
  steps,
  guide,
  advancedOpen = false,
  onAdvancedToggle,
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
    <div role="group" aria-label="Run controls" className="space-y-4 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        {steps}
        <Button type="button" variant="outline" className="h-9 text-sm" onClick={onRunAgain}>
          Run again
        </Button>
      </div>
      {guide}
      {note === undefined || note === null ? null : (
        <p data-switch-note role="status" className="text-xs text-muted-foreground">
          {note}
        </p>
      )}
      <details
        open={advancedOpen}
        onToggle={(event) => {
          onAdvancedToggle?.(event.currentTarget.open);
        }}
        className="rounded-md border px-3 py-2"
      >
        <summary className="cursor-pointer text-sm font-medium select-none">Advanced</summary>
        <div className="mt-3 flex flex-wrap items-center gap-3">
          <label className="flex items-center gap-2">
            Scenario
            <select
              value={scenario}
              onChange={(event) => {
                onScenarioChange(event.target.value);
              }}
              className={SELECT}
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
              className={SELECT}
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
          <Button
            type="button"
            variant="outline"
            aria-pressed={viewMode === "three-lane"}
            className="h-9 text-sm"
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
        </div>
      </details>
    </div>
  );
}

"use client";

import { useState } from "react";

import { PANELS } from "@/components/playground-panels";
import {
  DEFAULT_PLAYGROUND_MODE,
  MODE_TITLES,
  PLAYGROUND_MODES,
  playgroundUrl,
} from "@/lib/playground-state";
import type { PlaygroundMode } from "@/lib/playground-state";

export interface PlaygroundViewProps {
  apiUrl: string;
  initialMode?: PlaygroundMode;
}

/** The judge playground: four tabs and the active mode's panel. Panels keep their own state. */
export function PlaygroundView({
  apiUrl,
  initialMode = DEFAULT_PLAYGROUND_MODE,
}: PlaygroundViewProps) {
  const [mode, setMode] = useState<PlaygroundMode>(initialMode);
  const Panel = PANELS[mode];
  return (
    <main className="mx-auto max-w-[1600px] space-y-4 px-6 py-6 text-sm">
      <header>
        <h1 className="text-xl font-semibold">Judge playground</h1>
      </header>
      <div role="tablist" aria-label="Playground modes" className="flex flex-wrap gap-2">
        {PLAYGROUND_MODES.map((item) => (
          <button
            key={item}
            type="button"
            role="tab"
            aria-selected={item === mode}
            className={`h-8 border px-3 ${item === mode ? "bg-primary text-primary-foreground" : "bg-background"}`}
            onClick={() => {
              setMode(item);
              window.history.replaceState(null, "", playgroundUrl({ mode: item }));
            }}
          >
            {MODE_TITLES[item]}
          </button>
        ))}
      </div>
      <div role="tabpanel" aria-label={MODE_TITLES[mode]}>
        <Panel apiUrl={apiUrl} />
      </div>
    </main>
  );
}

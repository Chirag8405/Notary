"use client";

import Link from "next/link";
import { useState } from "react";

import { PANELS } from "@/components/playground-panels";
import { Button } from "@/components/ui/button";
import {
  DEFAULT_PLAYGROUND_MODE,
  MODE_INTRO,
  MODE_TITLES,
  PLAYGROUND_MODES,
  playgroundUrl,
} from "@/lib/playground-state";
import type { PlaygroundMode } from "@/lib/playground-state";

export interface PlaygroundViewProps {
  apiUrl: string;
  initialMode?: PlaygroundMode;
}

/** The judge playground: four tabs, what the open mode is for, and the mode's panel. */
export function PlaygroundView({
  apiUrl,
  initialMode = DEFAULT_PLAYGROUND_MODE,
}: PlaygroundViewProps) {
  const [mode, setMode] = useState<PlaygroundMode>(initialMode);
  const Panel = PANELS[mode];
  return (
    <main className="mx-auto max-w-6xl space-y-6 px-4 py-8 text-sm sm:px-6">
      <header className="space-y-1">
        <h1 className="text-3xl font-semibold tracking-tight">Judge playground</h1>
        <p className="text-base text-muted-foreground">
          Try to break NOTARY.{" "}
          <Link href="/demo" className="underline underline-offset-4">
            New here? Start with the guided demo.
          </Link>
        </p>
      </header>
      <div role="tablist" aria-label="Playground modes" className="flex flex-wrap gap-2">
        {PLAYGROUND_MODES.map((item) => (
          <Button
            key={item}
            type="button"
            role="tab"
            aria-selected={item === mode}
            variant={item === mode ? "default" : "outline"}
            className="h-9"
            onClick={() => {
              setMode(item);
              window.history.replaceState(null, "", playgroundUrl({ mode: item }));
            }}
          >
            {MODE_TITLES[item]}
          </Button>
        ))}
      </div>
      <p className="text-base">{MODE_INTRO[mode]}</p>
      <div role="tabpanel" aria-label={MODE_TITLES[mode]}>
        <Panel apiUrl={apiUrl} />
      </div>
    </main>
  );
}

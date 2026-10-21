"use client";

import { useEffect, useState } from "react";

import { Card, CardContent } from "@/components/ui/card";
import { usePrefersReducedMotion } from "@/lib/motion";
import { cn } from "@/lib/utils";

const PHASES = [
  { label: "Checking the account…", tone: "border-border bg-muted text-muted-foreground" },
  {
    label: "Needs your approval",
    tone: "animate-pulse-ring border-warn bg-warn-soft text-warn-strong",
  },
  { label: "You said no. Nothing was paid.", tone: "border-ok bg-ok-soft text-ok-strong" },
] as const;

function Mark({ children }: { children: string }) {
  return (
    <mark className="rounded-sm bg-bad/25 px-px font-bold text-bad-strong underline decoration-bad">
      {children}
    </mark>
  );
}

/**
 * A small looping picture of the whole idea: a bill with a swapped account, the account NOTARY
 * knows, and the answer NOTARY gives. It is decoration, not data, and stands still for people who
 * ask for less motion.
 */
export function LiveCheck() {
  const reduced = usePrefersReducedMotion();
  const [tick, setTick] = useState(0);

  useEffect(() => {
    if (reduced) return;
    const timer = window.setInterval(() => {
      setTick((value) => value + 1);
    }, 2400);
    return () => {
      window.clearInterval(timer);
    };
  }, [reduced]);

  const index = reduced ? 1 : tick % PHASES.length;
  const phase = PHASES[index] ?? PHASES[0];
  return (
    <Card className="mx-auto w-full max-w-xl text-left shadow-xl shadow-primary/10">
      <CardContent className="space-y-4">
        <div className="flex items-center justify-between gap-3">
          <p className="text-sm text-muted-foreground">
            You asked: <span className="font-medium text-foreground">Pay my December bill</span>
          </p>
          <span className="flex gap-1" aria-hidden="true">
            <span className="size-2.5 rounded-full bg-bad/70" />
            <span className="size-2.5 rounded-full bg-warn/70" />
            <span className="size-2.5 rounded-full bg-ok/70" />
          </span>
        </div>
        <div className="space-y-3 rounded-lg border bg-background p-4 font-mono text-sm">
          <div>
            <p className="font-sans text-xs tracking-wide text-muted-foreground uppercase">
              The email tells the agent to pay
            </p>
            <p className="break-all">
              DE00A<Mark>TTACKER</Mark>0000000001
            </p>
          </div>
          <div>
            <p className="font-sans text-xs tracking-wide text-muted-foreground uppercase">
              The account you always pay
            </p>
            <p className="break-all">
              DE00A<Mark>CME0000</Mark>0000000001
            </p>
          </div>
        </div>
        <div
          key={index}
          role="status"
          aria-live="polite"
          className={cn(
            "animate-pop rounded-lg border px-4 py-3 text-sm font-medium transition-colors",
            phase.tone,
          )}
        >
          {phase.label}
        </div>
      </CardContent>
    </Card>
  );
}

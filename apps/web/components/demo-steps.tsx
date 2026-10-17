"use client";

import type { ReactNode } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { DEMO_STEPS } from "@/lib/demo-steps";

/** The four demo steps as buttons; the active one is filled. */
export function DemoStepNav({
  active,
  onSelect,
}: {
  active: number | null;
  onSelect: (id: number) => void;
}) {
  return (
    <nav aria-label="Demo steps">
      <ol className="flex flex-wrap gap-2">
        {DEMO_STEPS.map((step) => {
          const current = step.id === active;
          return (
            <li key={step.id}>
              <Button
                type="button"
                variant={current ? "default" : "outline"}
                aria-current={current ? "step" : undefined}
                data-step={step.id}
                className="h-9 cursor-pointer gap-2 text-sm"
                onClick={() => {
                  onSelect(step.id);
                }}
              >
                <Badge
                  variant={current ? "secondary" : "muted"}
                  className="size-5 justify-center rounded-full px-0"
                >
                  {step.id}
                </Badge>
                {step.title}
              </Button>
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

/** What the active step is about and what to look for. Nothing for a screen that is no step. */
export function DemoGuide({ active }: { active: number | null }): ReactNode {
  const step = DEMO_STEPS.find((item) => item.id === active);
  if (step === undefined) return null;
  return (
    <Alert role="note" data-demo-guide={step.id}>
      <AlertTitle>{`Step ${step.id}: ${step.title}`}</AlertTitle>
      <AlertDescription>
        <p>{step.description}</p>
        <p className="mt-2 font-medium text-foreground">Look for:</p>
        <ul className="list-disc pl-5">
          {step.lookFor.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      </AlertDescription>
    </Alert>
  );
}

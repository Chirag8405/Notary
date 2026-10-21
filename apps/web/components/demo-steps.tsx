"use client";

import { ArrowLeft, ArrowRight, ChevronDown } from "lucide-react";
import type { ReactNode } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { DEMO_STEPS } from "@/lib/demo-steps";

/** The four demo steps as buttons, with where you are: a count and a progress bar. */
export function DemoStepNav({
  active,
  onSelect,
}: {
  active: number | null;
  onSelect: (id: number) => void;
}) {
  return (
    <nav aria-label="Demo steps" className="w-full space-y-3">
      {active === null ? null : (
        <div className="flex items-center gap-3">
          <Badge variant="secondary">
            Step {active} of {DEMO_STEPS.length}
          </Badge>
          <Progress
            value={(active / DEMO_STEPS.length) * 100}
            aria-label="Progress"
            className="max-w-xs"
          />
        </div>
      )}
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
                className="h-9 cursor-pointer gap-2"
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
    <Card role="note" data-demo-guide={step.id}>
      <CardHeader>
        <CardTitle>{`Step ${step.id}: ${step.title}`}</CardTitle>
        <CardDescription className="text-base">{step.description}</CardDescription>
      </CardHeader>
      <CardContent>
        <Collapsible>
          <CollapsibleTrigger className="group flex cursor-pointer items-center gap-1 text-sm font-medium">
            What to watch
            <ChevronDown className="size-4 transition-transform group-data-[state=open]:rotate-180" />
          </CollapsibleTrigger>
          <CollapsibleContent>
            <ul className="mt-2 list-disc space-y-1 pl-5">
              {step.lookFor.map((line) => (
                <li key={line}>{line}</li>
              ))}
            </ul>
          </CollapsibleContent>
        </Collapsible>
      </CardContent>
    </Card>
  );
}

/** Back and Next between the steps; nothing for a screen that is no step. */
export function DemoStepFooter({
  active,
  onSelect,
}: {
  active: number | null;
  onSelect: (id: number) => void;
}): ReactNode {
  if (active === null) return null;
  return (
    <nav aria-label="Step navigation" className="flex items-center justify-between">
      <Button
        type="button"
        variant="outline"
        disabled={active <= 1}
        onClick={() => {
          onSelect(active - 1);
        }}
      >
        <ArrowLeft /> Back
      </Button>
      <Button
        type="button"
        disabled={active >= DEMO_STEPS.length}
        onClick={() => {
          onSelect(active + 1);
        }}
      >
        Next step <ArrowRight />
      </Button>
    </nav>
  );
}

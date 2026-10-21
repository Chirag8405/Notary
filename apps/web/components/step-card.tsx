import type { ReactNode } from "react";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

/**
 * One numbered step of a task, the way the guided demo lays them out: the number, a title, one
 * line saying what to do, then the step's content.
 */
export function StepCard({
  step,
  title,
  hint,
  children,
}: {
  step: number;
  title: string;
  hint?: string;
  children: ReactNode;
}) {
  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-3">
          <span className="flex size-7 shrink-0 items-center justify-center rounded-full bg-primary text-sm text-primary-foreground">
            {step}
          </span>
          <h2 className="text-lg font-semibold">{title}</h2>
        </CardTitle>
        {hint === undefined ? null : <CardDescription>{hint}</CardDescription>}
      </CardHeader>
      <CardContent className="space-y-4">{children}</CardContent>
    </Card>
  );
}

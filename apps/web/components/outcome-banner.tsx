import { CircleDashed, ShieldAlert, ShieldCheck, TriangleAlert } from "lucide-react";
import type { ReactNode } from "react";

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import type { Outcome, OutcomeTone } from "@/lib/guided";
import { cn } from "@/lib/utils";

const TONE: Record<OutcomeTone, { icon: ReactNode; box: string }> = {
  safe: {
    icon: <ShieldCheck className="size-5 text-ok-strong" />,
    box: "border-ok bg-ok-soft",
  },
  warn: {
    icon: <TriangleAlert className="size-5 text-warn-strong" />,
    box: "border-warn bg-warn-soft",
  },
  danger: {
    icon: <ShieldAlert className="size-5 text-bad-strong" />,
    box: "border-bad bg-bad-soft",
  },
  idle: {
    icon: <CircleDashed className="size-5 text-muted-foreground" />,
    box: "bg-muted/40",
  },
};

/** One headline for a run: an icon and words, never colour alone. */
export function OutcomeBanner({
  outcome,
  compact = false,
}: {
  outcome: Outcome;
  compact?: boolean;
}) {
  const tone = TONE[outcome.tone];
  return (
    <Alert
      role="region"
      aria-label="Result"
      aria-live="polite"
      data-outcome={outcome.tone}
      className={cn(
        "flex animate-pop items-start gap-3",
        tone.box,
        compact ? "px-3 py-2" : "px-4 py-4",
      )}
    >
      <span className="mt-0.5 shrink-0">{tone.icon}</span>
      <div>
        <AlertTitle className={compact ? "text-sm" : "text-base"}>{outcome.title}</AlertTitle>
        <AlertDescription className="text-muted-foreground">{outcome.detail}</AlertDescription>
      </div>
    </Alert>
  );
}

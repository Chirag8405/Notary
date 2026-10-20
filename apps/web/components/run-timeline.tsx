import type { CallView, RunView } from "@notary/ui";

import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { explainDecision, paramText, toolText, verdictText } from "@/lib/plain-language";
import { cn } from "@/lib/utils";

const TONE_BADGE = {
  safe: "border-ok bg-ok-soft text-ok-strong",
  warn: "border-warn bg-warn-soft text-warn-strong",
  stop: "border-bad bg-bad-soft text-bad-strong",
} as const;

function argLines(call: CallView, view: RunView): { label: string; value: string }[] {
  return Object.entries(call.args).map(([name, ref]) => ({
    label: paramText(name),
    value: view.values.find((value) => value.ref.id === ref.id)?.preview ?? "",
  }));
}

function Verdict({ call }: { call: CallView }) {
  if (call.decision === null) {
    return <Badge variant="muted">No check</Badge>;
  }
  const text = verdictText(call.decision.verdict);
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge variant="outline" className={cn("cursor-help", TONE_BADGE[text.tone])}>
          {text.label}
        </Badge>
      </TooltipTrigger>
      <TooltipContent className="max-w-xs">
        <p className="font-medium">Technical detail</p>
        <ul className="mt-1 space-y-0.5 font-mono text-xs">
          {call.decision.reasons.map((reason, index) => (
            <li key={`${reason.check}:${reason.code}:${index}`}>
              {reason.check}: {reason.code}
            </li>
          ))}
        </ul>
      </TooltipContent>
    </Tooltip>
  );
}

/**
 * What the agent tried to do, one row per action: what it was, what it carried, and in plain
 * words whether NOTARY let it through. The technical reason codes are in the badge's tooltip.
 */
export function RunTimeline({ view }: { view: RunView }) {
  if (view.calls.length === 0) {
    return <p className="text-sm text-muted-foreground">The agent has not done anything yet.</p>;
  }
  return (
    <TooltipProvider>
      <ol aria-label="What the agent did" className="space-y-3">
        {view.calls.map((call, index) => (
          <li
            key={call.callId}
            data-timeline-call={call.callId}
            style={{ animationDelay: `${index * 90}ms` }}
            className="flex animate-rise gap-3"
          >
            <span className="flex size-6 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-medium">
              {index + 1}
            </span>
            <div className="min-w-0 flex-1 space-y-1">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-medium">{toolText(call.tool)}</span>
                <Verdict call={call} />
              </div>
              {argLines(call, view).map((line) => (
                <p key={line.label} className="text-sm text-muted-foreground">
                  {line.label}: <span className="font-mono text-foreground">{line.value}</span>
                </p>
              ))}
              {call.decision === null ? null : (
                <p className="text-sm">{explainDecision(call.decision)}</p>
              )}
              {call.executed === null ? null : (
                <p className="text-sm text-muted-foreground">Result: {call.executed.summary}</p>
              )}
            </div>
          </li>
        ))}
      </ol>
    </TooltipProvider>
  );
}

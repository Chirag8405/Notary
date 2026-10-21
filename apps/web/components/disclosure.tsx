import { ChevronDown } from "lucide-react";
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

/**
 * Detail that most people do not need: a titled row that opens on request. The content stays in
 * the page while closed, so it is still there for a screen reader's search and for the tests.
 */
export function Disclosure({
  title,
  hint,
  defaultOpen = false,
  className,
  onToggle,
  children,
}: {
  title: string;
  hint?: string;
  defaultOpen?: boolean;
  className?: string;
  /** Called with the new state each time the row opens or closes. */
  onToggle?: (open: boolean) => void;
  children: ReactNode;
}) {
  return (
    <details
      open={defaultOpen}
      onToggle={(event) => {
        onToggle?.(event.currentTarget.open);
      }}
      className={cn("group rounded-lg border bg-card", className)}
    >
      <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-sm font-medium select-none [&::-webkit-details-marker]:hidden">
        <span>
          {title}
          {hint === undefined ? null : (
            <span className="ml-2 font-normal text-muted-foreground">{hint}</span>
          )}
        </span>
        <ChevronDown className="size-4 shrink-0 text-muted-foreground transition-transform group-open:rotate-180" />
      </summary>
      <div className="space-y-4 border-t px-4 py-4">{children}</div>
    </details>
  );
}

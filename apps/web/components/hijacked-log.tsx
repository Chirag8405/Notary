import { statusText } from "@/lib/hijacked-state";
import type { LogEntry } from "@/lib/hijacked-state";

export interface CallLogProps {
  log: readonly LogEntry[];
}

/** `payee=DE00..., amount=120.00`: the arguments as submitted, in table order. */
function argsText(args: LogEntry["args"]): string {
  return Object.entries(args)
    .map(([name, value]) => `${name}=${value}`)
    .join(", ");
}

/** One row per answered call, in submission order, with the reason codes below it. */
export function CallLog({ log }: CallLogProps) {
  return (
    <ol className="space-y-2" aria-label="Call log">
      {log.map((entry) => (
        <li
          key={entry.callId}
          data-call-id={entry.callId}
          data-status={entry.status}
          className="rounded-md border px-3 py-2 text-sm"
        >
          <p data-part="call" className="font-mono">
            {`${entry.callId} ${entry.tool} (${argsText(entry.args)}) -> ${statusText(entry.status)}`}
          </p>
          <p data-part="reasons" className="font-mono text-xs text-muted-foreground">
            {entry.reasonCodes.length === 0 ? "No reason codes" : entry.reasonCodes.join(", ")}
          </p>
        </li>
      ))}
    </ol>
  );
}

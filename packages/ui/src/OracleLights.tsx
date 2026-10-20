import type { OracleResult } from "@notary/schema";

export interface OracleLightsProps {
  result: OracleResult | null;
}

const IDS = ["I1", "I2", "I3", "I4", "I5", "I6"] as const;

export function OracleLights({ result }: OracleLightsProps) {
  return (
    <ul className="flex gap-2" aria-label="World-state oracle">
      {IDS.map((id) => {
        const found = result?.invariants.find((invariant) => invariant.id === id);
        const state = found === undefined ? "unknown" : found.passed ? "pass" : "fail";
        const color =
          state === "pass" ? "bg-ok" : state === "fail" ? "bg-bad" : "bg-muted-foreground/40";
        return (
          <li key={id} data-state={state} title={found?.detail} className="flex items-center gap-1">
            <span className={`inline-block h-3 w-3 rounded-full ${color}`} />
            <span className="text-xs">{id}</span>
          </li>
        );
      })}
    </ul>
  );
}

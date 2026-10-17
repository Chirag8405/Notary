import type { Marker } from "@notary/schema";

/**
 * How a per-parameter marker of the intent contract reads on a chip. Pure and deterministic.
 *
 * - strict: the contract pins the value (literal, named source or ledger)
 * - gated: the user must confirm it (endorse)
 * - open: the contract does not constrain it (free)
 */
export type MarkerTone = "strict" | "gated" | "open";

export const LABEL_ENDORSE = "endorse";
export const LABEL_FREE = "free";
export const LABEL_LEDGER_PREFIX = "ledger:";
export const LABEL_LITERAL_PREFIX = "literal:";
export const LABEL_SOURCE_PREFIX = "source:";

function assertNever(marker: never): never {
  throw new Error(`Unhandled marker: ${JSON.stringify(marker)}`);
}

/** The text of a marker chip, built from the fields each marker kind really carries. */
export function markerLabel(marker: Marker): string {
  switch (marker.kind) {
    case "literal":
      return `${LABEL_LITERAL_PREFIX}${String(marker.value)}`;
    case "named_source":
      return `${LABEL_SOURCE_PREFIX}${marker.source}`;
    case "ledger":
      return `${LABEL_LEDGER_PREFIX}${marker.ledger}`;
    case "endorse":
      return LABEL_ENDORSE;
    case "free":
      return LABEL_FREE;
    default:
      return assertNever(marker);
  }
}

export function markerTone(marker: Marker): MarkerTone {
  switch (marker.kind) {
    case "literal":
    case "named_source":
    case "ledger":
      return "strict";
    case "endorse":
      return "gated";
    case "free":
      return "open";
    default:
      return assertNever(marker);
  }
}

"use client";

import { getAnchor } from "@notary/client";
import type { RestClient } from "@notary/client";
import { useEffect, useState } from "react";

const HEAD_SHORT = 12;

interface Result {
  runId: string;
  anchor: { head: string; length: number } | null;
}

/** The first characters of a hash, without a leading "<algorithm>:" prefix if there is one. */
function shortHead(head: string): string {
  const start = head.lastIndexOf(":") + 1;
  return head.slice(start, start + HEAD_SHORT);
}

/**
 * The audit head the server persisted outside the log. Nothing is shown until the run has
 * finished; then the anchor is read once per run, and any failure reads "no anchor available".
 */
export function AnchorFooter({
  client,
  runId,
  finished,
}: {
  client: RestClient;
  runId: string | null;
  finished: boolean;
}) {
  const [result, setResult] = useState<Result | null>(null);

  useEffect(() => {
    if (!finished || runId === null) return;
    let cancelled = false;
    getAnchor(client, runId).then(
      (anchor) => {
        if (!cancelled) {
          setResult({
            runId,
            anchor: anchor === null ? null : { head: anchor.head, length: anchor.length },
          });
        }
      },
      () => {
        if (!cancelled) setResult({ runId, anchor: null });
      },
    );
    return () => {
      cancelled = true;
    };
  }, [client, runId, finished]);

  if (!finished || runId === null || result?.runId !== runId) return null;
  return (
    <footer aria-label="Audit anchor" className="text-xs text-neutral-600">
      {result.anchor === null
        ? "no anchor available"
        : `Audit head ${shortHead(result.anchor.head)} | ${result.anchor.length} entries | persisted outside the log`}
    </footer>
  );
}

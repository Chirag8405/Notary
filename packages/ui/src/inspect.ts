import type { ValueRef } from "@notary/schema";

import type { RunView, ValueView } from "./run-view";

/**
 * What the content inspector shows for one value. Pure and deterministic: no React, clock or
 * randomness, and the view is never mutated. Events carry only the server's redacted preview, so
 * a span is a best effort over that preview (see `approximate`).
 */

export interface Inspection {
  /** Always the bare value id, even when looked up by a graph node id. */
  valueId: string;
  contentHash: string;
  preview: string;
  unit: ValueView["unit"];
  /** True once a `value_labeled` event arrived; false for a value seen only as a call argument. */
  labeled: boolean;
  originKind: string;
  /** The tool's name for a tool origin, else null. */
  originName: string | null;
  integrity: ValueRef["label"]["integrity"];
  readers:
    { kind: "public" } | { kind: "nobody" } | { kind: "principals"; names: readonly string[] };
  source: null | {
    valueId: string;
    start: number;
    end: number;
    /** The source's preview; null when the source has not been seen or has no preview yet. */
    sourcePreview: string | null;
    before: string;
    span: string;
    after: string;
    /**
     * True when the source preview is known but the span is clipped (end past the preview) or
     * clamps to nothing: the pointer's offsets are into the full text, which the UI never has.
     */
    approximate: boolean;
  };
}

function byText(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function decodeReaders(readers: readonly string[]): Inspection["readers"] {
  if (readers.includes("*")) return { kind: "public" };
  if (readers.length === 0) return { kind: "nobody" };
  return { kind: "principals", names: [...new Set(readers)].sort(byText) };
}

function find(view: RunView, id: string): ValueView | undefined {
  return view.values.find((value) => value.ref.id === id);
}

/** Look a value up by its bare id; a graph node id ("v:<id>") is accepted once. */
function lookup(view: RunView, id: string): ValueView | null {
  const direct = find(view, id);
  if (direct !== undefined) return direct;
  if (!id.startsWith("v:")) return null;
  return find(view, id.slice(2)) ?? null;
}

function clamp(n: number, low: number, high: number): number {
  return Math.min(Math.max(n, low), high);
}

function sourceOf(view: RunView, pointer: NonNullable<ValueRef["label"]["span_pointer"]>) {
  const source = find(view, pointer.source_value_id);
  const sourcePreview = source === undefined || source.preview === "" ? null : source.preview;
  if (sourcePreview === null) {
    return {
      valueId: pointer.source_value_id,
      start: pointer.start,
      end: pointer.end,
      sourcePreview,
      before: "",
      span: "",
      after: "",
      approximate: false,
    };
  }
  const start = clamp(pointer.start, 0, sourcePreview.length);
  const end = clamp(pointer.end, start, sourcePreview.length);
  const span = sourcePreview.slice(start, end);
  return {
    valueId: pointer.source_value_id,
    start: pointer.start,
    end: pointer.end,
    sourcePreview,
    before: sourcePreview.slice(0, start),
    span,
    after: sourcePreview.slice(end),
    approximate: pointer.end > sourcePreview.length || (span === "" && pointer.end > pointer.start),
  };
}

/** Everything the inspector shows for a value; null for an unknown id. Looks one hop, never more. */
export function inspectValue(view: RunView, valueId: string): Inspection | null {
  const value = lookup(view, valueId);
  if (value === null) return null;
  const label = value.ref.label;
  const origin = label.origin;
  return {
    valueId: value.ref.id,
    contentHash: value.ref.content_hash,
    preview: value.preview,
    unit: value.unit,
    labeled: value.labeled,
    originKind: origin.kind,
    originName: origin.kind === "tool" ? origin.name : null,
    integrity: label.integrity,
    readers: decodeReaders(label.readers),
    source: label.span_pointer === null ? null : sourceOf(view, label.span_pointer),
  };
}

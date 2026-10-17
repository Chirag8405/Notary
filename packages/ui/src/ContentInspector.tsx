import { inspectValue } from "./inspect";
import type { Inspection } from "./inspect";
import type { RunView } from "./run-view";

export interface ContentInspectorProps {
  view: RunView;
  /** The bare value id (a graph node id such as "v:<id>" is accepted); null when nothing is selected. */
  valueId: string | null;
}

const HASH_SHORT = 12;

/** The visible warning for an untrusted value, from where it came. */
function untrustedTag(originKind: string): string {
  switch (originKind) {
    case "tool":
    case "email":
    case "file":
    case "web":
      return `untrusted: came from ${originKind} content`;
    case "llm":
      return "untrusted: written by the model";
    default:
      return `untrusted: from ${originKind}`;
  }
}

function readersText(readers: Inspection["readers"]): string {
  switch (readers.kind) {
    case "public":
      return "public";
    case "nobody":
      return "nobody";
    case "principals":
      return readers.names.join(", ");
  }
}

/**
 * The value behind a node or chip: its label, where it was taken from and the server's redacted
 * preview. Everything is rendered as plain text; the component keeps no state.
 */
export function ContentInspector({ view, valueId }: ContentInspectorProps) {
  if (valueId === null) {
    return (
      <section aria-label="Content inspector" className="text-sm">
        <p className="text-neutral-500">Select a node or chip to inspect it</p>
      </section>
    );
  }
  const found = inspectValue(view, valueId);
  if (found === null) {
    return (
      <section aria-label="Content inspector" className="text-sm">
        <p className="text-neutral-500">Value not found</p>
      </section>
    );
  }
  const origin = found.originName === null ? found.originKind : `tool:${found.originName}`;
  const source = found.source;
  return (
    <section aria-label="Content inspector" className="space-y-3 text-sm">
      {found.integrity === "untrusted" ? (
        <p
          data-testid="untrusted-tag"
          className="inline-block rounded bg-amber-100 px-1 text-xs font-semibold text-amber-900"
        >
          {untrustedTag(found.originKind)}
        </p>
      ) : null}
      <dl aria-label="Value details" className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
        <dt className="text-neutral-500">value</dt>
        <dd className="font-mono">{found.valueId}</dd>
        <dt className="text-neutral-500">origin</dt>
        <dd>{origin}</dd>
        <dt className="text-neutral-500">integrity</dt>
        <dd>{found.integrity}</dd>
        <dt className="text-neutral-500">readers</dt>
        <dd>{readersText(found.readers)}</dd>
        <dt className="text-neutral-500">unit</dt>
        <dd>{found.unit ?? "none"}</dd>
        <dt className="text-neutral-500">content hash</dt>
        <dd className="font-mono" title={found.contentHash}>
          {found.contentHash.slice(0, HASH_SHORT)}
        </dd>
      </dl>
      <div>
        <h4 className="text-xs font-semibold uppercase text-neutral-500">preview</h4>
        <p data-testid="preview" className="whitespace-pre-wrap break-words font-mono">
          {found.preview === "" && !found.labeled ? "preview not available yet" : found.preview}
        </p>
      </div>
      {source === null ? null : (
        <div data-testid="source">
          <h4 className="text-xs font-semibold uppercase text-neutral-500">
            taken from <span className="font-mono normal-case">{source.valueId}</span>{" "}
            <span className="normal-case">
              ({source.start}..{source.end})
            </span>
          </h4>
          {source.sourcePreview === null ? (
            <p className="text-neutral-500">source value not seen yet</p>
          ) : (
            <p className="whitespace-pre-wrap break-words font-mono">
              {source.before}
              <mark data-testid="span">{source.span}</mark>
              {source.after}
            </p>
          )}
          {source.approximate ? (
            <p data-testid="approximate" className="text-xs text-neutral-600">
              span is approximate: only a redacted preview is available
            </p>
          ) : null}
        </div>
      )}
    </section>
  );
}

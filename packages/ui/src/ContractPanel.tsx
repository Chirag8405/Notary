import type { IntentContract } from "@notary/schema";

import { markerLabel, markerTone } from "./marker-chip";
import type { MarkerTone } from "./marker-chip";

export interface ContractPanelProps {
  contract: IntentContract | null;
}

const MANIFEST_SHORT = 8;

const TONE_CLASS: Record<MarkerTone, string> = {
  strict: "border-green-500 bg-green-50 text-green-900",
  gated: "border-yellow-500 bg-yellow-50 text-yellow-900",
  open: "border-neutral-400 bg-neutral-50 text-neutral-700",
};

/** The frozen intent contract as chips: what the user approved, not the monitor's effective policy. */
export function ContractPanel({ contract }: ContractPanelProps) {
  if (contract === null) {
    return (
      <section aria-label="Intent contract" className="text-sm">
        <p className="text-neutral-500">No contract yet</p>
      </section>
    );
  }
  const irreversible = new Set(contract.authorized_irreversible);
  return (
    <section aria-label="Intent contract" className="space-y-3 text-sm">
      <p data-testid="intent" className="font-semibold">
        {contract.user_intent}
      </p>
      <ul className="space-y-2" aria-label="Allowed tools">
        {contract.allowed_tools.map((scope, index) => {
          const params = Object.entries(scope.params);
          const isIrreversible = irreversible.has(scope.tool);
          return (
            <li
              key={`${index}:${scope.tool}`}
              data-tool={scope.tool}
              {...(isIrreversible ? { "data-irreversible": "true" } : {})}
              className="flex flex-wrap items-center gap-2"
            >
              <code>{scope.tool}</code>
              <span data-effect className="text-xs text-neutral-600">
                {scope.effect}
              </span>
              <span
                data-manifest
                title={scope.manifest_hash}
                className="font-mono text-xs text-neutral-400"
              >
                {scope.manifest_hash.slice(0, MANIFEST_SHORT)}
              </span>
              {isIrreversible ? (
                <span
                  data-irreversible-tag
                  className="rounded bg-red-100 px-1 text-xs font-semibold text-red-900"
                >
                  irreversible
                </span>
              ) : null}
              {params.length === 0 ? (
                <span data-no-params className="text-xs text-neutral-500">
                  no parameters
                </span>
              ) : (
                params.map(([param, marker]) => {
                  const tone = markerTone(marker);
                  return (
                    <span key={param} className="inline-flex items-center gap-1">
                      <span
                        data-param={param}
                        data-tone={tone}
                        data-marker-kind={marker.kind}
                        className={`rounded border px-1 text-xs ${TONE_CLASS[tone]}`}
                      >
                        {param}: {markerLabel(marker)}
                      </span>
                      <span data-tone-label className="text-[10px] uppercase text-neutral-500">
                        {tone}
                      </span>
                    </span>
                  );
                })
              )}
            </li>
          );
        })}
      </ul>
      <dl aria-label="Effect budget" className="grid grid-cols-[auto_1fr] gap-x-3 text-xs">
        {Object.entries(contract.budget).flatMap(([field, value]) => [
          <dt key={`${field}:dt`} className="font-mono text-neutral-600">
            {field}
          </dt>,
          <dd key={`${field}:dd`}>{String(value)}</dd>,
        ])}
      </dl>
      {contract.egress_hosts.length === 0 ? (
        <p data-egress-empty className="text-xs text-neutral-600">
          no egress allowed
        </p>
      ) : (
        <ul className="flex flex-wrap gap-1" aria-label="Egress hosts">
          {contract.egress_hosts.map((host) => (
            <li key={host} className="rounded border px-1 font-mono text-xs">
              {host}
            </li>
          ))}
        </ul>
      )}
      <div>
        <h4 className="text-xs font-semibold uppercase text-neutral-500">
          authorized irreversible
        </h4>
        {contract.authorized_irreversible.length === 0 ? (
          <p data-irreversible-none className="text-xs text-neutral-600">
            none
          </p>
        ) : (
          <ul className="flex flex-wrap gap-1" aria-label="Authorized irreversible">
            {contract.authorized_irreversible.map((tool) => (
              <li key={tool} className="rounded border px-1 font-mono text-xs">
                {tool}
              </li>
            ))}
          </ul>
        )}
      </div>
    </section>
  );
}

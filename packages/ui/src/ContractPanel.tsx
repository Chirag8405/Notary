import type { IntentContract } from "@notary/schema";

export interface ContractPanelProps {
  contract: IntentContract | null;
}

export function ContractPanel({ contract }: ContractPanelProps) {
  if (contract === null) return <p className="text-sm text-neutral-500">No contract yet.</p>;
  return (
    <section aria-label="Intent contract" className="space-y-2 text-sm">
      <p className="font-semibold">{contract.user_intent}</p>
      <ul className="space-y-1">
        {contract.allowed_tools.map((scope) => (
          <li key={scope.tool}>
            <code>{scope.tool}</code>
            {Object.entries(scope.params).map(([param, marker]) => (
              <span key={param} className="ml-2 text-neutral-600">
                {param}: {marker.kind}
              </span>
            ))}
          </li>
        ))}
      </ul>
      <p className="text-neutral-600">
        Budget: {contract.budget.max_effects} effects, {contract.budget.max_spend_cents}¢ spend
      </p>
    </section>
  );
}

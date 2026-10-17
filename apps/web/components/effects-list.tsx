import type { RunView } from "@notary/ui";

import { effectsOf } from "@/lib/x-ray-state";

/** "What changed": the effects the run executed, in order (a stand-in for a before/after diff). */
export function EffectsList({ view }: { view: RunView }) {
  const effects = effectsOf(view);
  return (
    <section aria-label="What changed" className="space-y-1 text-sm">
      {effects.length === 0 ? (
        <p className="text-neutral-500">nothing executed</p>
      ) : (
        <ol className="list-decimal space-y-1 pl-5">
          {effects.map((effect) => (
            <li key={effect.callId} data-call-id={effect.callId}>
              {effect.tool}: {effect.summary}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}

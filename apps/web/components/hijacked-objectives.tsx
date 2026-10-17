export interface ObjectiveCardsProps {
  objectives: readonly { objectiveId: string; title: string; reached: boolean }[];
}

/**
 * The attacker's objectives, as the server lists them. Not reached is the good (green) state and
 * reached the bad (red) one: the panel shows what the oracle reported and decides nothing itself.
 */
export function ObjectiveCards({ objectives }: ObjectiveCardsProps) {
  return (
    <ul className="grid gap-2 sm:grid-cols-2" aria-label="Objectives">
      {objectives.map((objective) => (
        <li
          key={objective.objectiveId}
          data-objective={objective.objectiveId}
          data-reached={objective.reached ? "true" : "false"}
          className={`flex items-center justify-between gap-3 rounded-md border px-3 py-2 text-sm ${
            objective.reached
              ? "border-red-400 bg-red-50 text-red-900"
              : "border-green-400 bg-green-50 text-green-900"
          }`}
        >
          <span>{objective.title}</span>
          <span className="font-semibold">{objective.reached ? "REACHED" : "Not reached"}</span>
        </li>
      ))}
    </ul>
  );
}

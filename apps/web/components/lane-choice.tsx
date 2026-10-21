import type { ReactNode } from "react";

/** A defence to test, as a tick box in a bordered chip that lights up when ticked. */
export function LaneChoice({
  checked,
  onChange,
  children,
}: {
  checked: boolean;
  onChange: (checked: boolean) => void;
  children: ReactNode;
}) {
  return (
    <label className="flex cursor-pointer items-center gap-2 rounded-lg border px-3 py-2 text-sm transition-colors has-[:checked]:border-primary has-[:checked]:bg-primary/5 hover:bg-muted">
      <input
        type="checkbox"
        className="size-4 accent-primary"
        checked={checked}
        onChange={(event) => {
          onChange(event.target.checked);
        }}
      />
      {children}
    </label>
  );
}

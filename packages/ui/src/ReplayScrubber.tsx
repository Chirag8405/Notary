/** A range over positions 0..length: the number of events shown, not an event index. */
export interface ReplayScrubberProps {
  length: number;
  index: number;
  onChange: (index: number) => void;
}

export function ReplayScrubber({ length, index, onChange }: ReplayScrubberProps) {
  return (
    <input
      type="range"
      aria-label="Replay position"
      min={0}
      max={length}
      value={index}
      disabled={length === 0}
      onChange={(change) => {
        onChange(Number(change.target.value));
      }}
      className="w-full"
    />
  );
}

export interface Segment {
  text: string;
  differs: boolean;
}

/**
 * Split `text` into runs of equal and differing characters.
 *
 * `positions` are character indices as the Python side counts them: Unicode code points, not
 * UTF-16 units, so the text is walked with `Array.from`. Positions that are negative, not whole
 * numbers or past the end are ignored, as are duplicates. Consecutive code points with the same
 * flag are merged, and joining the segments gives back `text` exactly. Pure; never throws.
 */
export function highlightDiff(text: string, positions: readonly number[]): readonly Segment[] {
  const characters = Array.from(text);
  const marked = new Set<number>();
  for (const position of positions) {
    if (Number.isInteger(position) && position >= 0 && position < characters.length) {
      marked.add(position);
    }
  }
  const segments: Segment[] = [];
  characters.forEach((character, index) => {
    const differs = marked.has(index);
    const last = segments[segments.length - 1];
    if (last?.differs === differs) last.text += character;
    else segments.push({ text: character, differs });
  });
  return segments;
}

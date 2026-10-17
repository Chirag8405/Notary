import type { ReactElement } from "react";

import type { PlaygroundMode } from "@/lib/playground-state";

export interface PanelProps {
  apiUrl: string;
}

function Placeholder(): ReactElement {
  return <p>Coming in a later P5 issue</p>;
}

/** One panel per mode. The mode issues replace their placeholder here. */
export const PANELS: Readonly<Record<PlaygroundMode, (props: PanelProps) => ReactElement>> = {
  poison: Placeholder,
  hijacked: Placeholder,
  library: Placeholder,
  arena: Placeholder,
};

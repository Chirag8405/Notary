import type { ReactElement } from "react";

import { ArenaPanel } from "@/components/arena-panel";
import { AttackLibraryPanel } from "@/components/attack-library-panel";
import { HijackedPanel } from "@/components/hijacked-panel";
import { PoisonPanel } from "@/components/poison-panel";
import type { PlaygroundMode } from "@/lib/playground-state";

export interface PanelProps {
  apiUrl: string;
}

/** One panel per mode. */
export const PANELS: Readonly<Record<PlaygroundMode, (props: PanelProps) => ReactElement>> = {
  poison: PoisonPanel,
  hijacked: HijackedPanel,
  library: AttackLibraryPanel,
  arena: ArenaPanel,
};

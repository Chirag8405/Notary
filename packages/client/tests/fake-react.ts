import type { DependencyList, EffectCallback } from "react";

/**
 * A minimal stand-in for the `react` module, so hooks can be tested in this package without a DOM
 * renderer (it has none). It mirrors the documented behavior the hook relies on: slots by call
 * order, `Object.is` dependency comparison, cleanups before the next run, cleanup on unmount, and
 * a synchronous re-render when state is set. It is installed with `vi.mock("react", ...)`.
 */

type Deps = DependencyList | undefined;
type Cleanup = (() => void) | undefined;

interface StateSlot {
  kind: "state";
  value: unknown;
  set: (next: unknown) => void;
}
interface RefSlot {
  kind: "ref";
  ref: { current: unknown };
}
interface EffectSlot {
  kind: "effect";
  deps: Deps;
  cleanup: Cleanup;
}
interface CallbackSlot {
  kind: "callback";
  fn: unknown;
  deps: readonly unknown[];
}
type Slot = StateSlot | RefSlot | EffectSlot | CallbackSlot;

interface Pending {
  slot: EffectSlot;
  run: EffectCallback;
}

function sameDeps(a: Deps, b: Deps): boolean {
  if (a === undefined || b === undefined) return false;
  return a.length === b.length && a.every((value, index) => Object.is(value, b[index]));
}

class Component<T> {
  readonly slots: Slot[] = [];
  private cursor = 0;
  private pending: Pending[] = [];
  private rendering = false;
  private dirty = false;
  mounted = true;
  result: T | undefined;
  renders = 0;

  constructor(readonly body: () => T) {}

  render(): void {
    if (!this.mounted) return;
    this.rendering = true;
    this.cursor = 0;
    this.pending = [];
    try {
      this.result = runBody(this);
    } finally {
      this.rendering = false;
    }
    this.renders += 1;
    this.flushEffects();
    if (this.dirty) {
      this.dirty = false;
      this.render();
    }
  }

  requestRender(): void {
    if (!this.mounted) return;
    if (this.rendering) this.dirty = true;
    else this.render();
  }

  nextSlot<S extends Slot>(create: () => S): { slot: S; fresh: boolean } {
    const existing = this.slots[this.cursor];
    this.cursor += 1;
    if (existing !== undefined) return { slot: existing as S, fresh: false };
    const slot = create();
    this.slots.push(slot);
    return { slot, fresh: true };
  }

  schedule(entry: Pending): void {
    this.pending.push(entry);
  }

  private flushEffects(): void {
    const due = this.pending;
    this.pending = [];
    for (const { slot } of due) {
      slot.cleanup?.();
      slot.cleanup = undefined;
    }
    for (const { slot, run } of due) {
      const cleanup = run();
      slot.cleanup = typeof cleanup === "function" ? cleanup : undefined;
    }
  }

  unmount(): void {
    if (!this.mounted) return;
    this.mounted = false;
    for (const slot of this.slots) {
      if (slot.kind === "effect") slot.cleanup?.();
    }
  }
}

let active: Component<unknown> | null = null;

/** Run a component body with its hooks bound to it. */
function runBody<T>(component: Component<T>): T {
  active = component;
  try {
    return component.body();
  } finally {
    active = null;
  }
}

function current(): Component<unknown> {
  if (active === null) throw new Error("a hook was called outside a render");
  return active;
}

export function useState<S>(initial: S | (() => S)): [S, (next: S | ((prev: S) => S)) => void] {
  const component = current();
  const { slot } = component.nextSlot<StateSlot>(() => {
    const created: StateSlot = {
      kind: "state",
      value: typeof initial === "function" ? (initial as () => S)() : initial,
      set: (next) => {
        const value =
          typeof next === "function" ? (next as (prev: unknown) => unknown)(created.value) : next;
        created.value = value;
        component.requestRender();
      },
    };
    return created;
  });
  return [slot.value as S, slot.set];
}

export function useRef<R>(initial: R): { current: R } {
  const { slot } = current().nextSlot<RefSlot>(() => ({ kind: "ref", ref: { current: initial } }));
  return slot.ref as { current: R };
}

export function useEffect(effect: EffectCallback, deps?: DependencyList): void {
  const component = current();
  const { slot, fresh } = component.nextSlot<EffectSlot>(() => ({
    kind: "effect",
    deps,
    cleanup: undefined,
  }));
  if (fresh || !sameDeps(slot.deps, deps)) {
    slot.deps = deps;
    component.schedule({ slot, run: effect });
  }
}

export function useCallback<F>(fn: F, deps: readonly unknown[]): F {
  const { slot, fresh } = current().nextSlot<CallbackSlot>(() => ({ kind: "callback", fn, deps }));
  if (!fresh && !sameDeps(slot.deps, deps)) {
    slot.fn = fn;
    slot.deps = deps;
  }
  return slot.fn as F;
}

export interface HookHandle<T> {
  readonly result: { readonly current: T };
  rerender(): void;
  unmount(): void;
  readonly renders: number;
}

/** Run `body` as a component: render once, run its effects, and let the test re-render it. */
export function renderHook<T>(body: () => T): HookHandle<T> {
  const component = new Component(body);
  component.render();
  return {
    get result() {
      return { current: component.result as T };
    },
    rerender: () => {
      component.render();
    },
    unmount: () => {
      component.unmount();
    },
    get renders() {
      return component.renders;
    },
  };
}

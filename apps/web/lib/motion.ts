import { useSyncExternalStore } from "react";

const QUERY = "(prefers-reduced-motion: reduce)";

/** Some environments (a test DOM, an old browser) have no `matchMedia`: treat that as "no preference". */
function supported(): boolean {
  return typeof window.matchMedia === "function";
}

function subscribe(notify: () => void): () => void {
  if (!supported()) return () => undefined;
  const query = window.matchMedia(QUERY);
  query.addEventListener("change", notify);
  return () => {
    query.removeEventListener("change", notify);
  };
}

/** True when the person asked their system for less motion. False on the server. */
export function usePrefersReducedMotion(): boolean {
  return useSyncExternalStore(
    subscribe,
    () => supported() && window.matchMedia(QUERY).matches,
    () => false,
  );
}

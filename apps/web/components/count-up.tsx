"use client";

import { useEffect, useRef, useState } from "react";

import { usePrefersReducedMotion } from "@/lib/motion";

/** A number that counts up from zero the first time it scrolls into view. */
export function CountUp({ to, durationMs = 1400 }: { to: number; durationMs?: number }) {
  const reduced = usePrefersReducedMotion();
  const box = useRef<HTMLSpanElement>(null);
  const [value, setValue] = useState(0);

  useEffect(() => {
    const element = box.current;
    if (reduced || element === null || typeof IntersectionObserver === "undefined") return;
    let frame = 0;
    const observer = new IntersectionObserver((entries) => {
      if (!entries.some((entry) => entry.isIntersecting)) return;
      observer.disconnect();
      const start = performance.now();
      const tick = (now: number) => {
        const progress = Math.min(1, (now - start) / durationMs);
        setValue(Math.round(to * (1 - (1 - progress) ** 3)));
        if (progress < 1) frame = requestAnimationFrame(tick);
      };
      frame = requestAnimationFrame(tick);
    });
    observer.observe(element);
    return () => {
      observer.disconnect();
      cancelAnimationFrame(frame);
    };
  }, [reduced, to, durationMs]);

  return <span ref={box}>{reduced ? to : value}</span>;
}

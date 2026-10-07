"use client";

import { useLayoutEffect, useMemo, useRef } from "react";
import { useReducedMotion } from "framer-motion";
import { gsap } from "gsap";

type AnimatedCounterProps = {
  value: number;
  decimals?: number;
  prefix?: string;
  suffix?: string;
};

export function AnimatedCounter({ value, decimals = 0, prefix = "", suffix = "" }: AnimatedCounterProps) {
  const reducedMotion = useReducedMotion();
  const precision = Math.min(2, Math.max(0, decimals));
  const target = Number.isFinite(value) ? value : 0;
  const formatter = useMemo(() => new Intl.NumberFormat("pt-BR", {
    minimumFractionDigits: precision,
    maximumFractionDigits: precision,
  }), [precision]);
  const format = (current: number) => `${prefix}${formatter.format(current)}${suffix}`;
  const displayRef = useRef<HTMLSpanElement>(null);
  const currentRef = useRef(target);
  const targetRef = useRef(target);
  const tweenRef = useRef<gsap.core.Tween | null>(null);

  useLayoutEffect(() => {
    const display = displayRef.current;
    if (!display) return;
    tweenRef.current?.kill();

    if (targetRef.current === target || reducedMotion) {
      currentRef.current = target;
      targetRef.current = target;
      display.textContent = format(target);
      return;
    }

    targetRef.current = target;
    const counter = { value: currentRef.current };
    display.textContent = format(counter.value);
    tweenRef.current = gsap.to(counter, {
      value: target,
      duration: 0.7,
      ease: "power3.out",
      overwrite: true,
      onUpdate: () => {
        currentRef.current = counter.value;
        display.textContent = format(counter.value);
      },
      onComplete: () => {
        currentRef.current = target;
        display.textContent = format(target);
        tweenRef.current = null;
      },
    });

    return () => { tweenRef.current?.kill(); };
  }, [target, precision, prefix, suffix, formatter, reducedMotion]);

  return <span className="animated-counter" role="text" aria-label={format(target)}><span ref={displayRef} aria-hidden="true">{format(target)}</span></span>;
}

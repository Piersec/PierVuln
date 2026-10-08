"use client";

import { useEffect, useState } from "react";

const key = "piervuln:presentation-mode";
const eventName = "piervuln:presentation-mode-change";
let fallbackMode = false;

export function usePresentationMode() {
  const [enabled, setEnabled] = useState(false);

  useEffect(() => {
    const read = () => {
      try { setEnabled(sessionStorage.getItem(key) === "on"); }
      catch { setEnabled(fallbackMode); }
    };
    read();
    window.addEventListener(eventName, read);
    return () => window.removeEventListener(eventName, read);
  }, []);

  function setPresentationMode(next: boolean) {
    fallbackMode = next;
    try { sessionStorage.setItem(key, next ? "on" : "off"); } catch { /* In-memory mode still works. */ }
    window.dispatchEvent(new Event(eventName));
  }

  return { presentationMode: enabled, setPresentationMode };
}

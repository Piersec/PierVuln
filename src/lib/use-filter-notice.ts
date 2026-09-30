"use client";

import { useEffect, useRef } from "react";
import { useSiteNotifications } from "@/src/components/site-notifications";

export function useFilterNotice(key: string, detail: string, enabled = true) {
  const { notify } = useSiteNotifications();
  const previous = useRef(detail);
  useEffect(() => {
    if (!enabled) { previous.current = detail; return; }
    if (previous.current === detail) return;
    const timer = setTimeout(() => {
      previous.current = detail;
      notify({ title: "Seleção atualizada.", detail, key });
    }, 600);
    return () => clearTimeout(timer);
  }, [detail, enabled, key, notify]);
}

export function useErrorNotice(message: string, key: string) {
  const { notify } = useSiteNotifications();
  useEffect(() => { if (message) notify({ title: message, error: true, key }); }, [key, message, notify]);
}

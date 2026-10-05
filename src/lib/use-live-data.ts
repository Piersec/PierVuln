"use client";

import { useEffect, useRef, useState } from "react";
import type { SupabaseClient } from "@supabase/supabase-js";
import { isSyncBoundary } from "./live-events";

export function useLiveData(client: SupabaseClient | null, userId: string | undefined, busy: boolean) {
  const [revision, setRevision] = useState(0);
  const [connected, setConnected] = useState(false);
  const [now, setNow] = useState(() => Date.now());
  const busyRef = useRef(busy);
  const pending = useRef(false);
  busyRef.current = busy;

  useEffect(() => {
    if (!busy && pending.current) {
      pending.current = false;
      setRevision((value) => value + 1);
    }
  }, [busy]);

  useEffect(() => {
    if (!client || !userId) return;
    let active = true;
    let subscribedOnce = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    setConnected(false);
    const request = () => {
      if (!active || document.visibilityState === "hidden") return;
      if (timer) return;
      timer = setTimeout(() => {
        timer = undefined;
        if (!active) return;
        if (busyRef.current) pending.current = true;
        else setRevision((value) => value + 1);
      }, 1000);
    };
    const channel = client.channel(`operational-${userId}`)
      .on("postgres_changes", { event: "*", schema: "public", table: "sync_runs" }, (payload) => {
        // Progress updates arrive for every page; refresh only at run boundaries.
        const next = payload.new as { status?: string };
        if (isSyncBoundary(payload.eventType, next)) request();
      })
      .on("postgres_changes", { event: "INSERT", schema: "public", table: "finding_events" }, request)
      .on("postgres_changes", { event: "*", schema: "public", table: "vulnerability_comments" }, request)
      .subscribe((status) => {
        if (!active) return;
        setConnected(status === "SUBSCRIBED");
        if (status === "SUBSCRIBED") {
          if (subscribedOnce) request();
          subscribedOnce = true;
        }
      });
    const clock = setInterval(() => setNow(Date.now()), 15_000);
    const fallback = setInterval(request, 120_000);
    document.addEventListener("visibilitychange", request);
    window.addEventListener("focus", request);
    window.addEventListener("online", request);
    return () => {
      active = false;
      pending.current = false;
      if (timer) clearTimeout(timer);
      clearInterval(clock);
      clearInterval(fallback);
      document.removeEventListener("visibilitychange", request);
      window.removeEventListener("focus", request);
      window.removeEventListener("online", request);
      void client.removeChannel(channel);
    };
  }, [client, userId]);

  return { revision, connected, now };
}

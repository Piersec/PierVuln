"use client";

import { useEffect } from "react";
import { useSiteNotifications } from "@/src/components/site-notifications";

export function useErrorNotice(message: string, key: string) {
  const { notify } = useSiteNotifications();
  useEffect(() => { if (message) notify({ title: message, error: true, key }); }, [key, message, notify]);
}

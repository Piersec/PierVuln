"use client";

import { useEffect, useState } from "react";
import { getSupabaseBrowserClient } from "@/src/lib/supabase/client";

export const profileUpdatedEvent = "piervuln:profile-updated";

export function UserAvatar({ userId, fallback, large = false }: { userId: string; fallback: string; large?: boolean }) {
  const client = getSupabaseBrowserClient();
  const [image, setImage] = useState<{ userId: string; url: string } | null>(null);

  useEffect(() => {
    if (!client || !userId) return;
    let active = true;
    let generation = 0;
    let currentUrl: string | null = null;
    async function load() {
      const request = ++generation;
      const { data } = await client!.from("user_profiles").select("avatar_path").eq("id", userId).single();
      if (!active || request !== generation) return;
      if (!data?.avatar_path) {
        if (currentUrl) URL.revokeObjectURL(currentUrl);
        currentUrl = null;
        setImage(null);
        return;
      }
      const image = await client!.storage.from("profile-avatars").download(data.avatar_path);
      if (!active || request !== generation || !image.data) return;
      if (currentUrl) URL.revokeObjectURL(currentUrl);
      currentUrl = URL.createObjectURL(image.data);
      setImage({ userId, url: currentUrl });
    }
    void load();
    window.addEventListener(profileUpdatedEvent, load);
    return () => {
      active = false;
      window.removeEventListener(profileUpdatedEvent, load);
      if (currentUrl) URL.revokeObjectURL(currentUrl);
    };
  }, [client, userId]);

  return <span className={`avatar user-avatar${large ? " is-large" : ""}`} aria-label="Foto de perfil">
    {image?.userId === userId ? <img src={image.url} alt="" /> : fallback.slice(0, 1).toLocaleUpperCase("pt-BR") || "U"}
  </span>;
}

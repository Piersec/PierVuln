import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { clearTemporaryAuthFlow, grantTemporaryAuthFlow } from "@/src/lib/temporary-auth-flow";

let browserClient: SupabaseClient | null = null;

export function getSupabaseBrowserClient(): SupabaseClient | null {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
  if (!url || !key) return null;

  if (!browserClient) {
    browserClient = createClient(url, key, {
      auth: {
        autoRefreshToken: true,
        persistSession: true,
        detectSessionInUrl: true,
      },
    });
    if (typeof window !== "undefined") {
      browserClient.auth.onAuthStateChange((event, session) => {
        if (event === "PASSWORD_RECOVERY" && session) grantTemporaryAuthFlow("recovery", session.user.id);
        if (event === "SIGNED_OUT") clearTemporaryAuthFlow();
      });
    }
  }
  return browserClient;
}

import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import { clearTemporaryAuthFlow, grantTemporaryAuthFlow } from "@/src/lib/temporary-auth-flow";
import { clearOverviewCache } from "@/src/lib/vulnerability-overview";
import { withRequestTimeout } from "@/src/lib/request-timeout";

let browserClient: SupabaseClient | null = null;

export function getSupabaseBrowserClient(): SupabaseClient | null {
  const url = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const key = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;
  if (!url || !key) return null;

  if (!browserClient) {
    browserClient = createClient(url, key, {
      global: {
        fetch: (input, init) => withRequestTimeout(
          (signal) => fetch(input, { ...init, signal }),
          init?.signal ?? (input instanceof Request ? input.signal : undefined),
        ),
      },
      auth: {
        autoRefreshToken: true,
        persistSession: true,
        detectSessionInUrl: true,
      },
    });
    if (typeof window !== "undefined") {
      browserClient.auth.onAuthStateChange((event, session) => {
        if (event === "PASSWORD_RECOVERY" && session) grantTemporaryAuthFlow("recovery", session.user.id);
        if (event === "SIGNED_OUT") {
          clearTemporaryAuthFlow();
          clearOverviewCache();
        }
      });
    }
  }
  return browserClient;
}

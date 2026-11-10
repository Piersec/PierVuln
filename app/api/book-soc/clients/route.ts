import { requireInternal } from "@/src/lib/book-soc/auth";
import { loadClients, publicClients } from "@/src/lib/book-soc/clients";

export const dynamic = "force-dynamic";

// Lista só id e nome. Endereço, usuário e senha nunca saem do servidor.
export async function GET(request: Request) {
  const denied = await requireInternal(request);
  if (denied) return denied;
  return Response.json({ clients: publicClients(loadClients()) });
}

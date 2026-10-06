const storagePrefix = "piervuln:selected-company:v1:";

export function readCompanySelection(userId: string): string | null {
  try { return localStorage.getItem(`${storagePrefix}${userId}`); }
  catch { return null; }
}

export function writeCompanySelection(userId: string, companyId: string) {
  try { localStorage.setItem(`${storagePrefix}${userId}`, companyId || "all"); }
  catch { /* Navigation links preserve the selection when storage is unavailable. */ }
}

export function resolveCompanySelection(companies: { id: string }[], candidate: string | null | undefined): string {
  if (candidate === "all") return "";
  return companies.some((company) => company.id === candidate) ? candidate! : companies[0]?.id ?? "";
}

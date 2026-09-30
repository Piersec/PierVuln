import { AdminWorkspace } from "@/src/components/admin-console";

export default function AdminLayout({ children }: { children: React.ReactNode }) {
  return <AdminWorkspace>{children}</AdminWorkspace>;
}

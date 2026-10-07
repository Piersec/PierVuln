"use client";

import { Dropdown, Label } from "@heroui/react";
import { usePathname, useRouter } from "next/navigation";
import { UserAvatar } from "@/src/components/user-avatar";
import { NavSymbol } from "@/src/components/ui/nav-symbol";
import { visibleText } from "@/src/lib/visible-text";

const links = [
  { href: "/status", label: "Status", kind: "status" },
  { href: "/admin", label: "Administração", kind: "admin" },
  { href: "/settings", label: "Configurações", kind: "settings" },
] as const;

export function ProfileMenu({ userId, fallback, isInternal }: {
  userId: string; fallback: string; isInternal: boolean;
}) {
  const pathname = usePathname();
  const router = useRouter();
  const items = links.filter((item) => isInternal || item.kind !== "admin");

  return <Dropdown>
    <Dropdown.Trigger className="profile-menu-trigger" aria-label="Menu de perfil">
      <UserAvatar userId={userId} fallback={fallback} />
    </Dropdown.Trigger>
    <Dropdown.Popover className="profile-menu-popover" placement="top start" offset={10}>
      <div className="profile-menu-heading"><strong>{visibleText(fallback)}</strong><span>{isInternal ? "Equipe Pier" : "Minha conta"}</span></div>
      <Dropdown.Menu aria-label="Navegação da conta" onAction={(key) => router.push(String(key))}>
        {items.map((item) => <Dropdown.Item key={item.href} id={item.href} textValue={item.label}
          aria-current={pathname === item.href || pathname.startsWith(`${item.href}/`) ? "page" : undefined}>
          <NavSymbol kind={item.kind} /><Label>{item.label}</Label>
        </Dropdown.Item>)}
      </Dropdown.Menu>
    </Dropdown.Popover>
  </Dropdown>;
}

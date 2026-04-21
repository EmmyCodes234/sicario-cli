"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

const NAV_ITEMS = [
  { href: "/", label: "Overview", icon: "📊" },
  { href: "/priority", label: "Priority", icon: "🔥" },
  { href: "/findings", label: "Findings", icon: "🔍" },
  { href: "/analytics", label: "Analytics", icon: "📈" },
  { href: "/projects", label: "Projects", icon: "📁" },
  { href: "/scans", label: "Scans", icon: "⚡" },
  { href: "/settings", label: "Settings", icon: "⚙️" },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">🛡️ Sicario</div>
      <nav className="sidebar-nav">
        {NAV_ITEMS.map((item) => (
          <Link
            key={item.href}
            href={item.href}
            className={`sidebar-link ${pathname === item.href ? "active" : ""}`}
          >
            <span>{item.icon}</span>
            {item.label}
          </Link>
        ))}
      </nav>
    </aside>
  );
}

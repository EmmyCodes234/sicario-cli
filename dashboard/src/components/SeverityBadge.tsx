import type { Severity } from "@/lib/api";

export function SeverityBadge({ severity }: { severity: Severity }) {
  const cls = `badge badge-${severity.toLowerCase()}`;
  return <span className={cls}>{severity}</span>;
}

"use client";

import { useQuery } from "convex/react";
import { findingsList } from "@/lib/convexApi";
import { SeverityBadge } from "@/components/SeverityBadge";
import Link from "next/link";

/**
 * Priority tab — default developer landing view.
 * Critical/High + high confidence (≥0.8) + reachable findings.
 * Req 21.24, 21.25
 */
export default function PriorityPage() {
  const result = useQuery(findingsList, { perPage: 200, confidenceMin: 0.8 });
  const findings = (result?.items ?? []).filter(
    (f: any) =>
      (f.severity === "Critical" || f.severity === "High") &&
      f.reachable &&
      f.confidence_score >= 0.8 &&
      f.triage_state !== "Fixed" &&
      f.triage_state !== "Ignored" &&
      f.triage_state !== "AutoIgnored"
  );

  if (result === undefined) return <p>Loading priority findings...</p>;

  return (
    <>
      <div className="page-header">
        <h1>🔥 Priority Findings</h1>
        <p>Critical/High severity, high confidence, reachable — requires immediate attention</p>
      </div>

      {findings.length === 0 ? (
        <div className="card"><p style={{ color: "var(--text-muted)" }}>No priority findings. Your codebase looks clean! 🎉</p></div>
      ) : (
        <div className="card">
          <table>
            <thead><tr><th>Severity</th><th>Confidence</th><th>Rule</th><th>File</th><th>Line</th><th>CWE</th><th>State</th><th></th></tr></thead>
            <tbody>
              {findings.map((f: any) => (
                <tr key={f.id}>
                  <td><SeverityBadge severity={f.severity} /></td>
                  <td>{Math.round(f.confidence_score * 100)}%</td>
                  <td>{f.rule_id}</td>
                  <td style={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{f.file_path}</td>
                  <td>{f.line}</td>
                  <td>{f.cwe_id || "—"}</td>
                  <td>{f.triage_state}</td>
                  <td><Link href={`/findings/${f.id}`}>View →</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}

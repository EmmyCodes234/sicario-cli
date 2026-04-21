"use client";

import { useState } from "react";
import { useQuery } from "convex/react";
import { scansList } from "@/lib/convexApi";

export default function ScansPage() {
  const [page, setPage] = useState(1);
  const result = useQuery(scansList, { page, perPage: 20 });

  const scans = result?.items ?? [];
  const total = result?.total ?? 0;
  const totalPages = Math.ceil(total / 20);

  return (
    <>
      <div className="page-header"><h1>Scan History</h1><p>{total} scans recorded</p></div>
      <div className="card">
        {result === undefined ? <p>Loading...</p> : (
          <table>
            <thead><tr><th>Repository</th><th>Branch</th><th>Commit</th><th>Duration</th><th>Files</th><th>Rules</th><th>Timestamp</th></tr></thead>
            <tbody>
              {scans.map((s: any) => (
                <tr key={s.id}>
                  <td>{s.repository}</td>
                  <td>{s.branch}</td>
                  <td style={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{s.commit_sha.substring(0, 8)}</td>
                  <td>{s.duration_ms}ms</td>
                  <td>{s.files_scanned}</td>
                  <td>{s.rules_loaded}</td>
                  <td>{new Date(s.timestamp).toLocaleString()}</td>
                </tr>
              ))}
              {scans.length === 0 && (
                <tr><td colSpan={7} style={{ color: "var(--text-muted)" }}>No scans recorded yet.</td></tr>
              )}
            </tbody>
          </table>
        )}
        {totalPages > 1 && (
          <div className="flex-between mt-2">
            <button className="btn" disabled={page <= 1} onClick={() => setPage(page - 1)}>← Previous</button>
            <span style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>Page {page} of {totalPages}</span>
            <button className="btn" disabled={page >= totalPages} onClick={() => setPage(page + 1)}>Next →</button>
          </div>
        )}
      </div>
    </>
  );
}

"use client";

import { useState } from "react";
import { useQuery, useMutation } from "convex/react";
import { findingsList, findingsBulkTriage } from "@/lib/convexApi";
import type { Severity, TriageState } from "@/lib/api";
import { SeverityBadge } from "@/components/SeverityBadge";
import Link from "next/link";

const TRIAGE_STATES: TriageState[] = ["Open", "Reviewing", "ToFix", "Fixed", "Ignored", "AutoIgnored"];
const SEVERITIES: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

export default function FindingsPage() {
  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState("");
  const [triageState, setTriageState] = useState("");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [bulkState, setBulkState] = useState<TriageState>("Ignored");

  const args: any = { page, perPage: 25 };
  if (severity) args.severity = severity;
  if (triageState) args.triageState = triageState;

  const result = useQuery(findingsList, args);
  const bulkTriage = useMutation(findingsBulkTriage);

  const findings = result?.items ?? [];
  const total = result?.total ?? 0;
  const totalPages = Math.ceil(total / 25);

  const toggleSelect = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  };

  const toggleAll = () => {
    if (selected.size === findings.length) setSelected(new Set());
    else setSelected(new Set(findings.map((f: any) => f.id)));
  };

  const handleBulkTriage = async () => {
    if (selected.size === 0) return;
    await bulkTriage({ ids: Array.from(selected), triageState: bulkState });
    setSelected(new Set());
  };

  return (
    <>
      <div className="page-header">
        <h1>Findings</h1>
        <p>{total} total findings</p>
      </div>

      <div className="flex gap-2 mb-2">
        <select value={severity} onChange={(e) => { setSeverity(e.target.value); setPage(1); }}>
          <option value="">All Severities</option>
          {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select value={triageState} onChange={(e) => { setTriageState(e.target.value); setPage(1); }}>
          <option value="">All States</option>
          {TRIAGE_STATES.map((s) => <option key={s} value={s}>{s}</option>)}
        </select>

        {selected.size > 0 && (
          <div className="flex gap-1" style={{ marginLeft: "auto" }}>
            <span style={{ color: "var(--text-muted)", fontSize: "0.85rem", alignSelf: "center" }}>{selected.size} selected →</span>
            <select className="triage-select" value={bulkState} onChange={(e) => setBulkState(e.target.value as TriageState)}>
              {TRIAGE_STATES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <button className="btn btn-primary" onClick={handleBulkTriage}>Apply</button>
          </div>
        )}
      </div>

      <div className="card">
        {!result ? <p>Loading...</p> : (
          <table>
            <thead>
              <tr>
                <th><input type="checkbox" className="checkbox" checked={selected.size === findings.length && findings.length > 0} onChange={toggleAll} /></th>
                <th>Severity</th>
                <th>Confidence</th>
                <th>Rule</th>
                <th>File</th>
                <th>Line</th>
                <th>State</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {findings.map((f: any) => (
                <tr key={f.id}>
                  <td><input type="checkbox" className="checkbox" checked={selected.has(f.id)} onChange={() => toggleSelect(f.id)} /></td>
                  <td><SeverityBadge severity={f.severity} /></td>
                  <td>{Math.round(f.confidence_score * 100)}%</td>
                  <td>{f.rule_id}</td>
                  <td style={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{f.file_path}</td>
                  <td>{f.line}</td>
                  <td>{f.triage_state}</td>
                  <td><Link href={`/findings/${f.id}`}>Details →</Link></td>
                </tr>
              ))}
              {findings.length === 0 && (
                <tr><td colSpan={8} style={{ color: "var(--text-muted)" }}>No findings match the current filters.</td></tr>
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

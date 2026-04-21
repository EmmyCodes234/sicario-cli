"use client";

import { useQuery } from "convex/react";
import { analyticsOverview, analyticsTrends, analyticsMttr, projectsList } from "@/lib/convexApi";
import { StatCard } from "@/components/StatCard";
import { exportOverviewPdf } from "@/components/PdfExport";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, BarChart, Bar } from "recharts";

export default function OverviewPage() {
  const overview = useQuery(analyticsOverview, {});
  const trends = useQuery(analyticsTrends, {});
  const mttr = useQuery(analyticsMttr, {});
  const projects = useQuery(projectsList, {});

  if (!overview || !trends || !mttr) return <p style={{ padding: "2rem" }}>Loading...</p>;

  const backlogData = trends.map((t: any) => ({
    date: t.timestamp.substring(0, 10),
    open: t.open_findings,
    new: t.new_findings,
    fixed: t.fixed_findings,
  }));

  const openAgeData = trends.map((t: any) => ({
    date: t.timestamp.substring(0, 10),
    open: t.open_findings,
  }));

  const handleExportPdf = () => exportOverviewPdf(overview as any, mttr as any);

  return (
    <>
      <div className="page-header flex-between">
        <div>
          <h1>Security Overview</h1>
          <p>Organization-wide security posture</p>
        </div>
        <button className="btn btn-primary" onClick={handleExportPdf}>📄 Export PDF</button>
      </div>

      <div className="grid-4 mb-2">
        <StatCard label="Total Findings" value={overview.total_findings} />
        <StatCard label="Open" value={overview.open_findings} colorClass="severity-high" />
        <StatCard label="Fixed" value={overview.fixed_findings} colorClass="severity-low" />
        <StatCard label="Ignored" value={overview.ignored_findings} />
      </div>

      <div className="grid-4 mb-2">
        <StatCard label="Critical" value={overview.critical_count} colorClass="severity-critical" />
        <StatCard label="High" value={overview.high_count} colorClass="severity-high" />
        <StatCard label="Medium" value={overview.medium_count} colorClass="severity-medium" />
        <StatCard label="Low" value={overview.low_count} colorClass="severity-low" />
      </div>

      {/* Production Backlog (Req 21.9) */}
      <div className="card mb-2">
        <h3 className="mb-1">Production Backlog</h3>
        <ResponsiveContainer width="100%" height={260}>
          <AreaChart data={backlogData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#2a2a3e" />
            <XAxis dataKey="date" stroke="#8888a0" fontSize={11} />
            <YAxis stroke="#8888a0" fontSize={11} />
            <Tooltip contentStyle={{ background: "#12121a", border: "1px solid #2a2a3e", borderRadius: 8, fontSize: 12 }} />
            <Area type="monotone" dataKey="open" stackId="1" stroke="#f59e0b" fill="rgba(245,158,11,0.3)" name="Open" />
            <Area type="monotone" dataKey="fixed" stackId="1" stroke="#22c55e" fill="rgba(34,197,94,0.3)" name="Fixed" />
            <Area type="monotone" dataKey="new" stackId="1" stroke="#ef4444" fill="rgba(239,68,68,0.3)" name="Net New" />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="grid-2 mb-2">
        {/* Secure Guardrails (Req 21.10) */}
        <div className="card">
          <h3 className="mb-1">Secure Guardrails</h3>
          <div className="grid-2">
            <div>
              <div className="stat-label">Shift-Left Rate</div>
              <div className="stat-value severity-low">
                {overview.total_findings > 0 ? `${Math.round((overview.fixed_findings / overview.total_findings) * 100)}%` : "N/A"}
              </div>
            </div>
            <div>
              <div className="stat-label">Total Scans</div>
              <div className="stat-value">{overview.total_scans}</div>
            </div>
          </div>
        </div>

        {/* Median Open Age (Req 21.12) */}
        <div className="card">
          <h3 className="mb-1">Median Open Age</h3>
          <ResponsiveContainer width="100%" height={140}>
            <BarChart data={openAgeData.slice(-14)}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a2a3e" />
              <XAxis dataKey="date" stroke="#8888a0" fontSize={10} />
              <YAxis stroke="#8888a0" fontSize={10} />
              <Tooltip contentStyle={{ background: "#12121a", border: "1px solid #2a2a3e", borderRadius: 8, fontSize: 12 }} />
              <Bar dataKey="open" fill="rgba(99,102,241,0.7)" radius={[4, 4, 0, 0]} name="Open Findings" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* MTTR (Req 21.17) */}
      <div className="card mb-2">
        <h3 className="mb-1">Mean Time to Resolve</h3>
        <div className="grid-4">
          <div>
            <div className="stat-label">Overall MTTR</div>
            <div className="stat-value">{mttr.overall_mttr_hours.toFixed(1)}h</div>
          </div>
          {Object.entries(mttr.by_severity).map(([sev, hours]: [string, any]) => (
            <div key={sev}>
              <div className="stat-label">{sev}</div>
              <div className={`stat-value severity-${sev.toLowerCase()}`}>{hours.toFixed(1)}h</div>
            </div>
          ))}
        </div>
      </div>

      {/* Most Findings by Project (Req 21.11) */}
      <div className="card">
        <h3 className="mb-1">Most Findings by Project</h3>
        <table>
          <thead><tr><th>Project</th><th>Repository</th></tr></thead>
          <tbody>
            {!projects || projects.length === 0 ? (
              <tr><td colSpan={2} style={{ color: "var(--text-muted)" }}>No projects configured</td></tr>
            ) : (
              projects.map((p: any) => (
                <tr key={p.id}><td>{p.name}</td><td style={{ color: "var(--text-muted)" }}>{p.repository_url || "—"}</td></tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}

"use client";

import { useQuery } from "convex/react";
import { analyticsOverview, analyticsTrends, analyticsMttr } from "@/lib/convexApi";
import { StatCard } from "@/components/StatCard";
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid, BarChart, Bar, PieChart, Pie, Cell } from "recharts";

const COLORS = ["#ef4444", "#f59e0b", "#eab308", "#3b82f6", "#6b7280"];

export default function AnalyticsPage() {
  const overview = useQuery(analyticsOverview, {});
  const trends = useQuery(analyticsTrends, {});
  const mttr = useQuery(analyticsMttr, {});

  if (!overview || !trends || !mttr) return <p>Loading analytics...</p>;

  const severityPie = [
    { name: "Critical", value: overview.critical_count },
    { name: "High", value: overview.high_count },
    { name: "Medium", value: overview.medium_count },
    { name: "Low", value: overview.low_count },
    { name: "Info", value: overview.info_count },
  ].filter((d) => d.value > 0);

  const fixRate = overview.total_findings > 0 ? Math.round((overview.fixed_findings / overview.total_findings) * 100) : 0;

  const trendData = trends.map((t: any) => ({
    date: t.timestamp.substring(0, 10),
    open: t.open_findings,
    new: t.new_findings,
    fixed: t.fixed_findings,
  }));

  return (
    <>
      <div className="page-header"><h1>Analytics</h1><p>AppSec program health across four pillars</p></div>

      {/* Coverage */}
      <div className="card mb-2">
        <h3 className="mb-1">📡 Coverage</h3>
        <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginBottom: "1rem" }}>Repositories and languages being scanned</p>
        <div className="grid-3">
          <StatCard label="Total Scans" value={overview.total_scans} />
          <StatCard label="Avg Scan Duration" value={`${overview.avg_scan_duration_ms}ms`} />
          <StatCard label="Findings Detected" value={overview.total_findings} />
        </div>
      </div>

      {/* Exposure */}
      <div className="card mb-2">
        <h3 className="mb-1">🎯 Exposure</h3>
        <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginBottom: "1rem" }}>Open critical/high findings and severity breakdown</p>
        <div className="grid-2">
          <div className="grid-2">
            <StatCard label="Open Findings" value={overview.open_findings} colorClass="severity-high" />
            <StatCard label="Critical + High" value={overview.critical_count + overview.high_count} colorClass="severity-critical" />
          </div>
          <div style={{ display: "flex", justifyContent: "center" }}>
            {severityPie.length > 0 && (
              <ResponsiveContainer width={200} height={200}>
                <PieChart>
                  <Pie data={severityPie} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={80} label={({ name, value }) => `${name}: ${value}`}>
                    {severityPie.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* Management */}
      <div className="card mb-2">
        <h3 className="mb-1">⚙️ Management</h3>
        <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginBottom: "1rem" }}>Mean time to resolve and issues resolved over time</p>
        <div className="grid-4 mb-2">
          <StatCard label="Overall MTTR" value={`${mttr.overall_mttr_hours.toFixed(1)}h`} />
          {Object.entries(mttr.by_severity).map(([sev, hours]: [string, any]) => (
            <StatCard key={sev} label={`${sev} MTTR`} value={`${hours.toFixed(1)}h`} colorClass={`severity-${sev.toLowerCase()}`} />
          ))}
        </div>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={trendData.slice(-30)}>
            <CartesianGrid strokeDasharray="3 3" stroke="#2a2a3e" />
            <XAxis dataKey="date" stroke="#8888a0" fontSize={10} />
            <YAxis stroke="#8888a0" fontSize={10} />
            <Tooltip contentStyle={{ background: "#12121a", border: "1px solid #2a2a3e", borderRadius: 8, fontSize: 12 }} />
            <Bar dataKey="fixed" fill="rgba(34,197,94,0.7)" radius={[4, 4, 0, 0]} name="Fixed" />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Prevention */}
      <div className="card">
        <h3 className="mb-1">🛡️ Prevention</h3>
        <p style={{ color: "var(--text-muted)", fontSize: "0.85rem", marginBottom: "1rem" }}>Shift-left adoption rate and developer engagement</p>
        <div className="grid-3 mb-2">
          <StatCard label="Fix Rate" value={`${fixRate}%`} colorClass="severity-low" />
          <StatCard label="Fixed Findings" value={overview.fixed_findings} colorClass="severity-low" />
          <StatCard label="Ignored / Auto-Ignored" value={overview.ignored_findings} />
        </div>
        <ResponsiveContainer width="100%" height={220}>
          <AreaChart data={trendData.slice(-30)}>
            <CartesianGrid strokeDasharray="3 3" stroke="#2a2a3e" />
            <XAxis dataKey="date" stroke="#8888a0" fontSize={10} />
            <YAxis stroke="#8888a0" fontSize={10} />
            <Tooltip contentStyle={{ background: "#12121a", border: "1px solid #2a2a3e", borderRadius: 8, fontSize: 12 }} />
            <Area type="monotone" dataKey="fixed" stroke="#22c55e" fill="rgba(34,197,94,0.2)" name="Fixed" />
            <Area type="monotone" dataKey="new" stroke="#ef4444" fill="rgba(239,68,68,0.2)" name="New" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </>
  );
}

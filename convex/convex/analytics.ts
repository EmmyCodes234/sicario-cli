import { query } from "./_generated/server";
import { v } from "convex/values";

export const overview = query({
  args: {},
  handler: async (ctx) => {
    const findings = await ctx.db.query("findings").collect();
    const scans = await ctx.db.query("scans").collect();

    let total = 0, open = 0, fixed = 0, ignored = 0;
    let critical = 0, high = 0, medium = 0, low = 0, info = 0;

    for (const f of findings) {
      total++;
      switch (f.triageState) {
        case "Open": case "Reviewing": case "ToFix": open++; break;
        case "Fixed": fixed++; break;
        case "Ignored": case "AutoIgnored": ignored++; break;
        default: open++; break;
      }
      switch (f.severity) {
        case "Critical": critical++; break;
        case "High": high++; break;
        case "Medium": medium++; break;
        case "Low": low++; break;
        case "Info": info++; break;
      }
    }

    const totalScans = scans.length;
    const avgDuration = totalScans > 0
      ? Math.round(scans.reduce((sum, s) => sum + s.durationMs, 0) / totalScans)
      : 0;

    return {
      total_findings: total,
      open_findings: open,
      fixed_findings: fixed,
      ignored_findings: ignored,
      critical_count: critical,
      high_count: high,
      medium_count: medium,
      low_count: low,
      info_count: info,
      total_scans: totalScans,
      avg_scan_duration_ms: avgDuration,
    };
  },
});

export const trends = query({
  args: {
    from: v.optional(v.string()),
    to: v.optional(v.string()),
    interval: v.optional(v.string()),
  },
  handler: async (ctx) => {
    const findings = await ctx.db.query("findings").collect();

    const byDay: Record<string, { open: number; new: number; fixed: number }> = {};

    for (const f of findings) {
      const day = f.createdAt.substring(0, 10); // YYYY-MM-DD
      if (!byDay[day]) byDay[day] = { open: 0, new: 0, fixed: 0 };
      byDay[day].new++;
      switch (f.triageState) {
        case "Open": case "Reviewing": case "ToFix":
          byDay[day].open++; break;
        case "Fixed":
          byDay[day].fixed++; break;
      }
    }

    return Object.entries(byDay)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([day, counts]) => ({
        timestamp: `${day}T00:00:00Z`,
        open_findings: counts.open,
        new_findings: counts.new,
        fixed_findings: counts.fixed,
      }));
  },
});

export const mttr = query({
  args: {},
  handler: async (ctx) => {
    const findings = await ctx.db.query("findings").collect();

    let totalHours = 0;
    let count = 0;
    const bySeverity: Record<string, { hours: number; count: number }> = {};

    for (const f of findings) {
      if (f.triageState === "Fixed") {
        const created = new Date(f.createdAt).getTime();
        const updated = new Date(f.updatedAt).getTime();
        const hours = (updated - created) / (1000 * 60 * 60);
        totalHours += hours;
        count++;

        if (!bySeverity[f.severity]) bySeverity[f.severity] = { hours: 0, count: 0 };
        bySeverity[f.severity].hours += hours;
        bySeverity[f.severity].count++;
      }
    }

    const overall = count > 0 ? totalHours / count : 0;
    const bySev: Record<string, number> = {};
    for (const [sev, data] of Object.entries(bySeverity)) {
      bySev[sev] = data.count > 0 ? data.hours / data.count : 0;
    }

    return {
      overall_mttr_hours: overall,
      by_severity: bySev,
    };
  },
});

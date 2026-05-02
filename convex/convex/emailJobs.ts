import { internalAction, internalQuery } from "./_generated/server";
import { internal } from "./_generated/api";
import { v } from "convex/values";

// ── Internal actions ──────────────────────────────────────────────────────────

export const sendWeeklyDigests = internalAction({
  args: {},
  handler: async (ctx) => {
    // Get all orgs
    const orgs: any[] = await ctx.runQuery(internal.emailJobs.getAllOrgs);
    for (const org of orgs) {
      try {
        const stats: any = await ctx.runQuery(internal.emailJobs.getWeeklyStats, { orgId: org.orgId });
        const admins: any[] = await ctx.runQuery(internal.emailJobs.getOrgAdminEmails, { orgId: org.orgId });
        const { sendWeeklyDigestEmail } = await import("./emails");
        for (const admin of admins) {
          if (admin.email) {
            await sendWeeklyDigestEmail(admin.email, org.name, stats);
          }
        }
      } catch (err) {
        console.error(`Weekly digest failed for org ${org.orgId}:`, err);
      }
    }
  },
});

export const sendInactivityNudges = internalAction({
  args: {},
  handler: async (ctx) => {
    const staleUsers: any[] = await ctx.runQuery(internal.emailJobs.getUsersWithNoRecentScan, { thresholdDays: 14 });
    const { sendInactivityNudgeEmail } = await import("./emails");
    for (const u of staleUsers) {
      try {
        if (u.email) {
          await sendInactivityNudgeEmail(u.email, u.name ?? u.email.split("@")[0], u.daysSinceLastScan);
        }
      } catch (err) {
        console.error(`Inactivity nudge failed for ${u.email}:`, err);
      }
    }
  },
});

// ── Internal queries ──────────────────────────────────────────────────────────

export const getAllOrgs = internalQuery({
  args: {},
  handler: async (ctx) => {
    return await ctx.db.query("organizations").collect();
  },
});

export const getWeeklyStats = internalQuery({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const now = Date.now();
    const weekAgo = new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString();
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .collect();
    const scans = await ctx.db
      .query("scans")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .collect();

    const newFindings = findings.filter((f) => f.createdAt >= weekAgo).length;
    const criticalOpen = findings.filter(
      (f) =>
        f.severity === "Critical" &&
        (f.triageState === "Open" || f.triageState === "Reviewing" || f.triageState === "ToFix")
    ).length;
    const highOpen = findings.filter(
      (f) =>
        f.severity === "High" &&
        (f.triageState === "Open" || f.triageState === "Reviewing" || f.triageState === "ToFix")
    ).length;
    const fixed = findings.filter(
      (f) =>
        f.updatedAt >= weekAgo &&
        (f.triageState === "Fixed" || f.triageState === "AutoFixed")
    ).length;
    const scansRun = scans.filter((s) => s.createdAt >= weekAgo).length;

    // Top project by new findings
    const projectCounts: Record<string, number> = {};
    for (const f of findings.filter((f) => f.createdAt >= weekAgo)) {
      if (f.projectId) {
        projectCounts[f.projectId] = (projectCounts[f.projectId] ?? 0) + 1;
      }
    }
    let topProjectId: string | null = null;
    let topCount = 0;
    for (const [pid, count] of Object.entries(projectCounts)) {
      if (count > topCount) {
        topCount = count;
        topProjectId = pid;
      }
    }
    let topProject: string | null = null;
    if (topProjectId) {
      const proj = await ctx.db
        .query("projects")
        .withIndex("by_projectId", (q) => q.eq("projectId", topProjectId!))
        .first();
      topProject = proj?.name ?? null;
    }

    return { newFindings, criticalOpen, highOpen, fixed, scansRun, topProject };
  },
});

export const getOrgAdminEmails = internalQuery({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const memberships = await ctx.db
      .query("memberships")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .collect();
    const admins = memberships.filter((m) => m.role === "admin");
    const result: { email: string | null; name: string | null }[] = [];
    for (const m of admins) {
      try {
        const user = await ctx.db.get(m.userId as any);
        result.push({
          email: (user as any)?.email ?? null,
          name: (user as any)?.name ?? null,
        });
      } catch {
        result.push({ email: null, name: null });
      }
    }
    return result.filter((r) => r.email);
  },
});

export const getUsersWithNoRecentScan = internalQuery({
  args: { thresholdDays: v.number() },
  handler: async (ctx, args) => {
    const threshold = new Date(
      Date.now() - args.thresholdDays * 24 * 60 * 60 * 1000
    ).toISOString();
    const memberships = await ctx.db.query("memberships").collect();
    const result: { email: string; name: string | null; daysSinceLastScan: number }[] = [];
    const seen = new Set<string>();

    for (const m of memberships) {
      if (seen.has(m.userId)) continue;
      seen.add(m.userId);
      try {
        // Get last scan for this org
        const scans = await ctx.db
          .query("scans")
          .withIndex("by_orgId", (q) => q.eq("orgId", m.orgId))
          .collect();
        const lastScan = scans.sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0];
        if (lastScan && lastScan.createdAt >= threshold) continue; // recent scan exists

        const daysSince = lastScan
          ? Math.floor(
              (Date.now() - new Date(lastScan.createdAt).getTime()) / (1000 * 60 * 60 * 24)
            )
          : args.thresholdDays;

        const user = await ctx.db.get(m.userId as any);
        const email = (user as any)?.email;
        if (email) {
          result.push({
            email,
            name: (user as any)?.name ?? null,
            daysSinceLastScan: daysSince,
          });
        }
      } catch {
        /* skip */
      }
    }
    return result;
  },
});

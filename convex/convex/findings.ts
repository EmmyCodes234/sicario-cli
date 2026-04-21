import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { requireRole } from "./rbac";

export const get = query({
  args: { id: v.string() },
  handler: async (ctx, args) => {
    const finding = await ctx.db
      .query("findings")
      .withIndex("by_findingId", (q) => q.eq("findingId", args.id))
      .first();
    if (!finding) return null;
    return mapFinding(finding);
  },
});

export const list = query({
  args: {
    page: v.optional(v.number()),
    perPage: v.optional(v.number()),
    severity: v.optional(v.string()),
    triageState: v.optional(v.string()),
    confidenceMin: v.optional(v.number()),
    scanId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const page = args.page ?? 1;
    const perPage = args.perPage ?? 20;

    const allFindings = await ctx.db.query("findings").order("desc").collect();

    const filtered = allFindings.filter((f) => {
      if (args.severity && f.severity !== args.severity) return false;
      if (args.triageState && f.triageState !== args.triageState) return false;
      if (args.confidenceMin !== undefined && f.confidenceScore < args.confidenceMin) return false;
      if (args.scanId && f.scanId !== args.scanId) return false;
      return true;
    });

    const total = filtered.length;
    const offset = (page - 1) * perPage;
    const items = filtered.slice(offset, offset + perPage).map(mapFinding);

    return { page, per_page: perPage, total, items };
  },
});

export const triage = mutation({
  args: {
    id: v.string(),
    triageState: v.optional(v.string()),
    triageNote: v.optional(v.string()),
    assignedTo: v.optional(v.string()),
    userId: v.optional(v.string()),
    orgId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    // Enforce RBAC when auth context is provided
    if (args.userId && args.orgId) {
      await requireRole(ctx, args.userId, args.orgId, "developer");
    }

    const finding = await ctx.db
      .query("findings")
      .withIndex("by_findingId", (q) => q.eq("findingId", args.id))
      .first();
    if (!finding) return null;

    const updates: Record<string, string> = {
      updatedAt: new Date().toISOString(),
    };
    if (args.triageState) updates.triageState = args.triageState;
    if (args.triageNote !== undefined) updates.triageNote = args.triageNote;
    if (args.assignedTo !== undefined) updates.assignedTo = args.assignedTo;

    await ctx.db.patch(finding._id, updates);

    return { ...mapFinding(finding), ...updates };
  },
});

export const bulkTriage = mutation({
  args: {
    ids: v.array(v.string()),
    triageState: v.string(),
    triageNote: v.optional(v.string()),
    userId: v.optional(v.string()),
    orgId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    // Enforce RBAC when auth context is provided
    if (args.userId && args.orgId) {
      await requireRole(ctx, args.userId, args.orgId, "developer");
    }

    const now = new Date().toISOString();
    let count = 0;

    for (const id of args.ids) {
      const finding = await ctx.db
        .query("findings")
        .withIndex("by_findingId", (q) => q.eq("findingId", id))
        .first();
      if (finding) {
        const updates: Record<string, string> = {
          triageState: args.triageState,
          updatedAt: now,
        };
        if (args.triageNote) updates.triageNote = args.triageNote;
        await ctx.db.patch(finding._id, updates);
        count++;
      }
    }

    return { updated_count: count };
  },
});

export const listForExport = query({
  args: {
    severity: v.optional(v.string()),
    triageState: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const allFindings = await ctx.db.query("findings").collect();
    return allFindings
      .filter((f) => {
        if (args.severity && f.severity !== args.severity) return false;
        if (args.triageState && f.triageState !== args.triageState) return false;
        return true;
      })
      .map(mapFinding);
  },
});

export const getCriticalForScan = query({
  args: { scanId: v.string() },
  handler: async (ctx, args) => {
    const findings = await ctx.db
      .query("findings")
      .withIndex("by_scanId", (q) => q.eq("scanId", args.scanId))
      .collect();
    return findings
      .filter((f) => f.severity === "Critical")
      .map(mapFinding);
  },
});

// Helper to map internal Convex doc to API-compatible shape
function mapFinding(f: any) {
  return {
    id: f.findingId,
    scan_id: f.scanId,
    rule_id: f.ruleId,
    rule_name: f.ruleName,
    file_path: f.filePath,
    line: f.line,
    column: f.column,
    end_line: f.endLine ?? null,
    end_column: f.endColumn ?? null,
    snippet: f.snippet,
    severity: f.severity,
    confidence_score: f.confidenceScore,
    reachable: f.reachable,
    cloud_exposed: f.cloudExposed ?? null,
    cwe_id: f.cweId ?? null,
    owasp_category: f.owaspCategory ?? null,
    fingerprint: f.fingerprint,
    triage_state: f.triageState,
    triage_note: f.triageNote ?? null,
    assigned_to: f.assignedTo ?? null,
    created_at: f.createdAt,
    updated_at: f.updatedAt,
  };
}

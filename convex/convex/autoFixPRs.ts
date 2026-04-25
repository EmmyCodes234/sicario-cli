import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

export const createAutoFix = mutation({
  args: {
    fixId: v.string(),
    projectId: v.string(),
    orgId: v.string(),
    cveId: v.string(),
    packageName: v.string(),
    fromVersion: v.string(),
    toVersion: v.string(),
  },
  handler: async (ctx, args) => {
    // Check for duplicate open/pending fix for same projectId + cveId + packageName
    const existing = await ctx.db
      .query("autoFixPRs")
      .withIndex("by_projectId_cveId", (q) =>
        q.eq("projectId", args.projectId).eq("cveId", args.cveId)
      )
      .collect();

    const hasDuplicate = existing.some(
      (fix) =>
        fix.packageName === args.packageName &&
        (fix.status === "opened" || fix.status === "pending")
    );

    if (hasDuplicate) {
      return { fixId: null, duplicate: true };
    }

    const now = new Date().toISOString();
    await ctx.db.insert("autoFixPRs", {
      fixId: args.fixId,
      projectId: args.projectId,
      orgId: args.orgId,
      cveId: args.cveId,
      packageName: args.packageName,
      fromVersion: args.fromVersion,
      toVersion: args.toVersion,
      status: "pending",
      createdAt: now,
    });

    return { fixId: args.fixId, duplicate: false };
  },
});

export const updateAutoFixStatus = mutation({
  args: {
    fixId: v.string(),
    status: v.string(),
    prNumber: v.optional(v.number()),
    prUrl: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const record = await ctx.db
      .query("autoFixPRs")
      .withIndex("by_fixId", (q) => q.eq("fixId", args.fixId))
      .first();
    if (!record) return null;

    const updates: Record<string, unknown> = { status: args.status };
    if (args.prNumber !== undefined) updates.prNumber = args.prNumber;
    if (args.prUrl !== undefined) updates.prUrl = args.prUrl;

    await ctx.db.patch(record._id, updates);
  },
});

export const listByOrg = query({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const fixes = await ctx.db
      .query("autoFixPRs")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .order("desc")
      .collect();
    return fixes.map(mapAutoFix);
  },
});

export const listByProject = query({
  args: { projectId: v.string() },
  handler: async (ctx, args) => {
    const fixes = await ctx.db
      .query("autoFixPRs")
      .withIndex("by_projectId", (q) => q.eq("projectId", args.projectId))
      .collect();
    return fixes.map(mapAutoFix);
  },
});

export const hasDuplicateOpenFix = query({
  args: {
    projectId: v.string(),
    cveId: v.string(),
    packageName: v.string(),
  },
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("autoFixPRs")
      .withIndex("by_projectId_cveId", (q) =>
        q.eq("projectId", args.projectId).eq("cveId", args.cveId)
      )
      .collect();

    return existing.some(
      (fix) =>
        fix.packageName === args.packageName &&
        (fix.status === "opened" || fix.status === "pending")
    );
  },
});

function mapAutoFix(f: any) {
  return {
    fix_id: f.fixId,
    project_id: f.projectId,
    org_id: f.orgId,
    cve_id: f.cveId,
    package_name: f.packageName,
    from_version: f.fromVersion,
    to_version: f.toVersion,
    pr_number: f.prNumber ?? null,
    pr_url: f.prUrl ?? null,
    status: f.status,
    created_at: f.createdAt,
  };
}

import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { requireRole } from "./rbac";

export const list = query({
  args: {},
  handler: async (ctx) => {
    const projects = await ctx.db.query("projects").order("desc").collect();
    return projects.map(mapProject);
  },
});

export const get = query({
  args: { id: v.string() },
  handler: async (ctx, args) => {
    const project = await ctx.db
      .query("projects")
      .withIndex("by_projectId", (q) => q.eq("projectId", args.id))
      .first();
    if (!project) return null;
    return mapProject(project);
  },
});

export const create = mutation({
  args: {
    id: v.string(),
    name: v.string(),
    repository_url: v.optional(v.string()),
    description: v.optional(v.string()),
    team_id: v.optional(v.string()),
    userId: v.optional(v.string()),
    orgId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    // Enforce RBAC when auth context is provided
    if (args.userId && args.orgId) {
      await requireRole(ctx, args.userId, args.orgId, "manager");
    }

    const now = new Date().toISOString();
    await ctx.db.insert("projects", {
      projectId: args.id,
      name: args.name,
      repositoryUrl: args.repository_url ?? "",
      description: args.description ?? "",
      teamId: args.team_id,
      createdAt: now,
    });
    return { id: args.id };
  },
});

export const update = mutation({
  args: {
    id: v.string(),
    name: v.optional(v.string()),
    repository_url: v.optional(v.string()),
    description: v.optional(v.string()),
    team_id: v.optional(v.string()),
    userId: v.optional(v.string()),
    orgId: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    // Enforce RBAC when auth context is provided
    if (args.userId && args.orgId) {
      await requireRole(ctx, args.userId, args.orgId, "manager");
    }

    const project = await ctx.db
      .query("projects")
      .withIndex("by_projectId", (q) => q.eq("projectId", args.id))
      .first();
    if (!project) return null;

    const updates: Record<string, string> = {};
    if (args.name) updates.name = args.name;
    if (args.repository_url) updates.repositoryUrl = args.repository_url;
    if (args.description) updates.description = args.description;
    if (args.team_id) updates.teamId = args.team_id;

    await ctx.db.patch(project._id, updates);
    return { id: args.id };
  },
});

function mapProject(p: any) {
  return {
    id: p.projectId,
    name: p.name,
    repository_url: p.repositoryUrl,
    description: p.description,
    team_id: p.teamId ?? null,
    created_at: p.createdAt,
  };
}

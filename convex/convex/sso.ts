import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { requireRole, getUserMembership } from "./rbac";

/**
 * Get SSO configuration for an organization. Returns null if user has no access.
 */
export const getConfig = query({
  args: {
    orgId: v.string(),
    userId: v.string(),
  },
  handler: async (ctx, args) => {
    // Gracefully return null if user has no membership (e.g. dev/demo mode)
    const membership = await getUserMembership(ctx, args.userId, args.orgId);
    if (!membership) return null;

    const config = await ctx.db
      .query("ssoConfigs")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .first();
    if (!config) return null;
    return mapSsoConfig(config);
  },
});

/**
 * Create or update SSO configuration for an organization. Admin only.
 */
export const configure = mutation({
  args: {
    userId: v.string(),
    orgId: v.string(),
    provider: v.string(),
    issuerUrl: v.string(),
    clientId: v.string(),
    metadataUrl: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    await requireRole(ctx, args.userId, args.orgId, "admin");

    const existing = await ctx.db
      .query("ssoConfigs")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .first();

    const now = new Date().toISOString();

    if (existing) {
      await ctx.db.patch(existing._id, {
        provider: args.provider,
        issuerUrl: args.issuerUrl,
        clientId: args.clientId,
        metadataUrl: args.metadataUrl,
        enabled: true,
      });
      return { orgId: args.orgId, updated: true };
    }

    await ctx.db.insert("ssoConfigs", {
      orgId: args.orgId,
      provider: args.provider,
      issuerUrl: args.issuerUrl,
      clientId: args.clientId,
      metadataUrl: args.metadataUrl,
      enabled: true,
      createdAt: now,
    });
    return { orgId: args.orgId, created: true };
  },
});

/**
 * Disable SSO for an organization. Admin only.
 */
export const disable = mutation({
  args: {
    userId: v.string(),
    orgId: v.string(),
  },
  handler: async (ctx, args) => {
    await requireRole(ctx, args.userId, args.orgId, "admin");

    const config = await ctx.db
      .query("ssoConfigs")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .first();
    if (!config) return false;

    await ctx.db.patch(config._id, { enabled: false });
    return true;
  },
});

/**
 * List available SSO providers (static).
 */
export const listProviders = query({
  args: {},
  handler: async () => {
    return ["saml", "oidc"];
  },
});

function mapSsoConfig(c: any) {
  return {
    org_id: c.orgId,
    provider: c.provider,
    issuer_url: c.issuerUrl,
    client_id: c.clientId,
    metadata_url: c.metadataUrl ?? null,
    enabled: c.enabled,
    created_at: c.createdAt,
  };
}

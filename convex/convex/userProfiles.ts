import { query, mutation } from "./_generated/server";
import { v } from "convex/values";

/**
 * Return the currently authenticated user's identity.
 * Used by the frontend to get name, email, picture, and a stable userId.
 */
export const currentIdentity = query({
  args: {},
  handler: async (ctx) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) return null;
    return {
      tokenIdentifier: identity.tokenIdentifier,
      name: identity.name ?? null,
      email: identity.email ?? null,
      pictureUrl: identity.pictureUrl ?? null,
    };
  },
});

export const get = query({
  args: { userId: v.string() },
  handler: async (ctx, args) => {
    const profile = await ctx.db
      .query("userProfiles")
      .withIndex("by_userId", (q) => q.eq("userId", args.userId))
      .first();
    return profile ?? null;
  },
});

export const upsert = mutation({
  args: {
    userId: v.string(),
    role: v.optional(v.string()),
    teamSize: v.optional(v.string()),
    languages: v.optional(v.array(v.string())),
    cicdPlatform: v.optional(v.string()),
    goals: v.optional(v.array(v.string())),
  },
  handler: async (ctx, args) => {
    const now = new Date().toISOString();
    const existing = await ctx.db
      .query("userProfiles")
      .withIndex("by_userId", (q) => q.eq("userId", args.userId))
      .first();

    if (existing) {
      const updates: Record<string, unknown> = { updatedAt: now };
      if (args.role !== undefined) updates.role = args.role;
      if (args.teamSize !== undefined) updates.teamSize = args.teamSize;
      if (args.languages !== undefined) updates.languages = args.languages;
      if (args.cicdPlatform !== undefined) updates.cicdPlatform = args.cicdPlatform;
      if (args.goals !== undefined) updates.goals = args.goals;
      await ctx.db.patch(existing._id, updates);
      return existing._id;
    }

    return await ctx.db.insert("userProfiles", {
      userId: args.userId,
      onboardingCompleted: false,
      onboardingSkipped: false,
      role: args.role,
      teamSize: args.teamSize,
      languages: args.languages ?? [],
      cicdPlatform: args.cicdPlatform,
      goals: args.goals ?? [],
      createdAt: now,
      updatedAt: now,
    });
  },
});

export const completeOnboarding = mutation({
  args: { userId: v.string() },
  handler: async (ctx, args) => {
    const profile = await ctx.db
      .query("userProfiles")
      .withIndex("by_userId", (q) => q.eq("userId", args.userId))
      .first();
    if (!profile) {
      throw new Error(`No profile found for userId: ${args.userId}`);
    }
    const now = new Date().toISOString();
    await ctx.db.patch(profile._id, {
      onboardingCompleted: true,
      onboardingCompletedAt: now,
      updatedAt: now,
    });
    return profile._id;
  },
});

export const skipOnboarding = mutation({
  args: { userId: v.string() },
  handler: async (ctx, args) => {
    const profile = await ctx.db
      .query("userProfiles")
      .withIndex("by_userId", (q) => q.eq("userId", args.userId))
      .first();
    if (!profile) {
      throw new Error(`No profile found for userId: ${args.userId}`);
    }
    const now = new Date().toISOString();
    await ctx.db.patch(profile._id, {
      onboardingSkipped: true,
      updatedAt: now,
    });
    return profile._id;
  },
});

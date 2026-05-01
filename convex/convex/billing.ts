import { mutation, query, internalMutation, internalQuery } from "./_generated/server";
import { v } from "convex/values";

// ── Whop product ID → plan name mapping ──────────────────────────────────────
// Placeholder IDs — update these when Whop products are created.
export const WHOP_PRODUCT_PLAN_MAP: Record<string, "pro" | "team" | "enterprise"> = {
  "plan_XXXX_pro":        "pro",
  "plan_XXXX_team":       "team",
  "plan_XXXX_enterprise": "enterprise",
};

// ── Plan limits ───────────────────────────────────────────────────────────────
export const PLAN_LIMITS = {
  free:       { projects: 1,   findings: 500 },
  pro:        { projects: 10,  findings: 5_000 },
  team:       { projects: Infinity, findings: Infinity },
  enterprise: { projects: Infinity, findings: Infinity },
} as const;

// ── Helpers ───────────────────────────────────────────────────────────────────
function nowIso() {
  return new Date().toISOString();
}

/**
 * Returns a period starting now and ending 30 days from now.
 * Used for free-tier subscriptions created at org creation time.
 */
function freeTierPeriod(): { start: string; end: string } {
  const now = new Date();
  const end = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000);
  return { start: now.toISOString(), end: end.toISOString() };
}

/** Returns the start/end of the current calendar month as ISO-8601 strings. */
function currentMonthPeriod(): { start: string; end: string } {
  const now = new Date();
  const start = new Date(now.getFullYear(), now.getMonth(), 1).toISOString();
  const end   = new Date(now.getFullYear(), now.getMonth() + 1, 0, 23, 59, 59, 999).toISOString();
  return { start, end };
}

// ── Queries ───────────────────────────────────────────────────────────────────

export const getSubscription = query({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("subscriptions")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .first();
  },
});

export const getUsageSummary = query({
  args: { orgId: v.string(), periodStart: v.string() },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("usageSummary")
      .withIndex("by_orgId_periodStart", (q) =>
        q.eq("orgId", args.orgId).eq("periodStart", args.periodStart)
      )
      .first();
  },
});

export const listAuditLog = query({
  args: {
    orgId:         v.string(),
    fromTimestamp: v.string(),
    toTimestamp:   v.string(),
  },
  handler: async (ctx, args) => {
    const entries = await ctx.db
      .query("auditLog")
      .withIndex("by_orgId_timestamp", (q) => q.eq("orgId", args.orgId))
      .collect();

    return entries.filter((e) => {
      return e.timestamp >= args.fromTimestamp && e.timestamp <= args.toTimestamp;
    });
  },
});

// ── Internal queries (callable from HTTP actions / other server functions) ────

export const getSubscriptionInternal = internalQuery({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("subscriptions")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .first();
  },
});

export const getUsageSummaryInternal = internalQuery({
  args: { orgId: v.string(), periodStart: v.string() },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("usageSummary")
      .withIndex("by_orgId_periodStart", (q) =>
        q.eq("orgId", args.orgId).eq("periodStart", args.periodStart)
      )
      .first();
  },
});

// ── Mutations ─────────────────────────────────────────────────────────────────

/**
 * Called when a new organization is created. Seeds a free subscription.
 * Period: now → 30 days from now (free tier).
 * Idempotent — skips insert if a subscription already exists for the org.
 */
export const createSubscription = mutation({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    // Idempotent — skip if one already exists
    const existing = await ctx.db
      .query("subscriptions")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .first();
    if (existing) return existing._id;

    const { start, end } = freeTierPeriod();
    const now = nowIso();

    return await ctx.db.insert("subscriptions", {
      orgId:              args.orgId,
      plan:               "free",
      status:             "active",
      billingCycle:       "manual",
      seatCount:          0,
      currentPeriodStart: start,
      currentPeriodEnd:   end,
      createdAt:          now,
      updatedAt:          now,
    });
  },
});

/** Patches mutable subscription fields. Used by the Whop webhook handler. */
export const updateSubscription = mutation({
  args: {
    orgId:              v.string(),
    plan:               v.optional(v.union(v.literal("free"), v.literal("pro"), v.literal("team"), v.literal("enterprise"))),
    status:             v.optional(v.union(v.literal("active"), v.literal("trialing"), v.literal("past_due"), v.literal("canceled"), v.literal("paused"))),
    billingCycle:       v.optional(v.union(v.literal("monthly"), v.literal("annual"), v.literal("manual"))),
    whopUserId:         v.optional(v.string()),
    whopSubscriptionId: v.optional(v.string()),
    currentPeriodStart: v.optional(v.string()),
    currentPeriodEnd:   v.optional(v.string()),
    trialEndsAt:        v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const sub = await ctx.db
      .query("subscriptions")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .first();

    if (!sub) {
      throw new Error(`No subscription found for orgId: ${args.orgId}`);
    }

    const patch: Record<string, unknown> = { updatedAt: nowIso() };
    if (args.plan               !== undefined) patch.plan               = args.plan;
    if (args.status             !== undefined) patch.status             = args.status;
    if (args.billingCycle       !== undefined) patch.billingCycle       = args.billingCycle;
    if (args.whopUserId         !== undefined) patch.whopUserId         = args.whopUserId;
    if (args.whopSubscriptionId !== undefined) patch.whopSubscriptionId = args.whopSubscriptionId;
    if (args.currentPeriodStart !== undefined) patch.currentPeriodStart = args.currentPeriodStart;
    if (args.currentPeriodEnd   !== undefined) patch.currentPeriodEnd   = args.currentPeriodEnd;
    if (args.trialEndsAt        !== undefined) patch.trialEndsAt        = args.trialEndsAt;

    await ctx.db.patch(sub._id, patch);
  },
});

/** Resets seatCount to 0 at the start of a new billing period. */
export const resetSeatCount = mutation({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    const sub = await ctx.db
      .query("subscriptions")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .first();
    if (!sub) return;
    await ctx.db.patch(sub._id, { seatCount: 0, updatedAt: nowIso() });
  },
});

/** Updates seatCount to MAX(current, submitted). */
export const updateSeatCount = mutation({
  args: { orgId: v.string(), contributorCount: v.number() },
  handler: async (ctx, args) => {
    const sub = await ctx.db
      .query("subscriptions")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .first();
    if (!sub) return;
    if (args.contributorCount > sub.seatCount) {
      await ctx.db.patch(sub._id, {
        seatCount: args.contributorCount,
        updatedAt: nowIso(),
      });
    }
  },
});

/**
 * Atomically increments usageSummary counters by the provided delta values.
 * If no record exists for the (orgId, periodStart) pair, inserts a new one.
 *
 * @param delta.findingsStored - number of new findings to add
 * @param delta.projectCount   - number of new projects to add (typically 0 or 1)
 * @param delta.scansSubmitted - number of new scans to add (typically 1)
 */
export const upsertUsageSummary = mutation({
  args: {
    orgId:       v.string(),
    periodStart: v.string(),
    periodEnd:   v.string(),
    delta: v.object({
      findingsStored: v.number(),
      projectCount:   v.number(),
      scansSubmitted: v.number(),
    }),
  },
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("usageSummary")
      .withIndex("by_orgId_periodStart", (q) =>
        q.eq("orgId", args.orgId).eq("periodStart", args.periodStart)
      )
      .first();

    if (existing) {
      await ctx.db.patch(existing._id, {
        findingsStored: existing.findingsStored + args.delta.findingsStored,
        projectCount:   existing.projectCount   + args.delta.projectCount,
        scansSubmitted: existing.scansSubmitted + args.delta.scansSubmitted,
      });
    } else {
      await ctx.db.insert("usageSummary", {
        orgId:          args.orgId,
        periodStart:    args.periodStart,
        periodEnd:      args.periodEnd,
        findingsStored: args.delta.findingsStored,
        projectCount:   args.delta.projectCount,
        scansSubmitted: args.delta.scansSubmitted,
      });
    }
  },
});

/** Appends an immutable audit log entry. No update/delete mutations exist for auditLog. */
export const appendAuditLog = mutation({
  args: {
    orgId:     v.string(),
    eventType: v.string(),
    payload:   v.any(),
    userId:    v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    await ctx.db.insert("auditLog", {
      orgId:     args.orgId,
      eventType: args.eventType,
      payload:   args.payload,
      userId:    args.userId,
      timestamp: nowIso(),
    });
  },
});

// ── Internal mutations (callable from HTTP actions / other server functions) ──

/**
 * Internal version of createSubscription — callable from other mutations
 * (e.g., the org creation flow in organizations.ts).
 */
export const createSubscriptionInternal = internalMutation({
  args: { orgId: v.string() },
  handler: async (ctx, args) => {
    // Idempotent — skip if one already exists
    const existing = await ctx.db
      .query("subscriptions")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .first();
    if (existing) return existing._id;

    const { start, end } = freeTierPeriod();
    const now = nowIso();

    return await ctx.db.insert("subscriptions", {
      orgId:              args.orgId,
      plan:               "free",
      status:             "active",
      billingCycle:       "manual",
      seatCount:          0,
      currentPeriodStart: start,
      currentPeriodEnd:   end,
      createdAt:          now,
      updatedAt:          now,
    });
  },
});

export const appendAuditLogInternal = internalMutation({
  args: {
    orgId:     v.string(),
    eventType: v.string(),
    payload:   v.any(),
    userId:    v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    await ctx.db.insert("auditLog", {
      orgId:     args.orgId,
      eventType: args.eventType,
      payload:   args.payload,
      userId:    args.userId,
      timestamp: nowIso(),
    });
  },
});

export const updateSubscriptionInternal = internalMutation({
  args: {
    orgId:              v.string(),
    plan:               v.optional(v.union(v.literal("free"), v.literal("pro"), v.literal("team"), v.literal("enterprise"))),
    status:             v.optional(v.union(v.literal("active"), v.literal("trialing"), v.literal("past_due"), v.literal("canceled"), v.literal("paused"))),
    billingCycle:       v.optional(v.union(v.literal("monthly"), v.literal("annual"), v.literal("manual"))),
    whopUserId:         v.optional(v.string()),
    whopSubscriptionId: v.optional(v.string()),
    currentPeriodStart: v.optional(v.string()),
    currentPeriodEnd:   v.optional(v.string()),
    trialEndsAt:        v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const sub = await ctx.db
      .query("subscriptions")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .first();

    if (!sub) {
      throw new Error(`No subscription found for orgId: ${args.orgId}`);
    }

    const patch: Record<string, unknown> = { updatedAt: nowIso() };
    if (args.plan               !== undefined) patch.plan               = args.plan;
    if (args.status             !== undefined) patch.status             = args.status;
    if (args.billingCycle       !== undefined) patch.billingCycle       = args.billingCycle;
    if (args.whopUserId         !== undefined) patch.whopUserId         = args.whopUserId;
    if (args.whopSubscriptionId !== undefined) patch.whopSubscriptionId = args.whopSubscriptionId;
    if (args.currentPeriodStart !== undefined) patch.currentPeriodStart = args.currentPeriodStart;
    if (args.currentPeriodEnd   !== undefined) patch.currentPeriodEnd   = args.currentPeriodEnd;
    if (args.trialEndsAt        !== undefined) patch.trialEndsAt        = args.trialEndsAt;

    await ctx.db.patch(sub._id, patch);
  },
});

export const upsertUsageSummaryInternal = internalMutation({
  args: {
    orgId:       v.string(),
    periodStart: v.string(),
    periodEnd:   v.string(),
    delta: v.object({
      findingsStored: v.number(),
      projectCount:   v.number(),
      scansSubmitted: v.number(),
    }),
  },
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("usageSummary")
      .withIndex("by_orgId_periodStart", (q) =>
        q.eq("orgId", args.orgId).eq("periodStart", args.periodStart)
      )
      .first();

    if (existing) {
      await ctx.db.patch(existing._id, {
        findingsStored: existing.findingsStored + args.delta.findingsStored,
        projectCount:   existing.projectCount   + args.delta.projectCount,
        scansSubmitted: existing.scansSubmitted + args.delta.scansSubmitted,
      });
    } else {
      await ctx.db.insert("usageSummary", {
        orgId:          args.orgId,
        periodStart:    args.periodStart,
        periodEnd:      args.periodEnd,
        findingsStored: args.delta.findingsStored,
        projectCount:   args.delta.projectCount,
        scansSubmitted: args.delta.scansSubmitted,
      });
    }
  },
});

/** Resets seatCount to 0 for all subscriptions. Called by the monthly billing cron. */
export const resetAllSeatCounts = internalMutation({
  args: {},
  handler: async (ctx) => {
    // Collect all subscriptions and reset seatCount to 0
    const subs = await ctx.db.query("subscriptions").collect();
    await Promise.all(
      subs.map((sub) => ctx.db.patch(sub._id, { seatCount: 0, updatedAt: new Date().toISOString() }))
    );
  },
});

/** Manual enterprise provisioning — bypasses Whop checkout. Admin use only. */
export const provisionEnterprise = mutation({
  args: {
    orgId:               v.string(),
    contractStartDate:   v.string(),
    customRetentionDays: v.optional(v.number()),
    csmIdentifier:       v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const sub = await ctx.db
      .query("subscriptions")
      .withIndex("by_orgId", (q) => q.eq("orgId", args.orgId))
      .first();

    const now = nowIso();
    const patch: Record<string, unknown> = {
      plan:              "enterprise",
      status:            "active",
      billingCycle:      "manual",
      contractStartDate: args.contractStartDate,
      updatedAt:         now,
    };
    if (args.customRetentionDays !== undefined) patch.customRetentionDays = args.customRetentionDays;
    if (args.csmIdentifier       !== undefined) patch.csmIdentifier       = args.csmIdentifier;

    if (sub) {
      await ctx.db.patch(sub._id, patch);
    } else {
      const { start, end } = currentMonthPeriod();
      await ctx.db.insert("subscriptions", {
        orgId:              args.orgId,
        seatCount:          0,
        currentPeriodStart: start,
        currentPeriodEnd:   end,
        createdAt:          now,
        ...(patch as {
          plan: "enterprise";
          status: "active";
          billingCycle: "manual";
          contractStartDate: string;
          updatedAt: string;
        }),
      });
    }

    // Append audit log entry for enterprise provisioning
    await ctx.db.insert("auditLog", {
      orgId:     args.orgId,
      eventType: "subscription.enterprise_provisioned",
      payload:   {
        triggerSource:     "admin",
        contractStartDate: args.contractStartDate,
      },
      timestamp: now,
    });
  },
});

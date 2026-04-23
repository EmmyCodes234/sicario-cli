import { mutation, query } from "./_generated/server";
import { v } from "convex/values";

/**
 * Insert a new device code record for the OAuth device flow.
 */
export const createDeviceCode = mutation({
  args: {
    deviceCode: v.string(),
    userCode: v.string(),
    codeChallenge: v.string(),
    codeChallengeMethod: v.string(),
    clientId: v.string(),
    scope: v.optional(v.string()),
    expiresAt: v.number(),
  },
  handler: async (ctx, args) => {
    const now = new Date().toISOString();
    await ctx.db.insert("deviceCodes", {
      deviceCode: args.deviceCode,
      userCode: args.userCode,
      codeChallenge: args.codeChallenge,
      codeChallengeMethod: args.codeChallengeMethod,
      clientId: args.clientId,
      scope: args.scope,
      status: "pending",
      expiresAt: args.expiresAt,
      createdAt: now,
    });
    return { deviceCode: args.deviceCode, userCode: args.userCode };
  },
});

/**
 * Look up a device code record by user_code (for the approval page).
 */
export const getDeviceCodeByUserCode = query({
  args: { userCode: v.string() },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("deviceCodes")
      .withIndex("by_userCode", (q) => q.eq("userCode", args.userCode))
      .first();
  },
});

/**
 * Approve a device code — sets status to "approved" and associates the userId.
 */
export const approveDeviceCode = mutation({
  args: {
    userCode: v.string(),
    userId: v.string(),
  },
  handler: async (ctx, args) => {
    const record = await ctx.db
      .query("deviceCodes")
      .withIndex("by_userCode", (q) => q.eq("userCode", args.userCode))
      .first();
    if (!record) throw new Error("Device code not found");
    if (record.status !== "pending") throw new Error("Device code is no longer pending");
    if (Date.now() > record.expiresAt) {
      await ctx.db.patch(record._id, { status: "expired" });
      throw new Error("Device code has expired");
    }
    await ctx.db.patch(record._id, {
      status: "approved",
      userId: args.userId,
    });
    return { success: true };
  },
});

/**
 * Look up a device code record by device_code (for token polling).
 */
export const getDeviceCodeByDeviceCode = query({
  args: { deviceCode: v.string() },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("deviceCodes")
      .withIndex("by_deviceCode", (q) => q.eq("deviceCode", args.deviceCode))
      .first();
  },
});

/**
 * Mark a device code as consumed and store the access token.
 */
export const consumeDeviceCode = mutation({
  args: {
    deviceCode: v.string(),
    accessToken: v.string(),
  },
  handler: async (ctx, args) => {
    const record = await ctx.db
      .query("deviceCodes")
      .withIndex("by_deviceCode", (q) => q.eq("deviceCode", args.deviceCode))
      .first();
    if (!record) throw new Error("Device code not found");
    await ctx.db.patch(record._id, {
      status: "consumed",
      accessToken: args.accessToken,
    });
    return { success: true };
  },
});

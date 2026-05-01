// convex/convex/planEnforcer.ts

import { internal } from "./_generated/api";
import { PLAN_LIMITS } from "./billing";

type CheckResult =
  | { allowed: true }
  | { allowed: false; reason: "findings" | "projects" };

/**
 * Checks whether accepting a new telemetry payload would exceed the org's plan limits.
 * Called from within HTTP actions (ctx is an ActionCtx).
 *
 * @param ctx - Convex action context (has runQuery/runMutation)
 * @param orgId - The organization ID
 * @param incomingFindingsCount - Number of findings in the incoming payload
 * @param isNewProject - Whether this payload introduces a new project
 */
export async function checkLimits(
  ctx: any,
  orgId: string,
  incomingFindingsCount: number,
  isNewProject: boolean,
): Promise<CheckResult> {
  // 1. Fetch subscription; treat past_due as free
  const sub = await ctx.runQuery(internal.billing.getSubscriptionInternal, { orgId });
  const effectivePlan = (!sub || sub.status === "past_due") ? "free" : sub.plan;
  const limits = PLAN_LIMITS[effectivePlan as keyof typeof PLAN_LIMITS];

  // 2. Fetch current usage summary for the active billing period
  const periodStart = sub?.currentPeriodStart ?? new Date().toISOString();
  const usage = await ctx.runQuery(internal.billing.getUsageSummaryInternal, {
    orgId,
    periodStart,
  });

  const currentFindings = usage?.findingsStored ?? 0;
  const currentProjects = usage?.projectCount ?? 0;

  // 3. Check findings limit
  if (limits.findings !== Infinity && currentFindings + incomingFindingsCount > limits.findings) {
    return { allowed: false, reason: "findings" };
  }

  // 4. Check project limit
  if (isNewProject && limits.projects !== Infinity && currentProjects >= limits.projects) {
    return { allowed: false, reason: "projects" };
  }

  return { allowed: true };
}

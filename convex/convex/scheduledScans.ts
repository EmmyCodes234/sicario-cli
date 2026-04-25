import { internalMutation, internalAction, internalQuery } from "./_generated/server";
import { internal } from "./_generated/api";
import { v } from "convex/values";
import { resolveProjectDefaults } from "./projects";

/**
 * Scheduled SCA scan — runs every 24 hours via cron (see crons.ts).
 *
 * For each project with autoFixEnabled !== false, runs a stub SCA analysis
 * and creates autoFixPRs records for any detected CVEs (checking for duplicates).
 *
 * The actual CVE detection logic is stubbed — replace `runScaAnalysis` with
 * real dependency scanning when the SCA engine is integrated.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface DetectedVulnerability {
  cveId: string;
  packageName: string;
  fromVersion: string;
  toVersion: string;
}

// ---------------------------------------------------------------------------
// Stub SCA analysis — replace with real implementation
// ---------------------------------------------------------------------------

/**
 * Stub: Analyse a project's dependencies for known CVEs.
 * Returns an empty array until the real SCA engine is wired in.
 */
function runScaAnalysis(
  _projectId: string,
  _repositoryUrl: string
): DetectedVulnerability[] {
  // TODO: Integrate with actual CVE database / dependency scanner.
  return [];
}

// ---------------------------------------------------------------------------
// Internal action — orchestrates the scan across all eligible projects
// ---------------------------------------------------------------------------

export const runScheduledScaScan = internalAction({
  args: {},
  handler: async (ctx) => {
    // 1. Fetch all projects
    const projects: Array<{
      projectId: string;
      orgId: string;
      repositoryUrl: string;
      autoFixEnabled?: boolean;
    }> = await ctx.runQuery(internal.scheduledScans.listEligibleProjects, {});

    // 2. For each eligible project, run SCA and create fix records
    for (const project of projects) {
      const vulns = runScaAnalysis(project.projectId, project.repositoryUrl);

      for (const vuln of vulns) {
        await ctx.runMutation(internal.scheduledScans.createAutoFixIfNotDuplicate, {
          projectId: project.projectId,
          orgId: project.orgId,
          cveId: vuln.cveId,
          packageName: vuln.packageName,
          fromVersion: vuln.fromVersion,
          toVersion: vuln.toVersion,
        });
      }
    }
  },
});

// ---------------------------------------------------------------------------
// Internal query — list projects eligible for scheduled SCA scan
// ---------------------------------------------------------------------------

export const listEligibleProjects = internalQuery({
  args: {},
  handler: async (ctx) => {
    const allProjects = await ctx.db.query("projects").collect();

    return allProjects
      .filter((p) => {
        const defaults = resolveProjectDefaults(p);
        // Only scan projects where autoFix is enabled and provisioning is active
        return (
          defaults.autoFixEnabled === true &&
          defaults.provisioningState === "active"
        );
      })
      .map((p) => ({
        projectId: p.projectId,
        orgId: p.orgId,
        repositoryUrl: p.repositoryUrl,
        autoFixEnabled: p.autoFixEnabled,
      }));
  },
});

// ---------------------------------------------------------------------------
// Internal mutation — create an autoFixPR record if no duplicate exists
// ---------------------------------------------------------------------------

export const createAutoFixIfNotDuplicate = internalMutation({
  args: {
    projectId: v.string(),
    orgId: v.string(),
    cveId: v.string(),
    packageName: v.string(),
    fromVersion: v.string(),
    toVersion: v.string(),
  },
  handler: async (ctx, args) => {
    // Check for existing open/pending fix for same project + CVE + package
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
      return { created: false };
    }

    const fixId = crypto.randomUUID();
    const now = new Date().toISOString();

    await ctx.db.insert("autoFixPRs", {
      fixId,
      projectId: args.projectId,
      orgId: args.orgId,
      cveId: args.cveId,
      packageName: args.packageName,
      fromVersion: args.fromVersion,
      toVersion: args.toVersion,
      status: "pending",
      createdAt: now,
    });

    return { created: true, fixId };
  },
});

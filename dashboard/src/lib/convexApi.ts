/**
 * Typed Convex function references for the dashboard.
 * These map to the queries/mutations defined in convex/convex/*.ts
 * using anyApi so we don't need to share the generated types.
 */
import { anyApi } from "convex/server";

// ── Queries ───────────────────────────────────────────────────────────────────

export const analyticsOverview = anyApi.analytics.overview;
export const analyticsTrends = anyApi.analytics.trends;
export const analyticsMttr = anyApi.analytics.mttr;

export const findingsList = anyApi.findings.list;
export const findingsGet = anyApi.findings.get;
export const findingsListForExport = anyApi.findings.listForExport;

export const projectsList = anyApi.projects.list;
export const projectsGet = anyApi.projects.get;

export const scansList = anyApi.scans.list;
export const scansGet = anyApi.scans.get;

export const teamsList = anyApi.teams.list;

// ── Mutations ─────────────────────────────────────────────────────────────────

export const findingsTriage = anyApi.findings.triage;
export const findingsBulkTriage = anyApi.findings.bulkTriage;

// ── Memberships ───────────────────────────────────────────────────────────────

export const membershipsList = anyApi.memberships.list;
export const membershipsGetForUser = anyApi.memberships.getForUser;
export const membershipsCreate = anyApi.memberships.create;
export const membershipsUpdate = anyApi.memberships.update;
export const membershipsRemove = anyApi.memberships.remove;

// ── SSO ───────────────────────────────────────────────────────────────────────

export const ssoGetConfig = anyApi.sso.getConfig;
export const ssoConfigure = anyApi.sso.configure;
export const ssoDisable = anyApi.sso.disable;
export const ssoListProviders = anyApi.sso.listProviders;

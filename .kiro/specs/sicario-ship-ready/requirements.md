# Requirements: Sicario Ship-Ready Fix Sprint

## Context
Audit of the Sicario platform identified several broken, disconnected, or half-baked areas that prevent the product from being shippable. This spec addresses every issue found.

## Requirement 1: Cloud API — Deploy a Real Backend
- **User Story:** As a CLI user, I want `sicario login`, `sicario publish`, `sicario whoami`, and `--publish` to work against a real cloud endpoint so my scan results sync to the dashboard.
- **Acceptance Criteria:**
  - Convex HTTP actions handle `/api/v1/scans` (POST), `/api/v1/whoami` (GET), and OAuth device flow endpoints
  - CLI `sicario login` completes the device flow against the Convex-hosted auth endpoint
  - CLI `sicario publish` successfully uploads scan results to Convex
  - CLI `sicario whoami` returns the authenticated user's profile
  - All CLI default URLs point to the real Convex HTTP action URLs (no separate server needed)

## Requirement 2: Remove Dead Next.js Dashboard
- **User Story:** As a developer, I want a single frontend codebase so there's no confusion about which dashboard is the real one.
- **Acceptance Criteria:**
  - The `dashboard/` directory is deleted from the repo
  - All references to the old dashboard in docs, configs, and CI are removed
  - The `sicario-frontend/` is the sole frontend

## Requirement 3: Org Provisioning on First Login
- **User Story:** As a new user who just signed up, I want an organization and membership automatically created so I land on a functional dashboard instead of an empty shell.
- **Acceptance Criteria:**
  - On first authenticated dashboard visit, if no org/membership exists for the user, one is auto-created
  - The user is assigned the `admin` role in their auto-created org
  - All dashboard queries use the real authenticated userId and orgId (no more `PLACEHOLDER_ORG = 'org-1'`)

## Requirement 4: SCA Vulnerability Database — Real Data
- **User Story:** As a developer running `sicario scan`, I want SCA scanning to find real dependency vulnerabilities so I can audit my lockfiles.
- **Acceptance Criteria:**
  - The OSV.dev importer fetches real vulnerability data and populates the SQLite cache
  - `sicario scan .` on a project with known-vulnerable dependencies (e.g., lodash 4.17.20) returns SCA findings
  - The background sync runs on first scan if the cache is empty or stale (>24h)

## Requirement 5: Wire Cloud Exposure Analysis into Scan Pipeline
- **User Story:** As a user with Kubernetes manifests in my repo, I want `sicario scan` to automatically detect cloud exposure and adjust finding priorities.
- **Acceptance Criteria:**
  - `cmd_scan` checks for K8s manifests and CSPM data in the project directory
  - If found, cloud exposure analysis runs and adjusts vulnerability severity per the existing priority rules
  - Findings include `cloud_exposed: true/false` in JSON/SARIF output

## Requirement 6: Fix Scan Report Metadata
- **User Story:** As a user publishing scan results, I want accurate metadata (files scanned, language breakdown) in my reports.
- **Acceptance Criteria:**
  - `files_scanned` in published reports reflects the actual count of files scanned
  - `language_breakdown` contains a map of language → file count based on the scan
  - Both fields are populated in `--publish`, `sicario publish`, and JSON output

## Requirement 7: Frontend — Remove Hardcoded Org References
- **User Story:** As an authenticated user, I want the dashboard to use my real org context so RBAC, settings, and team management work correctly.
- **Acceptance Criteria:**
  - `PLACEHOLDER_ORG = 'org-1'` is replaced with the user's actual org ID from their membership
  - Settings page (members, SSO, webhooks) operates on the real org
  - RBAC checks use real userId + orgId pairs

## Requirement 8: Org Creation & Switching (Supabase-style)
- **User Story:** As a user who belongs to multiple organizations (e.g., personal + work), I want to create new orgs, be invited to existing ones, and switch between them from a dropdown in the dashboard — similar to how Supabase handles org switching.
- **Acceptance Criteria:**
  - Users can create a new organization from the dashboard (name required)
  - A `listUserOrgs` query returns all organizations the user is a member of
  - An org switcher dropdown is visible in the dashboard sidebar/header, showing all orgs the user belongs to with the active one highlighted
  - Switching orgs updates the active org context across all pages (projects, findings, settings, etc.) without a full page reload
  - The selected org persists across page navigations and browser refreshes (via localStorage)
  - The `useCurrentOrg()` hook respects the user's selected org rather than always returning the first membership
  - Creating a new org automatically assigns the creator as `admin` and switches to it
  - The org switcher shows the org name and a visual indicator (avatar/initial) for each org

## Requirement 9: Org-Scoped Projects with Auto-Creation from CLI Scans

**User Story:** As a platform user, I want projects and scans to be scoped to my organization, and I want the server to auto-create a project when the CLI publishes a scan for an unrecognized repository, so that scan results are always organized under the correct org and project without manual setup.

#### Acceptance Criteria

1. WHEN the schema is deployed, THE Projects_Table SHALL include an `orgId` field and a `by_orgId` index, and THE Scans_Table SHALL include `orgId` and `projectId` fields and a `by_orgId` index.
2. WHEN `projects.list` is called with an `orgId` argument, THE Projects_Query SHALL return only projects belonging to that organization.
3. WHEN `projects.create` is called, THE Projects_Mutation SHALL require an `orgId` argument and store it on the created project record.
4. WHEN a `POST /api/v1/scans` request is received with a valid Bearer token, THE Scan_Ingestion_Action SHALL resolve the authenticated user's `orgId` from the Memberships_Table.
5. WHEN the resolved `orgId` is available and `metadata.repository` matches an existing project's `repositoryUrl` within that organization, THE Scan_Ingestion_Action SHALL associate the scan with that project's `projectId`.
6. WHEN the resolved `orgId` is available and `metadata.repository` does not match any existing project within that organization, THE Scan_Ingestion_Action SHALL auto-create a new project with the repository URL as both name and `repositoryUrl`, scoped to that `orgId`, and associate the scan with the new project's `projectId`.
7. WHEN a scan is stored, THE Scan_Ingestion_Action SHALL persist both `orgId` and `projectId` on the scan record and on each finding record.
8. WHEN a user views the Projects page in the dashboard, THE Projects_Page SHALL display only projects belonging to the user's active organization.
9. WHEN a user views the Scans page in the dashboard, THE Scans_Page SHALL filter scans by the user's active organization.
10. WHEN a user views a scan detail page, THE Scan_Detail_Page SHALL display the associated project name and organization name.
11. THE CLI SHALL not require an `orgId` parameter for scan publishing — THE Scan_Ingestion_Action SHALL resolve the organization from the authenticated user's membership.
12. WHERE a user belongs to multiple organizations, THE CLI SHALL accept an optional `--org` flag to specify which organization to publish scans under.
13. IF the authenticated user has no membership in any organization, THEN THE Scan_Ingestion_Action SHALL return a 403 error with a descriptive message.
14. IF the `--org` flag is provided and the user is not a member of the specified organization, THEN THE Scan_Ingestion_Action SHALL return a 403 error with a descriptive message.

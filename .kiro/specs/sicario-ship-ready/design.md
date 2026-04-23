# Design: Sicario Ship-Ready Fix Sprint

## Requirement 1: Cloud API via Convex HTTP Actions

Instead of deploying a separate cloud API server, we use Convex HTTP actions to expose REST endpoints. The CLI already has `reqwest` for HTTP — it just needs to point at the right URLs.

### Architecture
```
CLI (sicario login/publish/whoami)
  → HTTPS POST/GET to flexible-terrier-680.convex.site/api/...
    → Convex HTTP actions in convex/http.ts
      → Convex mutations/queries (findings, scans, userProfiles)
```

### Endpoints to add in `convex/http.ts`:
- `POST /api/v1/scans` — accepts scan report JSON, stores findings + scan metadata
- `GET /api/v1/whoami` — returns user profile from Bearer token
- `POST /oauth/device/code` — initiates device flow, returns user_code + verification_uri
- `POST /oauth/token` — polls for token completion

### CLI changes:
- Update default `SICARIO_CLOUD_AUTH_URL` and `SICARIO_CLOUD_URL` to point at the Convex site URL
- The device flow verification_uri points users to `usesicario.xyz/auth/device?code=XXXX`

### Frontend addition:
- Add `/auth/device` page that accepts a `?code=` param and lets the authenticated user approve the CLI device code

## Requirement 2: Remove Dead Dashboard

Simple deletion. Remove `dashboard/` directory and any references.

## Requirement 3: Org Provisioning

### Backend:
- Add `convex/convex/organizations.ts` with `ensureOrg` mutation
- On first dashboard load, call `ensureOrg` which:
  - Checks if user has any membership
  - If not, creates a personal org + admin membership
  - Returns the orgId

### Frontend:
- Add `useCurrentOrg()` hook that calls `ensureOrg` and caches the result
- Replace all `PLACEHOLDER_ORG` references with `useCurrentOrg().orgId`

## Requirement 4: SCA Real Data

### Implementation:
- Implement the OSV.dev REST API importer in `sicario-cli/src/engine/sca/vuln_db.rs`
- On first scan (or when cache is >24h old), fetch from `https://api.osv.dev/v1/query`
- Parse lockfiles (package-lock.json, Cargo.lock, requirements.txt) to extract package+version pairs
- Query OSV for each package ecosystem
- Store results in the SQLite cache

### No GHSA needed initially — OSV covers the same data.

## Requirement 5: Cloud Exposure in Scan Pipeline

### Implementation:
- In `cmd_scan()` in `main.rs`, after scanning, check if `k8s/` or `kubernetes/` or `*.yaml` with `kind: Service` exist
- If found, run `CloudExposureAnalyzer` and `assign_cloud_priority()`
- Add `--cloud-exposure` flag (default: auto-detect)

## Requirement 6: Fix Scan Metadata

### Implementation:
- `files_scanned` is already computed in `cmd_scan` as `files_to_scan.len()` — just pass it through to `publish_scan_results`
- Build `language_breakdown` from file extensions during the scan
- Update `ScanMetadata` construction in both `cmd_scan` and `cmd_cloud_publish`

## Requirement 7: Frontend Org Context

### Implementation:
- `useCurrentOrg()` hook provides `orgId`
- Update ProjectsPage, ProjectDetailPage, SettingsPage to use it
- RBAC hooks receive real orgId

## Requirement 8: Org Creation & Switching

### Backend (`convex/convex/organizations.ts`):
- Add `createOrg` mutation — accepts `name`, creates org + admin membership for the caller, returns `{ orgId }`
- Add `listUserOrgs` query — returns all orgs the authenticated user belongs to (join memberships → organizations), each with `{ orgId, name, role, createdAt }`

### Frontend Hook (`useCurrentOrg.ts` update):
- Extend `useCurrentOrg()` to support multi-org:
  - Fetch all user orgs via `listUserOrgs` query
  - Track `activeOrgId` in state, initialized from `localStorage` key `sicario:activeOrgId`
  - On org switch, update state + persist to `localStorage`
  - If stored orgId is no longer valid (user removed from org), fall back to first org
  - Still call `ensureOrg` on first load to guarantee at least one org exists
  - Return `{ orgId, orgs, switchOrg, createOrg, isLoading }`

### Frontend Component (`OrgSwitcher.tsx`):
- Dropdown component in the sidebar header area
- Shows current org name with a colored initial/avatar circle
- Dropdown lists all orgs with role badges
- "Create Organization" option at the bottom with inline name input
- Keyboard accessible (arrow keys, Enter, Escape)

### Integration:
- Mount `OrgSwitcher` in the dashboard layout (sidebar or top nav)
- All pages already consume `useCurrentOrg().orgId` — switching orgs reactively updates everything

## Requirement 9: Org-Scoped Projects with Auto-Creation from CLI Scans

### Overview
Projects and scans become org-scoped. The `POST /api/v1/scans` endpoint gains intelligence: it resolves the caller's org from their membership, matches the scan's repository against existing projects in that org, auto-creates a project if none matches, and stores everything with `orgId` + `projectId`. The CLI stays simple — the server does the org resolution.

### Schema Changes (`convex/convex/schema.ts`)

**projects table** — add `orgId` field:
```typescript
projects: defineTable({
  projectId: v.string(),
  name: v.string(),
  repositoryUrl: v.string(),
  description: v.string(),
  orgId: v.string(),              // NEW
  teamId: v.optional(v.string()),
  createdAt: v.string(),
})
  .index("by_projectId", ["projectId"])
  .index("by_teamId", ["teamId"])
  .index("by_orgId", ["orgId"])   // NEW
```

**scans table** — add `orgId` field (already has optional `projectId`):
```typescript
scans: defineTable({
  // ... existing fields ...
  orgId: v.optional(v.string()),     // NEW
  projectId: v.optional(v.string()), // already exists
})
  // ... existing indexes ...
  .index("by_orgId", ["orgId"])      // NEW
```

**findings table** — add `orgId` and `projectId`:
```typescript
findings: defineTable({
  // ... existing fields ...
  orgId: v.optional(v.string()),     // NEW
  projectId: v.optional(v.string()), // NEW
})
```

### Backend — Project Scoping (`convex/convex/projects.ts`)

**Update `projects.list`:**
- Add required `orgId` arg
- Filter: `.withIndex("by_orgId", q => q.eq("orgId", args.orgId))`

**Update `projects.create`:**
- Add required `orgId` arg, store on the record

**Add `projects.listByOrg` query:**
- Convenience query that returns all projects for a given orgId

### Backend — Scan Ingestion (`convex/convex/http.ts` + `convex/convex/scans.ts`)

**Updated `POST /api/v1/scans` flow:**
```
1. Authenticate user via Bearer token → get userId
2. Check for X-Sicario-Org header (from --org flag)
3. If header present:
   a. Look up membership for (userId, specifiedOrgId)
   b. If no membership → 403 "Not a member of specified organization"
   c. Use specifiedOrgId
4. If no header:
   a. Query memberships by userId, take first result
   b. If no memberships → 403 "No organization membership found"
   c. Use that orgId
5. Query projects by_orgId, find one where repositoryUrl matches metadata.repository
6. If match → use that projectId
7. If no match → auto-create project:
   - projectId: crypto.randomUUID()
   - name: extract repo name from URL (e.g., "my-repo" from "https://github.com/org/my-repo")
   - repositoryUrl: metadata.repository
   - orgId: resolved orgId
8. Store scan with orgId + projectId
9. Store each finding with orgId + projectId
```

**New internal mutation `scans.insertWithOrg`** (or update existing `scans.insert`):
- Accepts `orgId` and `projectId` in addition to existing args
- Stores both on the scan record and each finding

### Frontend — Projects Page (`sicario-frontend/src/pages/dashboard/ProjectsPage.tsx`)

- Change `useQuery(api.projects.list)` → `useQuery(api.projects.list, { orgId })` where `orgId` comes from `useCurrentOrg()`
- The `CreateProjectModal` already passes `orgId` — just ensure the mutation stores it

### Frontend — Scans Page

- Add `orgId` filter to the scans list query
- Scan detail page: show project name + org name in the header metadata

### CLI Changes (`sicario-cli/src/main.rs`)

- Add optional `--org <ORG_ID>` flag to `sicario scan --publish` and `sicario publish`
- If provided, send as `X-Sicario-Org` header on the `POST /api/v1/scans` request
- If not provided, omit the header — server resolves from membership
- No other CLI changes needed

### Data Flow Diagram
```
CLI: sicario scan --publish
  → POST /api/v1/scans (Bearer token, optional X-Sicario-Org header)
    → http.ts handler:
      1. auth.getUserIdentity() → userId
      2. resolve orgId (from header or membership lookup)
      3. match repository → existing project or auto-create
      4. call scans.insertWithOrg({ orgId, projectId, ... })
    → Response: { scan_id, project_id, dashboard_url }

Dashboard: ProjectsPage
  → useQuery(api.projects.list, { orgId })  // filtered by active org
  → Only shows projects for the selected org

Dashboard: ScansPage
  → useQuery(api.scans.list, { orgId })     // filtered by active org
```

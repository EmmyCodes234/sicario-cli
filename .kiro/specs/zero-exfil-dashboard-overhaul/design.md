# Design Document: Zero-Exfiltration Dashboard & Onboarding Overhaul

## Overview

This document describes the technical design for the Zero-Exfiltration Dashboard & Onboarding Overhaul. The goal is to transform the Sicario web dashboard into a strictly read-only telemetry monitor that never touches source code, never triggers scans, and never pushes code changes. Every UI element must reinforce that all power lies in the developer's local terminal.

The overhaul has three phases:
1. **Surgical Removal** — strip all GitHub App references, Auto-Fix PR panels, Scan Now buttons, and Connected Repos banners.
2. **Zero-Exfil Onboarding** — replace the existing wizard with a terminal-first flow: project creation (name only) → Terminal Handshake waiting room → Demo Mode bypass.
3. **Command Center Rebuild** — redesign the dashboard, finding detail view, and project settings as a premium, high-density, read-only monitor.

### Design System Constraint

All new UI MUST use the existing design tokens and components. No new tokens are introduced.

| Token | Value | Usage |
|---|---|---|
| `--color-bg-main` | `#1c1c1c` | Primary background |
| `--color-bg-card` | `#232323` | Card background |
| `--color-border-subtle` | `#2e2e2e` | Borders |
| `--color-text-main` | `#f4f4f5` | Primary text |
| `--color-text-muted` | `#a1a1aa` | Secondary text |
| `--color-accent` | `#ADFF2F` | Matrix green accent |
| `--color-accent-hover` | `#98e629` | Accent hover |
| `--font-sans` | Inter | UI text |
| `--font-mono` | JetBrains Mono | Code/data/terminal |

Requirement 14 specifies `#0A0A0A` as the primary background. This maps to `bg-bg-main` (`#1c1c1c`) — the existing token is used as-is. Terminal blocks use `bg-[#0d0d0d]` (already used in the existing `OnboardingV2Page`). The "matrix green" maps to `text-accent` / `bg-accent`. "Muted red for critical" maps to the existing severity Critical color from `sicario-frontend/src/lib/severity.ts`.

---

## Architecture

The overhaul touches three layers:

```
┌─────────────────────────────────────────────────────────────┐
│  React Frontend (sicario-frontend/)                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Onboarding  │  │  Dashboard   │  │  Project         │  │
│  │  Flow        │  │  Pages       │  │  Settings        │  │
│  │  (new)       │  │  (overhauled)│  │  (new 4-tab)     │  │
│  └──────┬───────┘  └──────┬───────┘  └────────┬─────────┘  │
│         │                 │                    │            │
│  ┌──────▼─────────────────▼────────────────────▼─────────┐  │
│  │  Shared UI Components (existing + new TerminalBlock)  │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────┬───────────────────────────────┘
                              │ Convex reactive queries
┌─────────────────────────────▼───────────────────────────────┐
│  Convex Backend (convex/convex/)                            │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  projects.ts │  │  findings.ts │  │  scans.ts        │  │
│  │  (new        │  │  (unchanged) │  │  (unchanged)     │  │
│  │  mutations)  │  │              │  │                  │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

### Data Flow

The dashboard is a **read-only telemetry receiver**. The only write operations are:
- `projects.create` — user creates a project (name only)
- `projects.regenerateApiKey` — user rotates an API key
- `projects.updateAlertingConfig` — user saves Slack webhook config
- `projects.purgeTelemetry` — user purges all findings + scans
- `projects.deleteProject` — user deletes a project
- Triage state updates on findings (metadata only, no code changes)

All scan data arrives via `POST /api/v1/telemetry/scan` from the CLI. The dashboard never initiates scans.

### Demo Mode Architecture

Demo Mode is a client-side state machine with no backend interaction:

```
┌─────────────────────────────────────────────────────────────┐
│  DemoModeContext (React Context)                            │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  demoMode: boolean                                  │   │
│  │  demoProject: DemoProject (hard-coded constant)     │   │
│  │  enterDemoMode(): void                              │   │
│  │  exitDemoMode(): void  (called by LiveTransition)   │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

When `demoMode === true`, all dashboard pages read from `demoProject` instead of Convex queries. No Convex queries fire for real project data in Demo Mode.

---

## Components and Interfaces

### New Component: `TerminalBlock`

A reusable terminal UI block used in onboarding, CLI Integration tab, and Remediation Handoff.

```tsx
interface TerminalBlockProps {
  title?: string;           // shown in macOS title bar (e.g., "sicario — quick start")
  children: ReactNode;      // command rows, key reveals, etc.
  className?: string;
}

// Styling:
// Outer: bg-[#0d0d0d] border border-border-subtle rounded-lg overflow-hidden
// Title bar: flex items-center gap-2 border-b border-border-subtle px-4 py-2.5
//   - 3 dots: h-3 w-3 rounded-full bg-[#ff5f57] / bg-[#febc2e] / bg-[#28c840]
//   - Title text: text-xs text-text-muted font-mono
// Content area: p-5 space-y-4
```

### New Component: `SnippetBlock`

Code snippet display with fade-out gradient overlay.

```tsx
interface SnippetBlockProps {
  snippet: string;          // raw snippet text (max 500 chars enforced)
  filePath: string;
  line: number;
  endLine?: number;
}

// Container: relative overflow-hidden bg-bg-main rounded-lg
// Top gradient: absolute inset-x-0 top-0 h-8 bg-gradient-to-b from-bg-card to-transparent
//   (only rendered when snippet has > 1 line)
// Bottom gradient: absolute inset-x-0 bottom-0 h-8 bg-gradient-to-t from-bg-card to-transparent
//   (only rendered when snippet has > 1 line)
// Code: font-mono text-sm text-text-main px-5 py-4
// Caption: text-xs text-text-muted mt-2
//   "Snippet only — full file never stored on this server"
```

### New Component: `DemoModeBanner`

Persistent banner shown on every dashboard page while Demo Mode is active.

```tsx
// role="alert" aria-live="polite"
// border border-accent/20 bg-accent/5 rounded-xl px-4 py-3
// Text: text-text-muted with text-accent for the command
// Button: existing Button variant="primary" → "Connect Your Code"
```

### New Component: `RemediationHandoff`

Terminal block with the `sicario fix` command and copy button.

```tsx
interface RemediationHandoffProps {
  findingId: string;
}

// Card padding="md" wrapping a TerminalBlock
// Command: font-mono text-accent "sicario fix --id=<findingId>"
// CopyButton: existing CopyButton component with aria-label="Copy sicario fix command"
```

### New Component: `ExecutionAuditTrail`

Read-only scrollable timeline from `executionTrace`.

```tsx
interface ExecutionAuditTrailProps {
  entries: string[];   // format: "[HH:MM:SS] <emoji> <description>"
}

// Container: max-h-48 overflow-y-auto role="list" aria-label="Execution audit trail"
// Each entry: role="listitem" font-mono text-xs
//   Timestamp portion: text-accent
//   Rest: text-text-main
// Empty state: text-text-muted "No execution trace available for this finding."
```

### New Component: `ZeroExfilBadge`

Sidebar badge reinforcing the architecture.

```tsx
// Bottom of sidebar
// border border-accent/20 bg-accent/5 rounded-lg px-3 py-2
// Icon: Shield icon in text-accent
// Line 1: "Zero-Exfiltration" text-accent text-xs font-mono
// Line 2: "Telemetry Mode" text-text-muted text-xs
```

### New Component: `ProjectSettingsView`

4-tab settings layout for per-project settings.

```tsx
// Left sidebar: 4 tabs
//   - "CLI Integration" (default)
//   - "Telemetry API Keys"
//   - "Alerting & Notifications"
//   - "Danger Zone"
// Right content: tab-specific content
// Uses existing Tabs component
```

### Modified: `DashboardLayout`

- Add `DemoModeContext` provider wrapping the layout
- Render `DemoModeBanner` at the top of `<main>` when `demoMode === true`
- Add `ZeroExfilBadge` at the bottom of `Sidebar`
- Remove any GitHub App navigation items

### Modified: `OnboardingV2Page`

Replaced with a two-step flow:
1. **Project Creation** — name only, no repository URL field
2. **Terminal Handshake** — 4 CLI commands + Demo Mode ghost button

The existing `OnboardingV2Page.tsx` already has the correct structure. Changes:
- Remove the `repositoryUrl` input field from step 1
- Add "Explore Dashboard (Demo Mode)" ghost button below the terminal block in step 2
- Wire the ghost button to `enterDemoMode()` from `DemoModeContext`

### Modified: `FindingDetailPage`

- Replace the "Auto-Fix Command" card with `RemediationHandoff` component
- Replace the plain `<pre>` snippet with `SnippetBlock` component
- Add `ExecutionAuditTrail` section below `RemediationHandoff`
- Remove `TriageForm` cloud-action buttons (keep triage state metadata updates)
- Remove `PdfExport` if it implies cloud-side generation (keep if client-side)

### Modified: `OverviewPage`

- Remove `<PrChecksPanel />` and `<AutoFixPanel />` from render
- Remove `<AiFixesCard />` component
- Remove "connected repositories" banner
- Remove `<CoverageMap />` if it references GitHub repos
- Rename stat cards: "Total Findings" → "Vulnerabilities Intercepted", "Total Scans" → "Edge Scans Executed"
- Keep `TopVulnerableProjects`, `FindingsTrendChart`, `SeverityDonutChart`, `MttrBarChart`

---

## Data Models

### DemoProject Constant

```typescript
// sicario-frontend/src/data/demoProject.ts

import type { Finding, Scan, Project } from '../types/dashboard';

export const DEMO_PROJECT: Project = {
  id: 'demo-project-id',
  name: 'demo-app',
  repository_url: 'https://github.com/demo/demo-app',
  description: 'Demo project for exploring the dashboard',
  org_id: 'demo-org',
  team_id: null,
  created_at: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString(),
  provisioning_state: 'active',
  framework: 'Next.js',
  project_api_key: 'sic_proj_demo_••••••••••••••••',
  severity_threshold: 'high',
  auto_fix_enabled: false,
};

export const DEMO_FINDINGS: Finding[] = [
  {
    id: 'demo-finding-critical-1',
    // severity: 'Critical', file_path, line, snippet (≤500 chars),
    // executionTrace: ['[14:02:01] ⚡ Local AST parsed in 0.04s', ...],
    // ... all fields matching the Finding type
  },
  // High, Medium, Low findings...
];

export const DEMO_SCAN: Scan = {
  // repository, branch, commitSha, duration, filesScanned, languageBreakdown
};
```

All fields in `DEMO_PROJECT`, `DEMO_FINDINGS`, and `DEMO_SCAN` must conform to the TypeScript types returned by Convex queries (`api.projects.get`, `api.findings.list`, `api.scans.list`). This is enforced at compile time via explicit type annotations.

### Schema Additions (Convex)

Two new optional fields on the `projects` table in `convex/convex/schema.ts`:

```typescript
// In the projects defineTable:
slackWebhookUrl: v.optional(v.string()),
slackAlertSeverityThreshold: v.optional(v.string()), // "Critical" | "High" | "Medium" | "Low"
```

### New Convex Mutations

#### `projects.purgeTelemetry`

```typescript
export const purgeTelemetry = mutation({
  args: {
    projectId: v.string(),
    userId: v.string(),
    orgId: v.string(),
  },
  handler: async (ctx, args) => {
    await requireRole(ctx, args.userId, args.orgId, "manager");
    // Delete all findings where projectId matches
    const findings = await ctx.db.query("findings")
      .withIndex("by_projectId", q => q.eq("projectId", args.projectId))
      .collect();
    await Promise.all(findings.map(f => ctx.db.delete(f._id)));
    // Delete all scans where projectId matches
    const scans = await ctx.db.query("scans")
      .withIndex("by_projectId", q => q.eq("projectId", args.projectId))
      .collect();
    await Promise.all(scans.map(s => ctx.db.delete(s._id)));
  },
});
```

Note: The `findings` table has `by_orgId` index but not `by_projectId`. A new index `by_projectId` must be added to both `findings` and `scans` tables, or the purge must filter by `orgId` + `projectId` combination.

#### `projects.deleteProject`

```typescript
export const deleteProject = mutation({
  args: {
    projectId: v.string(),
    userId: v.string(),
    orgId: v.string(),
  },
  handler: async (ctx, args) => {
    await requireRole(ctx, args.userId, args.orgId, "admin");
    // Purge findings and scans first (reuse purgeTelemetry logic)
    // Then delete the project record
    const project = await ctx.db.query("projects")
      .withIndex("by_projectId", q => q.eq("projectId", args.projectId))
      .first();
    if (!project) return; // idempotent
    await ctx.db.delete(project._id);
  },
});
```

#### `projects.updateAlertingConfig`

```typescript
export const updateAlertingConfig = mutation({
  args: {
    projectId: v.string(),
    userId: v.string(),
    orgId: v.string(),
    slackWebhookUrl: v.string(),
    slackAlertSeverityThreshold: v.string(),
  },
  handler: async (ctx, args) => {
    await requireRole(ctx, args.userId, args.orgId, "manager");
    const project = await ctx.db.query("projects")
      .withIndex("by_projectId", q => q.eq("projectId", args.projectId))
      .first();
    if (!project) throw new Error("Project not found");
    await ctx.db.patch(project._id, {
      slackWebhookUrl: args.slackWebhookUrl,
      slackAlertSeverityThreshold: args.slackAlertSeverityThreshold,
    });
  },
});
```

### Slack Webhook URL Validation

Client-side validation function (pure, testable):

```typescript
// sicario-frontend/src/lib/validation.ts
export function isValidSlackWebhookUrl(url: string): boolean {
  return url.startsWith('https://hooks.slack.com/');
}
```

### Delete Project Name Confirmation

Client-side guard (pure, testable):

```typescript
// In DangerZoneTab component
const isDeleteEnabled = confirmInput.trim() === project.name;
```

---

## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Demo Mode data shape matches live data shape

*For any* field access pattern that is valid on a live Convex query result (`Finding`, `Scan`, `Project`), the same access pattern on `DEMO_FINDINGS`, `DEMO_SCAN`, and `DEMO_PROJECT` SHALL succeed without TypeScript type errors.

**Validates: Requirements 18.1, 18.5**

### Property 2: Snippet fade-out only applies when snippet has more than one line

*For any* snippet string that contains no newline characters, the `SnippetBlock` component SHALL NOT render any gradient overlay elements. *For any* snippet string that contains at least one newline character, the `SnippetBlock` component SHALL render both top and bottom gradient overlay elements.

**Validates: Requirements 19.4, 7.2**

### Property 3: Terminal Handshake auto-navigates when `provisioningState === "active"`

*For any* `projectId`, when the Convex reactive query for that project returns `provisioningState === "active"`, the Terminal Handshake component SHALL call `navigate` to the project dashboard route without any user interaction.

**Validates: Requirements 3.6, 5.2**

### Property 4: LiveTransition purges all demo state before rendering live data

*For any* Demo Mode state (any combination of `demoProject`, `demoFindings`, `demoScan`), when `exitDemoMode()` is called, all demo data fields SHALL be cleared from React state and all dashboard components SHALL re-render using live Convex queries.

**Validates: Requirements 5.3, 4.4**

### Property 5: Danger Zone delete requires exact project name match

*For any* project name string `name`, the delete confirmation button SHALL be disabled unless the user's input value is exactly equal to `name` (case-sensitive, no trimming). The button SHALL be enabled if and only if `confirmInput === project.name`.

**Validates: Requirements 13.5**

### Property 6: `purgeTelemetry` deletes all findings AND scans for the project (no orphans)

*For any* project with `N` findings and `M` scans, after `projects.purgeTelemetry` completes successfully, querying findings by `projectId` SHALL return an empty array AND querying scans by `projectId` SHALL return an empty array.

**Validates: Requirements 15.3, 15.4**

### Property 7: `deleteProject` leaves no project record in the database

*For any* valid `deleteProject` call (authorized admin, existing project), after the mutation completes, querying `projects` by `projectId` SHALL return `null`. This holds regardless of whether the project had findings, scans, or API keys.

**Validates: Requirements 16.3, 16.4, 16.6**

### Property 8: Slack webhook URL validation accepts only `https://hooks.slack.com/` URLs

*For any* URL string `url`, `isValidSlackWebhookUrl(url)` SHALL return `true` if and only if `url` starts with the prefix `"https://hooks.slack.com/"`.

**Validates: Requirements 12.3**

### Property 9: Remediation Handoff command contains the exact finding ID

*For any* `findingId` string, the `RemediationHandoff` component SHALL render a command string that contains `findingId` verbatim (i.e., `sicario fix --id=${findingId}`).

**Validates: Requirements 8.1**

### Property 10: Demo Mode banner is present on every dashboard page while Demo Mode is active

*For any* dashboard route rendered while `demoMode === true`, the `DemoModeBanner` component SHALL be present in the rendered output with the text "Viewing Demo Data."

**Validates: Requirements 4.3, 29.3**

---

## Error Handling

### Onboarding Errors

| Scenario | Handling |
|---|---|
| `projects.create` mutation throws | Show inline error banner with "Failed to create project. Please try again." and a Dismiss button. |
| `provisioningState === "failed"` | Show red error banner with "Provisioning failed." and a "Start over" button that resets to step 1. |
| Network offline during Terminal Handshake | Convex reactive query will reconnect automatically; show no additional error. |

### Demo Mode Errors

| Scenario | Handling |
|---|---|
| LiveTransition fires but Convex query returns null | Stay in Demo Mode; show toast "Connection established but no data yet. Run `sicario scan .` to populate." |

### Danger Zone Errors

| Scenario | Handling |
|---|---|
| `purgeTelemetry` throws authorization error | Show Toast variant="error" "Insufficient permissions to purge telemetry." |
| `deleteProject` throws authorization error | Show Toast variant="error" "Insufficient permissions to delete project." |
| `deleteProject` succeeds | Navigate to `/dashboard/projects` and show Toast variant="success" "Project deleted." |

### Slack Webhook Errors

| Scenario | Handling |
|---|---|
| URL does not start with `https://hooks.slack.com/` | Show inline validation error below the input field. Do not call mutation. |
| `updateAlertingConfig` mutation throws | Show Toast variant="error" "Failed to save alerting configuration." |
| "Test Webhook" fails | Show Toast variant="error" "Webhook test failed. Check the URL and try again." |

### API Key Errors

| Scenario | Handling |
|---|---|
| `regenerateApiKey` throws | Show Toast variant="error" "Failed to generate new key." |
| Clipboard write fails during copy | Show Toast variant="warning" "Could not copy to clipboard. Please copy manually." |

---

## Testing Strategy

### Unit Tests (Example-Based)

Focus on specific behaviors with concrete examples:

- `SnippetBlock` renders caption "Snippet only — full file never stored on this server"
- `TerminalBlock` renders macOS title bar with 3 colored dots
- `DemoModeBanner` renders with `role="alert"` and correct text
- `ExecutionAuditTrail` renders placeholder when `entries` is empty
- `ProjectSettingsView` renders 4 tabs in correct order
- `DangerZoneTab` renders red-bordered section
- `isValidSlackWebhookUrl` returns false for non-Slack URLs (example-based edge cases)
- `OverviewPage` does not render `AutoFixPanel`, `PrChecksPanel`, `AiFixesCard`
- `FindingDetailPage` does not render "Fix", "Create PR", "Commit" buttons
- `OnboardingV2Page` step 1 does not render repository URL field
- `DemoProject` constant has at least one finding per severity level
- `DemoProject` constant has at least one finding with `executionTrace.length >= 3`

### Property-Based Tests (Vitest + fast-check)

Each property test runs a minimum of 100 iterations. Tag format: `Feature: zero-exfil-dashboard-overhaul, Property N: <property_text>`.

**Property 1 — Demo Mode data shape** (TypeScript compile-time):
```typescript
// Enforced by TypeScript type checker — no runtime test needed.
// The DEMO_PROJECT, DEMO_FINDINGS, DEMO_SCAN constants are typed as:
//   const DEMO_PROJECT: Project = { ... }
//   const DEMO_FINDINGS: Finding[] = [ ... ]
// TypeScript will error at compile time if any field is missing or wrong type.
```

**Property 2 — Snippet fade-out**:
```typescript
// Feature: zero-exfil-dashboard-overhaul, Property 2: snippet fade-out only applies when snippet has > 1 line
fc.assert(fc.property(
  fc.string().filter(s => !s.includes('\n')),  // single-line snippets
  (snippet) => {
    const { container } = render(<SnippetBlock snippet={snippet} filePath="test.ts" line={1} />);
    expect(container.querySelectorAll('[data-testid="snippet-gradient"]')).toHaveLength(0);
  }
), { numRuns: 100 });

fc.assert(fc.property(
  fc.string().filter(s => s.includes('\n')),   // multi-line snippets
  (snippet) => {
    const { container } = render(<SnippetBlock snippet={snippet} filePath="test.ts" line={1} />);
    expect(container.querySelectorAll('[data-testid="snippet-gradient"]')).toHaveLength(2);
  }
), { numRuns: 100 });
```

**Property 5 — Delete confirmation**:
```typescript
// Feature: zero-exfil-dashboard-overhaul, Property 5: delete button enabled iff input === project name
fc.assert(fc.property(
  fc.string({ minLength: 1 }),  // project name
  fc.string(),                   // user input
  (projectName, userInput) => {
    const isEnabled = userInput === projectName;
    const { getByTestId } = render(
      <DangerZoneTab project={{ name: projectName }} />
    );
    const input = getByTestId('delete-confirm-input');
    fireEvent.change(input, { target: { value: userInput } });
    const button = getByTestId('delete-confirm-button');
    expect(button.disabled).toBe(!isEnabled);
  }
), { numRuns: 100 });
```

**Property 8 — Slack URL validation**:
```typescript
// Feature: zero-exfil-dashboard-overhaul, Property 8: Slack URL validation
fc.assert(fc.property(
  fc.string(),
  (url) => {
    const result = isValidSlackWebhookUrl(url);
    const expected = url.startsWith('https://hooks.slack.com/');
    expect(result).toBe(expected);
  }
), { numRuns: 100 });
```

**Property 9 — Remediation Handoff command**:
```typescript
// Feature: zero-exfil-dashboard-overhaul, Property 9: remediation command contains exact finding ID
fc.assert(fc.property(
  fc.string({ minLength: 1 }),  // finding ID
  (findingId) => {
    const { getByTestId } = render(<RemediationHandoff findingId={findingId} />);
    const command = getByTestId('remediation-command').textContent;
    expect(command).toContain(`sicario fix --id=${findingId}`);
  }
), { numRuns: 100 });
```

**Property 6 — purgeTelemetry no orphans** (Convex unit test):
```typescript
// Feature: zero-exfil-dashboard-overhaul, Property 6: purgeTelemetry deletes all findings and scans
// Uses Convex test harness (convex/convex/__tests__/)
// For any project with N findings and M scans, after purgeTelemetry:
//   - findings query returns []
//   - scans query returns []
```

**Property 7 — deleteProject idempotency** (Convex unit test):
```typescript
// Feature: zero-exfil-dashboard-overhaul, Property 7: deleteProject leaves no project record
// For any project, after deleteProject:
//   - projects.get returns null
//   - findings for project returns []
//   - scans for project returns []
```

### Integration Tests

- Terminal Handshake auto-navigation: mock Convex query returning `provisioningState: "active"`, assert `navigate` called.
- LiveTransition: mock first telemetry arrival, assert demo state cleared and live queries active.
- Demo Mode banner persistence: render multiple dashboard routes with `demoMode=true`, assert banner present on each.

### Accessibility Tests

- All data tables have `aria-label` attributes.
- All copy buttons have descriptive `aria-label` attributes.
- `DemoModeBanner` has `role="alert"`.
- "Waiting for edge telemetry…" indicator has `aria-live="polite"`.
- Terminal blocks have `role="region"` with `aria-label`.
- `ExecutionAuditTrail` has `role="list"` with `role="listitem"` entries.

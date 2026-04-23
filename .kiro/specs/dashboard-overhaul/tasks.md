# Implementation Plan: Dashboard Overhaul

## Overview

Transform the monolithic `sicario-frontend/src/pages/Dashboard.tsx` into a modular, multi-view security dashboard with React Router v7 nested routing, real-time Convex subscriptions, a comprehensive design system, and full backend integration. The implementation targets `sicario-frontend/` (React 19 + Vite 6 + Tailwind CSS v4 SPA). Every component must be fully functional with real Convex data — no mock data, no placeholders.

## Tasks

- [x] 1. Convex backend extensions and shared types
  - [x] 1.1 Add `userProfiles` table to Convex schema and create `convex/convex/userProfiles.ts` with `get`, `upsert`, `completeOnboarding`, and `skipOnboarding` functions
    - Add `userProfiles` table definition to `convex/convex/schema.ts` with fields: `userId`, `onboardingCompleted`, `onboardingCompletedAt`, `onboardingSkipped`, `role`, `teamSize`, `languages`, `cicdPlatform`, `goals`, `createdAt`, `updatedAt` and index `by_userId`
    - Create `convex/convex/userProfiles.ts` with query `get(userId)` and mutations `upsert`, `completeOnboarding`, `skipOnboarding`
    - All mutations must validate required fields and set timestamps
    - _Requirements: 21.11, 21.12, 23.16_

  - [x] 1.2 Add advanced analytics Convex functions
    - Add `topVulnerableProjects` query to `convex/convex/analytics.ts` — joins projects with findings, ranks by open finding count
    - Add `owaspCompliance` query — groups findings by `owaspCategory`, computes severity breakdown and compliance score per category
    - Add `findingsByLanguage` query — groups findings by language from scan `languageBreakdown`
    - _Requirements: 7.6, 14.2, 14.4, 18.1, 23.3, 23.4, 23.15_

  - [x] 1.3 Add advanced findings Convex functions
    - Add `listAdvanced` query to `convex/convex/findings.ts` — supports multi-value severity/state arrays, text search across ruleId/filePath/snippet, confidence range, reachability filter, server-side sort, cursor-based pagination
    - Add `getTimeline` query — returns triage state change history for a finding (derived from updatedAt)
    - Add `getAdjacentIds` query — returns previous/next finding IDs given current filters and current finding ID
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.8, 9.7, 9.8, 23.5, 23.6_

  - [x] 1.4 Create shared TypeScript types file at `sicario-frontend/src/types/dashboard.ts`
    - Define `Severity`, `TriageState`, `Finding`, `FindingFilters`, `OnboardingProfile`, `ToastMessage`, `PaletteCommand`, `ShortcutDef` interfaces as specified in the design
    - _Requirements: 1.1, 23.1_

- [x] 2. Install dependencies and configure Convex provider
  - [x] 2.1 Install new dependencies and create Convex client setup
    - Add `convex`, `recharts`, `jspdf`, `html2canvas`, `cmdk` to `sicario-frontend/package.json`
    - Create `sicario-frontend/src/lib/convex.ts` with `ConvexReactClient` initialized from `import.meta.env.VITE_CONVEX_URL`
    - Wrap the app in `ConvexProvider` in `sicario-frontend/src/main.tsx` or `App.tsx`
    - _Requirements: 23.1, 23.16_

  - [x] 2.2 Create utility modules
    - Create `sicario-frontend/src/lib/severity.ts` — severity color mapping, sort order helpers, severity-to-CSS-class functions using design tokens
    - Create `sicario-frontend/src/lib/owasp.ts` — OWASP Top 10 category ID-to-name mapping, category descriptions
    - Create `sicario-frontend/src/lib/pdf.ts` — PDF generation utility wrapping jsPDF + html2canvas with Sicario branding (logo, timestamps, page numbers)
    - _Requirements: 1.6, 14.2, 15.4_

- [x] 3. Design system UI primitives
  - [x] 3.1 Create core UI primitive components in `sicario-frontend/src/components/ui/`
    - `Button.tsx` — variants (primary, secondary, ghost, destructive), sizes (sm, md, lg), loading state with spinner, disabled state, visible keyboard focus ring meeting WCAG AA
    - `Input.tsx` — text input with error state, optional leading icon, focus ring
    - `Select.tsx` — dropdown with multi-select support, placeholder
    - `Checkbox.tsx` — checked, indeterminate (for select-all), onChange, label
    - `Badge.tsx` — variants (severity, state, default), color prop
    - All primitives use combined tokens from `index.css` and `design-tokens.css`, accept `className` prop
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 16.1, 16.2, 16.4_

  - [x] 3.2 Create layout and container UI primitives
    - `Card.tsx` — container with padding, optional hover border effect (rotating conic gradient), onClick
    - `Table.tsx` — data table with column definitions, sortable headers with direction indicators, row selection checkboxes, pagination controls
    - `Modal.tsx` — dialog with focus trap, Escape to close, returns focus to trigger on close, ARIA attributes
    - `Dropdown.tsx` — dropdown menu with keyboard arrow/Enter navigation
    - `Tabs.tsx` — tab navigation with active state
    - `Tooltip.tsx` — hover tooltip with configurable side
    - _Requirements: 1.3, 1.4, 16.2, 16.4, 16.6_

  - [x] 3.3 Create Skeleton and Toast primitives
    - `Skeleton.tsx` — shimmer loading placeholder with variants: text, card, chart, table-row, circle; configurable width/height
    - `Toast.tsx` — toast notification component managed by `useToast` hook; four variants (success, error, warning, info) with distinct icons and colors; stacking, auto-dismiss, manual dismiss button
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 4.1, 4.2, 4.3, 4.4, 4.5_

  - [x] 3.4 Write unit tests for UI primitives
    - Test Button variants, loading/disabled states, focus ring visibility
    - Test Modal focus trap and Escape-to-close behavior
    - Test Checkbox indeterminate state
    - Test Toast auto-dismiss timing and stacking
    - _Requirements: 1.4, 4.3, 16.6_

- [x] 4. Custom hooks
  - [x] 4.1 Create toast and filter hooks
    - `sicario-frontend/src/hooks/useToast.ts` — toast notification manager: `toast({ variant, title, message, duration? })`, `dismiss(id)`, auto-dismiss after 5s, stacking logic
    - `sicario-frontend/src/hooks/useFilters.ts` — filter state synced to URL search params via `useSearchParams`; `filters`, `setFilter`, `clearFilters`, `urlParams`
    - _Requirements: 4.1, 4.2, 4.3, 8.2, 8.3_

  - [x] 4.2 Create command palette and keyboard shortcut hooks
    - `sicario-frontend/src/hooks/useCommandPalette.ts` — `{ isOpen, open, close, search, results }`; fuzzy search across navigation targets + finding IDs from Convex
    - `sicario-frontend/src/hooks/useKeyboardShortcuts.ts` — registers global keyboard shortcuts, ignores when focus is in input/textarea/select; supports sequential key combos (G then O, G then F, etc.)
    - _Requirements: 5.1, 5.2, 5.7, 6.1, 6.2, 6.3_

  - [x] 4.3 Create Convex integration hooks
    - `sicario-frontend/src/hooks/useOptimisticTriage.ts` — wraps Convex `useMutation` for `findings.triage` and `findings.bulkTriage` with `optimisticUpdate`; reverts on error and shows error toast
    - `sicario-frontend/src/hooks/useOnboarding.ts` — `{ status, selections, saveStep, complete, skip }`; reads from `useQuery(api.userProfiles.get)`, writes via mutations
    - `sicario-frontend/src/hooks/useRbac.ts` — `{ role, canManageProjects, canManageMembers, canConfigureSSO, canManageWebhooks }`; reads from `useQuery(api.memberships.getForUser)`
    - `sicario-frontend/src/hooks/usePdfExport.ts` — `{ exportPdf(elementRef, title) }`; uses jsPDF + html2canvas from `lib/pdf.ts`
    - _Requirements: 17.1, 17.2, 17.3, 17.4, 21.11, 21.13, 10.6, 12.6, 13.5, 15.1, 15.2_

  - [x] 4.4 Write unit tests for custom hooks
    - Test useToast auto-dismiss and stacking behavior
    - Test useFilters URL sync round-trip
    - Test useKeyboardShortcuts ignores input fields
    - Test useOptimisticTriage rollback on error
    - _Requirements: 4.3, 6.3, 17.3_

- [x] 5. Dashboard layout shell and routing
  - [x] 5.1 Create DashboardLayout with Sidebar, Header, and ErrorBoundary
    - `sicario-frontend/src/pages/dashboard/DashboardLayout.tsx` — CSS Grid shell: collapsible sidebar (left), header (top), `<Outlet/>` (main content area); semantic HTML (`<nav>`, `<main>`, `<header>`); skip-to-content link
    - `sicario-frontend/src/components/dashboard/Sidebar.tsx` — collapsible navigation with icon-only mode below 768px, hamburger toggle; nav groups (Main, Reports, System); active route highlighting via `useLocation`; user avatar footer
    - `sicario-frontend/src/components/dashboard/Header.tsx` — breadcrumb trail from route, global search trigger (opens CommandPalette), theme toggle, user avatar dropdown
    - `sicario-frontend/src/components/dashboard/ErrorBoundary.tsx` — React error boundary wrapping each page; friendly error message with retry button
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 16.1, 16.4, 16.5, 20.1_

  - [x] 5.2 Set up React Router v7 nested routes under `/dashboard/*`
    - Update `sicario-frontend/src/App.tsx` to replace the single `/dashboard` route with nested routes: `/dashboard` (layout) → index (Overview), `/findings`, `/findings/:id`, `/projects`, `/projects/:id`, `/scans`, `/scans/:id`, `/owasp`, `/analytics`, `/settings`, `/onboarding`, `*` (404)
    - Create `sicario-frontend/src/pages/dashboard/NotFoundPage.tsx` — 404 page with navigation back to Overview
    - Ensure all routes are code-split via `React.lazy` for per-page bundles
    - _Requirements: 2.1, 20.4, 23.1_

  - [x] 5.3 Create CommandPalette and KeyboardShortcutsOverlay composites
    - `sicario-frontend/src/components/dashboard/CommandPalette.tsx` — Cmd/Ctrl+K overlay using `cmdk`; fuzzy search across navigation targets + finding IDs from Convex queries; keyboard arrow/Enter navigation; Escape to close
    - `sicario-frontend/src/components/dashboard/KeyboardShortcutsOverlay.tsx` — modal showing all keyboard shortcuts, triggered by `?` key
    - Register global shortcuts in DashboardLayout: G+O (Overview), G+P (Priority), G+F (Findings), G+A (Analytics), G+J (Projects), G+S (Scans), G+E (Settings)
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 6.1, 6.2, 6.3, 23.14_

- [ ] 6. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Chart components
  - [x] 7.1 Create Recharts visualization components in `sicario-frontend/src/components/charts/`
    - `FindingsTrendChart.tsx` — area chart showing open, new, fixed findings over time; interactive tooltips with exact values; responsive container; data from `useQuery(api.analytics.trends)`
    - `SeverityDonutChart.tsx` — donut/pie chart with severity color coding; hover-to-highlight interaction; data from `useQuery(api.analytics.overview)`
    - `MttrBarChart.tsx` — bar chart of MTTR broken down by severity; data from `useQuery(api.analytics.mttr)`
    - `ScanTimelineChart.tsx` — timeline showing scan frequency and finding counts over time; data from `useQuery(api.scans.list)`
    - `LanguageBreakdownChart.tsx` — chart showing findings by language; data from `useQuery(api.analytics.findingsByLanguage)`
    - All charts must include a data table fallback toggle for screen reader accessibility
    - All charts render from real Convex query results — no sample/random data
    - _Requirements: 7.3, 7.4, 7.5, 18.1, 18.2, 18.3, 18.4, 18.5, 18.6, 23.4_

- [x] 8. Overview page
  - [x] 8.1 Create OverviewPage with real-time metrics and charts
    - `sicario-frontend/src/pages/dashboard/OverviewPage.tsx` — top-level metrics row with animated counters (Total Findings, Open Findings, Fixed Findings, MTTR) from `useQuery(api.analytics.overview)` and `useQuery(api.analytics.mttr)`
    - `sicario-frontend/src/components/dashboard/StatCard.tsx` — animated counter card with icon, label, value, optional severity badge, click-to-navigate
    - Severity breakdown row with color-coded stat cards for Critical, High, Medium, Low, Info counts
    - Embed `FindingsTrendChart`, `SeverityDonutChart`, `MttrBarChart`
    - "Top Vulnerable Projects" table from `useQuery(api.analytics.topVulnerableProjects)`
    - Clicking a metric card or chart segment navigates to the relevant filtered Findings view
    - Skeleton loaders for all cards and charts while data loads; no layout shift on transition
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 3.1, 3.2, 3.3, 3.4, 23.3_

  - [x] 8.2 Implement onboarding gate on Overview
    - Query `useQuery(api.userProfiles.get)` on OverviewPage load
    - If `onboardingCompleted` is false, redirect to `/dashboard/onboarding`
    - If onboarding was skipped, show a non-intrusive banner offering to complete onboarding, dismissible via close button
    - _Requirements: 21.1, 21.13, 21.15, 22.9_

- [x] 9. Findings pages
  - [x] 9.1 Create FindingsPage with advanced filtering, sorting, bulk actions
    - `sicario-frontend/src/pages/dashboard/FindingsPage.tsx` — sortable, paginated data table using `useQuery(api.findings.listAdvanced)` with columns: Severity, Confidence, Rule, File, Line, State, Assigned To, Age
    - `sicario-frontend/src/components/dashboard/FilterBar.tsx` — multi-select severity, triage state, confidence slider, reachability toggle, text search; syncs to URL params via `useFilters`
    - `sicario-frontend/src/components/dashboard/FindingsTable.tsx` — sortable columns with direction indicators, row selection checkboxes, select-all toggle
    - `sicario-frontend/src/components/dashboard/BulkActionToolbar.tsx` — floating toolbar when rows selected: set triage state, assign, export selected; uses `useOptimisticTriage` for bulk operations
    - Display total count of findings matching current filters
    - Skeleton loaders for table rows while loading
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 3.1, 17.2, 23.5, 23.6_

  - [x] 9.2 Create FindingDetailPage with full metadata, code context, and triage workflow
    - `sicario-frontend/src/pages/dashboard/FindingDetailPage.tsx` — loads finding via `useQuery(api.findings.get, { id })` by route param
    - Structured metadata panel: severity badge, confidence score, reachability, CWE ID (linked to MITRE), OWASP category, file path with line numbers, fingerprint, timestamps
    - Code snippet with syntax highlighting, line numbers, vulnerable line highlighted
    - `sicario-frontend/src/components/dashboard/SeverityBadge.tsx` — color-coded severity indicator
    - `sicario-frontend/src/components/dashboard/TriageForm.tsx` — inline form: state selector, assignee autocomplete, notes textarea; saves via `useOptimisticTriage` with success toast
    - Finding timeline from `useQuery(api.findings.getTimeline)`
    - Previous/next navigation from `useQuery(api.findings.getAdjacentIds)`
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8, 17.1, 23.7, 23.8_

  - [x] 9.3 Write unit tests for FindingsTable and FilterBar
    - Test column sorting toggles direction indicator
    - Test row selection and select-all behavior
    - Test filter URL sync round-trip
    - Test bulk action toolbar appears/disappears with selection
    - _Requirements: 8.3, 8.4, 8.5, 8.6_

- [x] 10. Projects pages
  - [x] 10.1 Create ProjectsPage and ProjectDetailPage with real Convex data
    - `sicario-frontend/src/pages/dashboard/ProjectsPage.tsx` — card grid layout from `useQuery(api.projects.list)`; each card shows project name, repository URL, team assignment, last scan date, mini severity breakdown bar
    - Click card navigates to `/dashboard/projects/:id`
    - `sicario-frontend/src/pages/dashboard/ProjectDetailPage.tsx` — project metadata, scan history for project, findings summary by severity, trend charts scoped to project; all from Convex queries
    - "Create Project" form — accessible to manager/admin role only (checked via `useRbac`); calls `useMutation(api.projects.create)` with validation (required fields, URL format); success toast
    - "Edit Project" form — updates name, repository URL, description, team assignment via `useMutation(api.projects.update)`
    - If user lacks required RBAC role, hide create/edit controls and show read-only view
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 23.9_

- [x] 11. Scans pages
  - [x] 11.1 Create ScansPage and ScanDetailPage with real Convex data
    - `sicario-frontend/src/pages/dashboard/ScansPage.tsx` — paginated table from `useQuery(api.scans.list)` with columns: Repository, Branch, Commit SHA (truncated + copy-to-clipboard), Duration, Files Scanned, Rules Loaded, Findings Count, Timestamp
    - Filter controls for repository name and branch
    - Click row navigates to `/dashboard/scans/:id`
    - `sicario-frontend/src/pages/dashboard/ScanDetailPage.tsx` — full scan metadata from `useQuery(api.scans.get)`, language breakdown chart (`LanguageBreakdownChart`), findings table filtered to scan via `useQuery(api.findings.listAdvanced, { scanId })`
    - Scan timeline visualization (`ScanTimelineChart`) showing scan frequency and finding counts
    - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 23.1_

- [ ] 12. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 13. OWASP compliance and analytics pages
  - [x] 13.1 Create OwaspPage with compliance reporting
    - `sicario-frontend/src/pages/dashboard/OwaspPage.tsx` — table mapping each OWASP Top 10 category to finding count, severity breakdown, compliance status (pass/fail/warning) from `useQuery(api.analytics.owaspCompliance)`
    - Compliance score as percentage (resolved / total per category)
    - Click category row navigates to Findings filtered by that OWASP category
    - PDF export button using `usePdfExport` — generates branded PDF of the compliance report
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 15.1, 23.15_

  - [x] 13.2 Create AnalyticsPage with trend visualizations
    - `sicario-frontend/src/pages/dashboard/AnalyticsPage.tsx` — findings trend chart, severity distribution, MTTR breakdown, scan timeline, language breakdown; all from Convex analytics queries
    - PDF export button for the analytics view
    - _Requirements: 7.3, 7.4, 7.5, 18.1, 18.2, 18.3, 15.1, 23.4_

- [x] 14. Settings page — team management, SSO, webhooks
  - [x] 14.1 Create SettingsPage with members management tab
    - `sicario-frontend/src/pages/dashboard/SettingsPage.tsx` — tabbed layout (Members, SSO, Webhooks, Preferences)
    - Members tab: members table from `useQuery(api.memberships.list)` with columns: User, Role, Teams, Joined Date, Actions
    - "Add Member" form: user ID input, role selector (admin, manager, developer), team assignment multi-select; calls `useMutation(api.memberships.create)` with optimistic update
    - Inline role editing via dropdown in table; calls `useMutation(api.memberships.update)`
    - Remove member with confirmation dialog; calls `useMutation(api.memberships.remove)` with optimistic update
    - Organization hierarchy tree view: Organization → Teams → Projects with member counts
    - If user is not admin, hide management controls and show read-only hierarchy
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 17.4, 23.10_

  - [x] 14.2 Create SSO configuration tab
    - SSO tab: displays current SSO status (enabled/disabled) with provider details from `useQuery(api.sso.getConfig)`
    - Configuration form: provider type (SAML 2.0 / OpenID Connect), issuer URL, client ID, optional metadata URL; calls `useMutation(api.sso.configure)`
    - "Disable SSO" button with confirmation dialog; calls `useMutation(api.sso.disable)`
    - If user is not admin, hide SSO configuration controls
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5, 23.12_

  - [x] 14.3 Create webhooks management tab
    - Webhooks tab: webhooks table from `useQuery(api.webhooks.list)` with columns: URL, Events, Delivery Type, Status (enabled/disabled), Actions
    - "Create Webhook" form: URL, event type multi-select, delivery type, optional secret; calls `useMutation(api.webhooks.create)`
    - Inline toggle for enabling/disabling webhooks via `useMutation(api.webhooks.update)`
    - Delete webhook with confirmation dialog; calls `useMutation(api.webhooks.remove)`
    - If user is not admin, hide webhook management controls
    - _Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 23.11_

  - [x] 14.4 Create onboarding preferences tab
    - Preferences tab: displays current onboarding selections (role, team size, languages, CI/CD, goals) from `useQuery(api.userProfiles.get)`
    - Editable form to update any onboarding preference; calls `useMutation(api.userProfiles.upsert)`
    - Changes reflect immediately in dashboard personalization without page reload
    - _Requirements: 22.7, 22.8_

- [x] 15. Onboarding flow
  - [x] 15.1 Create OnboardingPage with multi-step wizard
    - `sicario-frontend/src/pages/dashboard/OnboardingPage.tsx` — renders `OnboardingWizard` composite
    - `sicario-frontend/src/components/dashboard/OnboardingWizard.tsx` — multi-step wizard with animated transitions (using `motion` library already installed), progress indicator, back/next navigation
    - Step 1 — Welcome: greeting with user's name, Sicario Cloud value proposition
    - Step 2 — Your Role: select from Security Engineer, Software Developer, DevOps/Platform Engineer, Engineering Manager, CISO/Security Lead, Other (free text)
    - Step 3 — Your Team: select team size (Just me, 2–10, 11–50, 51–200, 200+)
    - Step 4 — Your Stack: multi-select language grid (Go, Java, JavaScript/TypeScript, Python, Rust, Other)
    - Step 5 — Your Workflow: select CI/CD platform (GitHub Actions, GitLab CI, Jenkins, CircleCI, Bitbucket Pipelines, None/Manual, Other)
    - Step 6 — Your Goals: multi-select goals (Reduce vulnerabilities, Meet compliance requirements, Automate security in CI/CD, Triage findings faster, Get AI-powered fixes)
    - Final Step — You're All Set: summary of selections, "Get Started" CTA navigating to Overview, secondary "Install the CLI" link to Docs
    - "Skip for now" link visible on every step; calls `useMutation(api.userProfiles.skipOnboarding)` and navigates to Overview
    - Each step persists selections to Convex via `useOnboarding.saveStep`; completion calls `useOnboarding.complete`
    - Uses Design_System styling (dark theme, accent colors, card layouts, animations)
    - _Requirements: 21.1, 21.2, 21.3, 21.4, 21.5, 21.6, 21.7, 21.8, 21.9, 21.10, 21.11, 21.12, 21.14, 21.15_

- [x] 16. Onboarding-driven dashboard personalization
  - [x] 16.1 Implement personalization logic on Overview and Sidebar based on onboarding profile
    - Read onboarding profile from `useQuery(api.userProfiles.get)` in OverviewPage
    - If user selected languages: show findings/scan stats filtered to those languages by default with visible filter chip and clear option
    - If role is CISO/Security Lead or Engineering Manager: prioritize compliance and trend widgets above findings table
    - If role is Software Developer: prioritize recent findings list and AI remediation suggestions above aggregate metrics
    - If CI/CD platform selected: show platform-specific setup instructions in "Run Your First Scan" card (e.g., GitHub Actions YAML snippet)
    - If goal includes "Meet compliance requirements": highlight OWASP Compliance link in Sidebar with a recommended badge
    - If goal includes "Get AI-powered fixes": show "AI Fixes Available" card on Overview with count of findings with AI remediation
    - _Requirements: 22.1, 22.2, 22.3, 22.4, 22.5, 22.6_

- [x] 17. PDF export and empty states
  - [x] 17.1 Implement PDF export on Overview, Analytics, OWASP, and Finding Detail pages
    - `sicario-frontend/src/components/dashboard/PdfExport.tsx` — export button component that calls `usePdfExport`
    - Add PDF export button to OverviewPage, AnalyticsPage, OwaspPage, FindingDetailPage
    - Generated PDF includes Sicario logo, report title, date range, page numbers, charts rendered as images, generation timestamp
    - Show toast notification confirming PDF download started
    - _Requirements: 15.1, 15.2, 15.3, 15.4, 23.13_

  - [x] 17.2 Implement contextual empty states
    - `sicario-frontend/src/components/dashboard/EmptyState.tsx` — illustration, descriptive message, and CTA
    - Add empty states to: FindingsPage ("No findings yet. Run `sicario scan . --publish` to get started."), ProjectsPage, ScansPage, OwaspPage
    - Network error inline message with retry button on all pages
    - _Requirements: 20.2, 20.3, 23.17_

- [x] 18. Accessibility pass
  - [x] 18.1 Audit and fix accessibility across all dashboard components
    - Ensure all pages use semantic HTML (`nav`, `main`, `header`, `section`, `article`, `table`)
    - Add ARIA labels to all interactive elements lacking visible text labels
    - Verify all color combinations meet WCAG 2.1 AA contrast ratios (4.5:1 normal text, 3:1 large text)
    - Ensure all interactive elements reachable via keyboard Tab in logical order
    - Add skip-to-content links at top of each page
    - Ensure modals/overlays trap focus and return focus to trigger on close
    - Add text alternatives for all charts via `aria-label` or data table fallback
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5, 16.6, 16.7_

- [ ] 19. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Every component fetches real data from Convex — no mock data, no placeholders, no TODO comments
- All mutations call real Convex functions with proper error handling and toast notifications
- The `motion` library (already installed) is used for animations throughout
- The existing design tokens from `index.css` and `design-tokens.css` are the foundation for all styling
- Checkpoints ensure incremental validation of the implementation

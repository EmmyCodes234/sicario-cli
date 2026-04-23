# Requirements Document

## Introduction

Full overhaul of the Sicario Cloud Dashboard (`sicario-frontend/src/pages/Dashboard.tsx`) to match the quality, feature set, and UX polish of modern AppSec platforms like Semgrep and Snyk. The dashboard is part of the `sicario-frontend/` React 19 + Vite 6 + Tailwind CSS v4 single-page application, rendered at the `/dashboard` route via React Router DOM v7. The existing design system is defined in `sicario-frontend/src/index.css` with a dark theme (#1C1C1C backgrounds, #ADFF2F accent, Inter/JetBrains Mono fonts, noise texture, grid backgrounds, rotating conic borders, shimmer effects, chromatic aberration). The Supabase design tokens in `design-tokens.css` at the project root provide additional semantic color tokens (HSL-based foreground/background/border), typography families (Source Code Pro, Circular), border radii, and shadow elevations that must be integrated. This overhaul transforms the single-file Dashboard.tsx into a multi-view, production-grade security dashboard with rich data visualization, modern interaction patterns, comprehensive accessibility, and responsive design — targeting at least 95% positive UX and DX satisfaction.

## Glossary

- **Dashboard**: The cloud dashboard view rendered by `sicario-frontend/src/pages/Dashboard.tsx` at the `/dashboard` route, part of the React 19 + Vite 6 + Tailwind CSS v4 SPA in the `sicario-frontend/` directory
- **Convex_Backend**: The real-time backend in the `convex/` directory providing queries and mutations for findings, scans, projects, teams, memberships, analytics, webhooks, RBAC, and SSO. Note: the current Dashboard.tsx uses local mock data; this overhaul will wire it to the Convex backend
- **Finding**: A security vulnerability or issue detected by the Sicario CLI scanner, stored with severity, confidence score, reachability, CWE/OWASP classification, and triage state
- **Scan**: A single execution of the Sicario CLI against a repository, producing findings and metadata (duration, files scanned, rules loaded, language breakdown)
- **Project**: A repository or application registered in Sicario for ongoing security scanning
- **Triage_State**: The workflow state of a finding: Open, Reviewing, ToFix, Fixed, Ignored, or AutoIgnored
- **Severity**: The risk level of a finding: Critical, High, Medium, Low, or Info
- **RBAC**: Role-Based Access Control with three roles — admin, manager, developer — enforced by the Convex_Backend
- **MTTR**: Mean Time to Resolve — the average time from finding creation to resolution
- **Command_Palette**: A keyboard-activated overlay (Cmd/Ctrl+K) for quick navigation and actions
- **Skeleton_Loader**: A placeholder UI element that mimics the shape of content while data is loading
- **Toast_Notification**: A transient, non-blocking message displayed to confirm actions or report errors
- **Optimistic_Update**: A UI pattern where the interface reflects a mutation immediately before server confirmation
- **OWASP_Top_10**: The Open Web Application Security Project's list of the ten most critical web application security risks
- **Design_System**: The existing dark-theme visual system defined in `sicario-frontend/src/index.css` (#1C1C1C/#232323/#0A0A0A backgrounds, #ADFF2F accent, Inter for UI text, JetBrains Mono for code, noise texture overlay, grid backgrounds, rotating conic gradient borders, shimmer text, chromatic aberration effects) combined with the Supabase design tokens from `design-tokens.css` (HSL-based semantic color tokens, Source Code Pro/Circular typography, border radii, shadow elevations)
- **Sidebar_Navigation**: The fixed left-side navigation panel providing access to all Dashboard sections
- **Onboarding_Flow**: A multi-step, post-signup wizard that collects user context (role, team size, languages, CI/CD, goals) to personalize the Dashboard experience before landing on the main Overview page

## Requirements

### Requirement 1: Design System and UI Foundation

**User Story:** As a developer, I want a consistent, modern design system with reusable primitives, so that the Dashboard has a cohesive visual identity and new features can be built quickly.

#### Acceptance Criteria

1. THE Design_System SHALL use the existing dark-theme tokens from `sicario-frontend/src/index.css` (`--color-bg-main: #1c1c1c`, `--color-bg-card: #232323`, `--color-border-subtle: #2e2e2e`, `--color-text-main: #f4f4f5`, `--color-text-muted: #a1a1aa`, `--color-accent: #ADFF2F`) and integrate the Supabase semantic tokens from `design-tokens.css` (HSL-based foreground/background/border tokens, shadow elevations, border radii)
2. THE Design_System SHALL provide a dark theme as the default (preserving the existing noise texture overlay, grid background, rotating conic gradient borders, shimmer text, and chromatic aberration effects) and support a light theme toggle via the Supabase HSL custom property system
3. THE Design_System SHALL include reusable primitive components: Button, Input, Select, Checkbox, Badge, Card, Table, Modal, Dropdown, Tabs, and Tooltip — all styled using the combined token system
4. WHEN a primitive component receives focus via keyboard, THE Design_System SHALL display a visible focus indicator that meets WCAG 2.1 AA contrast requirements
5. THE Design_System SHALL use Inter (`--font-sans`) for UI text and JetBrains Mono (`--font-mono`) for code snippets and file paths, consistent with the existing `sicario-frontend` typography
6. THE Design_System SHALL define severity color tokens (Critical: red, High: amber, Medium: yellow, Low: blue, Info: gray) as extensions to the existing token system, using `--color-accent: #ADFF2F` for success/positive states and the Supabase `--destructive-default` token for destructive/critical actions

### Requirement 2: Responsive Layout Shell

**User Story:** As a user, I want the Dashboard layout to adapt to any screen size, so that I can use it on desktop, tablet, and mobile devices.

#### Acceptance Criteria

1. THE Dashboard SHALL render a collapsible Sidebar_Navigation on the left side with icon-only mode for narrow viewports
2. WHEN the viewport width is below 768px, THE Sidebar_Navigation SHALL collapse to an icon-only rail and provide a hamburger menu toggle
3. WHEN the viewport width is 768px or above, THE Sidebar_Navigation SHALL display full labels alongside icons
4. THE Dashboard SHALL render a top header bar containing a breadcrumb trail, global search trigger, theme toggle, and user avatar menu
5. THE Dashboard SHALL use CSS Grid or Flexbox layouts that reflow content gracefully from 4-column grids on desktop to single-column stacks on mobile
6. WHEN the user resizes the browser window, THE Dashboard SHALL reflow all content without horizontal scrolling at any viewport width from 320px to 2560px

### Requirement 3: Skeleton Loading States

**User Story:** As a user, I want to see placeholder shapes while data loads, so that the interface feels fast and I understand what content is coming.

#### Acceptance Criteria

1. WHILE data is loading from the Convex_Backend, THE Dashboard SHALL display Skeleton_Loader elements that match the shape and size of the expected content
2. THE Dashboard SHALL provide skeleton variants for: stat cards, tables, charts, detail panels, and list items
3. WHEN data finishes loading, THE Dashboard SHALL transition from Skeleton_Loader to real content without layout shift
4. THE Skeleton_Loader elements SHALL use a subtle shimmer animation to indicate loading activity

### Requirement 4: Toast Notification System

**User Story:** As a user, I want non-blocking feedback messages when I perform actions, so that I know whether my actions succeeded or failed without losing context.

#### Acceptance Criteria

1. WHEN a mutation succeeds (triage update, bulk triage, project creation, member addition), THE Dashboard SHALL display a success Toast_Notification with a descriptive message
2. WHEN a mutation fails, THE Dashboard SHALL display an error Toast_Notification with the error message
3. THE Toast_Notification SHALL appear in the bottom-right corner, stack vertically for multiple toasts, and auto-dismiss after 5 seconds
4. THE Toast_Notification SHALL include a manual dismiss button
5. THE Toast_Notification SHALL support four variants: success, error, warning, and info, each with a distinct icon and color

### Requirement 5: Command Palette

**User Story:** As a power user, I want a keyboard-activated command palette, so that I can navigate and perform actions without reaching for the mouse.

#### Acceptance Criteria

1. WHEN the user presses Cmd+K (macOS) or Ctrl+K (Windows/Linux), THE Dashboard SHALL open the Command_Palette overlay
2. THE Command_Palette SHALL display a search input that filters available commands and navigation targets in real time as the user types
3. THE Command_Palette SHALL include navigation commands for all Dashboard pages (Overview, Priority, Findings, Analytics, Projects, Scans, Settings)
4. THE Command_Palette SHALL include action commands for: export PDF, toggle theme, open finding by ID
5. WHEN the user selects a command, THE Command_Palette SHALL execute the action and close the overlay
6. WHEN the user presses Escape, THE Command_Palette SHALL close without executing any action
7. THE Command_Palette SHALL support keyboard navigation with arrow keys and Enter to select

### Requirement 6: Keyboard Shortcuts

**User Story:** As a power user, I want global keyboard shortcuts for common actions, so that I can work efficiently without leaving the keyboard.

#### Acceptance Criteria

1. THE Dashboard SHALL support the following global keyboard shortcuts: G then O for Overview, G then P for Priority, G then F for Findings, G then A for Analytics, G then J for Projects, G then S for Scans, G then E for Settings
2. WHEN the user presses the ? key outside of an input field, THE Dashboard SHALL display a keyboard shortcuts help overlay
3. THE Dashboard SHALL not trigger keyboard shortcuts when the user is typing in an input, textarea, or select element

### Requirement 7: Enhanced Security Overview Page

**User Story:** As a security lead, I want a rich overview dashboard with trend visualizations and key metrics at a glance, so that I can quickly assess the organization's security posture.

#### Acceptance Criteria

1. THE Dashboard SHALL display a top-level metrics row with animated counters for: Total Findings, Open Findings, Fixed Findings, and MTTR
2. THE Dashboard SHALL display a severity breakdown row with color-coded stat cards for Critical, High, Medium, Low, and Info counts
3. THE Dashboard SHALL render a findings trend area chart showing open, new, and fixed findings over the last 30 days with interactive tooltips
4. THE Dashboard SHALL render a severity distribution donut chart with hover-to-highlight interaction
5. THE Dashboard SHALL render a MTTR bar chart broken down by severity level
6. THE Dashboard SHALL display a "Top Vulnerable Projects" table ranked by open finding count
7. WHEN the user clicks on a metric card or chart segment, THE Dashboard SHALL navigate to the relevant filtered view (e.g., clicking Critical count navigates to Findings filtered by Critical severity)

### Requirement 8: Enhanced Findings List Page

**User Story:** As a security engineer, I want a powerful findings table with advanced filtering, sorting, and bulk actions, so that I can efficiently triage large volumes of findings.

#### Acceptance Criteria

1. THE Dashboard SHALL display findings in a sortable, paginated data table with columns: Severity, Confidence, Rule, File, Line, State, Assigned To, and Age
2. THE Dashboard SHALL provide filter controls for: severity (multi-select), triage state (multi-select), confidence range (slider), reachability (toggle), and text search across rule ID, file path, and snippet
3. WHEN the user applies filters, THE Dashboard SHALL update the URL query parameters so that filtered views are shareable via URL
4. THE Dashboard SHALL support column sorting by clicking column headers, with visual sort direction indicators
5. THE Dashboard SHALL support row selection via checkboxes with a select-all toggle
6. WHEN one or more rows are selected, THE Dashboard SHALL display a bulk action toolbar with options: set triage state, assign to user, and export selected
7. WHEN the user performs a bulk triage action, THE Dashboard SHALL apply an Optimistic_Update to reflect the change immediately before server confirmation
8. THE Dashboard SHALL display the total count of findings matching current filters

### Requirement 9: Enhanced Finding Detail Page

**User Story:** As a developer, I want a comprehensive finding detail view with code context, remediation guidance, and triage workflow, so that I can understand and resolve findings efficiently.

#### Acceptance Criteria

1. THE Dashboard SHALL display the finding's metadata in a structured panel: severity badge, confidence score, reachability status, CWE ID (linked to MITRE), OWASP category, file path with line numbers, fingerprint, and timestamps
2. THE Dashboard SHALL render the code snippet with syntax highlighting, line numbers, and the vulnerable line visually highlighted
3. THE Dashboard SHALL display AI-generated remediation guidance based on the finding's rule ID and CWE classification
4. THE Dashboard SHALL display an AI triage suggestion (True Positive, False Positive, Needs Review) with confidence reasoning
5. THE Dashboard SHALL provide an inline triage form with: state selector, assignee input with autocomplete, and notes textarea
6. WHEN the user saves a triage update, THE Dashboard SHALL apply an Optimistic_Update and display a success Toast_Notification
7. THE Dashboard SHALL display a finding timeline showing state transitions with timestamps and actor information
8. THE Dashboard SHALL provide navigation links to the previous and next finding in the current filtered list

### Requirement 10: Enhanced Projects Page

**User Story:** As a team lead, I want to manage projects with scan configuration and health summaries, so that I can oversee the security posture of each repository.

#### Acceptance Criteria

1. THE Dashboard SHALL display projects in a card grid layout showing: project name, repository URL, team assignment, last scan date, and a mini severity breakdown bar
2. WHEN the user clicks a project card, THE Dashboard SHALL navigate to a project detail page
3. THE Dashboard project detail page SHALL display: project metadata, scan history for that project, findings summary by severity, and trend charts scoped to the project
4. THE Dashboard SHALL provide a "Create Project" form accessible to users with manager or admin role
5. THE Dashboard SHALL provide an "Edit Project" form for updating name, repository URL, description, and team assignment
6. IF the user does not have the required RBAC role for project management, THEN THE Dashboard SHALL hide the create and edit controls and display a read-only view

### Requirement 11: Enhanced Scan History Page

**User Story:** As a developer, I want to browse scan history with detailed metadata and finding summaries, so that I can track scanning activity and investigate specific scan results.

#### Acceptance Criteria

1. THE Dashboard SHALL display scans in a paginated table with columns: Repository, Branch, Commit SHA (truncated with copy-to-clipboard), Duration, Files Scanned, Rules Loaded, Findings Count, and Timestamp
2. WHEN the user clicks a scan row, THE Dashboard SHALL navigate to a scan detail page
3. THE Dashboard scan detail page SHALL display: full scan metadata, language breakdown chart, and a findings table filtered to that scan
4. THE Dashboard SHALL provide filter controls for scan history: repository name and branch
5. THE Dashboard SHALL display a scan timeline visualization showing scan frequency and finding counts over time

### Requirement 12: Team and Organization Management

**User Story:** As an admin, I want to manage team members, roles, and organizational hierarchy, so that I can control access and organize security responsibilities.

#### Acceptance Criteria

1. THE Dashboard settings page SHALL display a members table with columns: User, Role, Teams, Joined Date, and Actions
2. THE Dashboard SHALL provide an "Add Member" form with user ID input, role selector (admin, manager, developer), and team assignment multi-select
3. THE Dashboard SHALL provide inline role editing via a dropdown selector in the members table
4. WHEN an admin removes a member, THE Dashboard SHALL display a confirmation dialog before executing the removal
5. THE Dashboard SHALL display an organization hierarchy tree view showing: Organization → Teams → Projects with member counts
6. IF the current user does not have admin role, THEN THE Dashboard SHALL hide member management controls and display a read-only view of the hierarchy

### Requirement 13: SSO Configuration

**User Story:** As an admin, I want to configure Single Sign-On for my organization, so that team members can authenticate using our identity provider.

#### Acceptance Criteria

1. THE Dashboard settings page SHALL display the current SSO configuration status (enabled/disabled) with provider details
2. THE Dashboard SHALL provide an SSO configuration form with fields: provider type (SAML 2.0 or OpenID Connect), issuer URL, client ID, and optional metadata URL
3. WHEN SSO is enabled, THE Dashboard SHALL display a success indicator with the active provider details
4. THE Dashboard SHALL provide a "Disable SSO" button with a confirmation dialog
5. IF the current user does not have admin role, THEN THE Dashboard SHALL hide SSO configuration controls

### Requirement 14: OWASP Compliance Reporting

**User Story:** As a compliance officer, I want to view findings mapped to OWASP Top 10 categories, so that I can assess compliance posture and generate reports.

#### Acceptance Criteria

1. THE Dashboard SHALL provide an OWASP compliance page accessible from the Sidebar_Navigation
2. THE Dashboard SHALL display a table mapping each OWASP Top 10 category to: finding count, severity breakdown, and compliance status (pass/fail/warning)
3. WHEN the user clicks an OWASP category row, THE Dashboard SHALL navigate to the Findings page filtered by that OWASP category
4. THE Dashboard SHALL display a compliance score as a percentage based on the ratio of resolved findings to total findings per category
5. THE Dashboard SHALL support exporting the OWASP compliance report as PDF

### Requirement 15: PDF Export Enhancement

**User Story:** As a security lead, I want to export comprehensive PDF reports from any Dashboard view, so that I can share security status with stakeholders who do not have Dashboard access.

#### Acceptance Criteria

1. THE Dashboard SHALL provide a PDF export button on the Overview, Analytics, OWASP Compliance, and Finding Detail pages
2. WHEN the user clicks the PDF export button, THE Dashboard SHALL generate a branded PDF document containing the current view's data, charts rendered as images, and a generation timestamp
3. THE Dashboard SHALL display a Toast_Notification confirming the PDF download has started
4. THE Dashboard PDF export SHALL include the Sicario logo, report title, date range, and page numbers

### Requirement 16: Accessibility Compliance

**User Story:** As a user with assistive technology, I want the Dashboard to be fully navigable and operable, so that I can use all features regardless of ability.

#### Acceptance Criteria

1. THE Dashboard SHALL use semantic HTML elements (nav, main, header, section, article, table) for all page structures
2. THE Dashboard SHALL provide ARIA labels for all interactive elements that lack visible text labels
3. THE Dashboard SHALL ensure all color combinations meet WCAG 2.1 AA contrast ratio requirements (4.5:1 for normal text, 3:1 for large text)
4. THE Dashboard SHALL ensure all interactive elements are reachable and operable via keyboard Tab navigation in a logical order
5. THE Dashboard SHALL provide skip-to-content links at the top of each page
6. WHEN a modal or overlay opens, THE Dashboard SHALL trap focus within the modal and return focus to the trigger element on close
7. THE Dashboard SHALL provide text alternatives for all chart visualizations via aria-label or a data table fallback

### Requirement 17: Optimistic Updates

**User Story:** As a user, I want the interface to respond instantly to my actions, so that the Dashboard feels fast and responsive even on slow connections.

#### Acceptance Criteria

1. WHEN the user updates a finding's triage state, THE Dashboard SHALL immediately reflect the new state in the UI before the Convex_Backend confirms the mutation
2. WHEN the user performs a bulk triage action, THE Dashboard SHALL immediately update all selected rows before server confirmation
3. IF an Optimistic_Update fails due to a server error, THEN THE Dashboard SHALL revert the UI to the previous state and display an error Toast_Notification
4. WHEN the user adds or removes a team member, THE Dashboard SHALL apply an Optimistic_Update to the members table

### Requirement 18: Data Visualization Library

**User Story:** As a user, I want interactive, accessible charts throughout the Dashboard, so that I can explore security data visually.

#### Acceptance Criteria

1. THE Dashboard SHALL use Recharts (already a dependency) for all chart visualizations
2. THE Dashboard SHALL provide interactive tooltips on all charts showing exact values on hover
3. THE Dashboard SHALL provide chart type options where applicable: area chart, bar chart, and line chart for trend data
4. WHEN the user hovers over a chart element, THE Dashboard SHALL highlight the corresponding data point and dim others
5. THE Dashboard SHALL render charts responsively, resizing to fit their container at any viewport width
6. THE Dashboard SHALL provide a data table fallback accessible via a toggle for each chart, supporting screen reader users

### Requirement 19: Webhook Management

**User Story:** As an admin, I want to manage webhook integrations from the Dashboard, so that I can configure automated notifications for security events.

#### Acceptance Criteria

1. THE Dashboard settings page SHALL display a webhooks table with columns: URL, Events, Delivery Type, Status (enabled/disabled), and Actions
2. THE Dashboard SHALL provide a "Create Webhook" form with fields: URL, event type multi-select, delivery type, and optional secret
3. THE Dashboard SHALL provide inline toggle for enabling/disabling webhooks
4. WHEN an admin deletes a webhook, THE Dashboard SHALL display a confirmation dialog before executing the deletion
5. IF the current user does not have admin role, THEN THE Dashboard SHALL hide webhook management controls

### Requirement 20: Error Boundary and Empty States

**User Story:** As a user, I want graceful error handling and helpful empty states, so that I always understand what happened and what to do next.

#### Acceptance Criteria

1. THE Dashboard SHALL wrap each page in a React error boundary that catches rendering errors and displays a friendly error message with a retry button
2. WHEN a Convex query returns an empty result set, THE Dashboard SHALL display a contextual empty state with an illustration, a descriptive message, and a call-to-action (e.g., "No findings yet. Run `sicario scan . --publish` to get started.")
3. IF a network error occurs during data fetching, THEN THE Dashboard SHALL display an inline error message with a retry button
4. THE Dashboard SHALL provide a global 404 page for unmatched routes with navigation back to the Overview

### Requirement 21: Post-Signup Onboarding Flow

**User Story:** As a new user who just signed up, I want a guided onboarding experience that asks me about my role, team, and goals, so that the Dashboard is personalized to my needs from the start.

#### Acceptance Criteria

1. WHEN a user signs up for the first time and has not completed onboarding, THE Dashboard SHALL redirect them to the Onboarding_Flow instead of the main Overview page
2. THE Onboarding_Flow SHALL present a multi-step wizard with smooth animated transitions between steps, a progress indicator showing current step and total steps, and back/next navigation
3. THE Onboarding_Flow SHALL include Step 1 — "Welcome" with a greeting, the user's name (from signup), and a brief value proposition for Sicario Cloud
4. THE Onboarding_Flow SHALL include Step 2 — "Your Role" asking the user to select their primary role from options: Security Engineer, Software Developer, DevOps/Platform Engineer, Engineering Manager, CISO/Security Lead, or Other (with free text input)
5. THE Onboarding_Flow SHALL include Step 3 — "Your Team" asking the user to select their team/organization size from options: Just me, 2–10, 11–50, 51–200, 200+
6. THE Onboarding_Flow SHALL include Step 4 — "Your Stack" asking the user to select the languages they scan from a multi-select grid: Go, Java, JavaScript/TypeScript, Python, Rust, with an "Other" option
7. THE Onboarding_Flow SHALL include Step 5 — "Your Workflow" asking the user to select their CI/CD platform from options: GitHub Actions, GitLab CI, Jenkins, CircleCI, Bitbucket Pipelines, None/Manual, or Other
8. THE Onboarding_Flow SHALL include Step 6 — "Your Goals" asking the user to select their primary goals from a multi-select list: Reduce vulnerabilities, Meet compliance requirements (OWASP/SOC2), Automate security in CI/CD, Triage findings faster, Get AI-powered fixes
9. THE Onboarding_Flow SHALL include a final Step — "You're All Set" with a summary of selections, a "Get Started" CTA button that navigates to the Dashboard Overview, and a secondary link to "Install the CLI" pointing to the Docs page
10. THE Onboarding_Flow SHALL allow the user to skip the entire onboarding via a "Skip for now" link visible on every step, which navigates directly to the Dashboard Overview
11. THE Onboarding_Flow SHALL persist the user's onboarding completion status and all selections to the Convex_Backend via a mutation, NOT to localStorage or client-side state alone
12. THE Convex_Backend SHALL store onboarding data in a user profile record including: `onboardingCompleted` (boolean), `onboardingCompletedAt` (timestamp), `role` (string), `teamSize` (string), `languages` (string array), `cicdPlatform` (string), `goals` (string array), and `onboardingSkipped` (boolean)
13. WHEN the Dashboard loads, it SHALL query the Convex_Backend for the current user's onboarding status and redirect to the Onboarding_Flow only if `onboardingCompleted` is false
14. THE Onboarding_Flow SHALL use the Design_System styling (dark theme, accent colors, card layouts, animations) consistent with the rest of the Dashboard
15. WHEN the user completes or skips the Onboarding_Flow, THE Dashboard SHALL navigate to the main Overview page

### Requirement 22: Onboarding-Driven Dashboard Personalization

**User Story:** As a user who completed onboarding, I want the Dashboard to reflect my selections, so that the experience is tailored to my role, stack, and goals rather than being generic.

#### Acceptance Criteria

1. WHEN the user selected languages during onboarding, THE Dashboard Overview SHALL display findings and scan statistics filtered to those languages by default, with a visible filter chip showing the active language filter and an option to clear it
2. WHEN the user selected "CISO/Security Lead" or "Engineering Manager" as their role, THE Dashboard Overview SHALL prioritize the compliance and trend visualization widgets (OWASP compliance score, findings trend chart, MTTR metrics) above the detailed findings table
3. WHEN the user selected "Software Developer" as their role, THE Dashboard Overview SHALL prioritize the recent findings list and AI remediation suggestions above aggregate metrics
4. WHEN the user selected a CI/CD platform during onboarding, THE Dashboard "Run Your First Scan" onboarding card SHALL display platform-specific setup instructions (e.g., GitHub Actions YAML snippet for GitHub Actions, `.gitlab-ci.yml` snippet for GitLab CI) instead of generic CLI instructions
5. WHEN the user selected "Meet compliance requirements (OWASP/SOC2)" as a goal, THE Sidebar_Navigation SHALL display the OWASP Compliance page link with a highlighted badge indicating it is recommended for them
6. WHEN the user selected "Get AI-powered fixes" as a goal, THE Dashboard Overview SHALL include a prominent "AI Fixes Available" card showing the count of findings with available AI remediation
7. THE Dashboard settings page SHALL include an "Onboarding Preferences" section where the user can view and update their onboarding selections (role, team size, languages, CI/CD, goals) at any time
8. WHEN the user updates their onboarding preferences in settings, THE Dashboard SHALL immediately reflect the updated personalization without requiring a page reload
9. IF the user skipped onboarding, THE Dashboard SHALL display a non-intrusive banner on the Overview page offering to complete onboarding to personalize their experience, dismissible via a close button

### Requirement 23: Full Functional Integration — No Placeholders

**User Story:** As a user, I want every Dashboard component to be fully functional with real data from the backend, so that the Dashboard is a production-grade tool and not a demo or mockup.

#### Acceptance Criteria

1. EVERY Dashboard view (Overview, Findings, Finding Detail, Projects, Scans, OWASP Compliance, Settings, Onboarding) SHALL fetch data from the Convex_Backend via real-time queries and subscriptions — no hardcoded mock data arrays, no placeholder values, and no `TODO` or `FIXME` comments in shipped code
2. EVERY mutation (triage state change, bulk triage, project creation, project edit, member addition, member removal, role change, webhook creation, webhook deletion, SSO configuration, onboarding save) SHALL call a real Convex mutation function and handle both success and error responses with appropriate Toast_Notifications
3. EVERY stat card on the Overview page SHALL compute its value from a Convex query that aggregates real finding/scan data — not from a static number or local calculation
4. EVERY chart (findings trend, severity distribution, MTTR, scan timeline, language breakdown) SHALL render from Convex query results with real timestamps and counts — not from generated/random sample data
5. THE findings table SHALL support real server-side pagination via Convex cursor-based queries, not client-side slicing of a fully-loaded array
6. THE findings table filters (severity, triage state, confidence, reachability, text search) SHALL pass filter parameters to Convex queries so that filtering happens server-side, not by hiding client-side rows
7. THE finding detail page SHALL load the full finding record from Convex by ID, including code snippet, AI remediation suggestion, and triage timeline — not from a cached list or local state
8. THE triage workflow (state change, assignee, notes) SHALL persist to Convex immediately and reflect in real-time across all connected clients via Convex subscriptions
9. THE project creation and edit forms SHALL validate inputs (required fields, URL format, duplicate names) and persist to Convex, with the new/updated project appearing in the projects list in real-time
10. THE team member management (add, remove, role change) SHALL call Convex RBAC mutations and enforce role permissions — admin-only actions SHALL be rejected by the backend if a non-admin attempts them, not just hidden in the UI
11. THE webhook management (create, delete, enable/disable) SHALL persist to Convex and the webhooks table SHALL reflect changes in real-time
12. THE SSO configuration form SHALL call a real Convex mutation to store provider settings and display the current configuration status from a Convex query
13. THE PDF export SHALL generate a real downloadable PDF file containing the current view's data and charts — not a browser print dialog or a placeholder "coming soon" message
14. THE command palette search SHALL query real navigation targets and finding IDs from the current Convex data, not a static list
15. THE OWASP compliance page SHALL compute compliance scores from real finding data grouped by OWASP category via Convex queries
16. IF the Convex_Backend does not yet have a required query or mutation for a Dashboard feature, THE implementation SHALL create the necessary Convex function in the `convex/convex/` directory as part of the task
17. EVERY loading state SHALL use Skeleton_Loaders that match the shape of the real content, and EVERY error state SHALL display a retry mechanism that re-fetches from Convex


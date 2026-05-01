# Requirements Document

## Introduction

This feature is a comprehensive overhaul of the Sicario web dashboard and onboarding flow to fully embody the "Zero-Exfiltration" architecture. The cloud dashboard is a strictly read-only telemetry receiver — it never touches source code, never triggers scans, and never pushes code changes. Every UI element must reinforce that all power lies in the developer's local terminal.

The overhaul has three phases:

1. **Surgical Removal**: Strip all GitHub App references, "Auto-Fix PR" panels, "Scan Now" buttons, "Connected Repos" banners, and any UI element that implies the cloud can act on code.
2. **Zero-Exfil Onboarding**: Replace the existing onboarding with a stark, terminal-first flow — project creation requires only a name, followed by a "Terminal Handshake" waiting room and a Demo Mode bypass.
3. **Command Center Rebuild**: Redesign the main dashboard, finding detail view, and project settings to be a premium, high-density, read-only monitor with a brutalist dark aesthetic.

The existing tech stack is React + TypeScript + Vite + Tailwind CSS (frontend), Convex TypeScript (backend), and `@convex-dev/auth`. The telemetry endpoint `POST /api/v1/telemetry/scan` already exists. The `projects` table already has `projectApiKey`. The `findings` table already has `executionTrace`.

---

## Glossary

- **Dashboard**: The Sicario React frontend application (`sicario-frontend/`).
- **Convex_Backend**: The Convex cloud deployment hosting HTTP endpoints, mutations, queries, and the database. Located under `convex/convex/`.
- **CLI**: The Sicario Rust CLI binary that performs all local scanning. The cloud never invokes it.
- **Telemetry_Endpoint**: The existing `POST /api/v1/telemetry/scan` HTTP endpoint that accepts structured scan findings from the CLI.
- **Project_API_Key**: The `projectApiKey` field on the `projects` table, prefixed `sic_proj_`, used by the CLI to authenticate telemetry submissions.
- **Demo_Mode**: A client-side state in which the Dashboard is populated with hard-coded mock data so users can explore the UI before running a real scan.
- **Terminal_Handshake**: The waiting-room screen shown after project creation, displaying CLI commands and a pulsing "Waiting for edge telemetry…" indicator.
- **Remediation_Handoff**: The UI panel on the finding detail page that displays a `sicario fix --id=<VULN_ID>` command for the developer to run locally — replacing any "Auto-Fix" or "Create PR" button.
- **Execution_Audit_Trail**: A read-only, monospace timeline rendered from the `executionTrace` array stored on each `findings` record.
- **AutoFixPanel**: The existing `AutoFixPanel.tsx` component that displays auto-fix PRs — to be removed.
- **PrChecksPanel**: The existing `PrChecksPanel.tsx` component that displays GitHub PR check results — to be removed from the Overview page.
- **OverviewPage**: The main dashboard landing page (`OverviewPage.tsx`).
- **OnboardingV2Page**: The existing onboarding wizard (`OnboardingV2Page.tsx`) — to be replaced.
- **FindingDetailPage**: The page showing a single finding's details (`FindingDetailPage.tsx`).
- **ProjectSettingsView**: A new per-project settings page with a 4-tab sidebar layout.
- **ProjectDetailPage**: The existing project detail page (`ProjectDetailPage.tsx`) — to be overhauled.
- **SettingsPage**: The existing org-level settings page (`SettingsPage.tsx`).
- **DemoProject**: The hard-coded mock project data used in Demo Mode.
- **LiveTransition**: The reactive event that purges Demo Mode data and renders live telemetry when the first real scan arrives.

---

## Requirements

### Requirement 1: Remove GitHub App and Auto-Fix UI Elements

**User Story:** As a product owner, I want all GitHub App references and auto-fix PR UI elements removed from the Dashboard, so that the UI accurately reflects the zero-exfiltration architecture and does not mislead users.

#### Acceptance Criteria

1. WHEN the Dashboard renders the OverviewPage, THE Dashboard SHALL NOT display the `AutoFixPanel` component or any panel referencing "Auto-Fix PRs."
2. WHEN the Dashboard renders the OverviewPage, THE Dashboard SHALL NOT display the `PrChecksPanel` component or any panel referencing "PR Security Checks" driven by GitHub App webhooks.
3. WHEN the Dashboard renders the OverviewPage, THE Dashboard SHALL NOT display the "connected repositories" banner that references GitHub repository URLs.
4. WHEN the Dashboard renders any page, THE Dashboard SHALL NOT display any button labeled "Scan Now," "Connect Repository," or "Install GitHub App."
5. WHEN the Dashboard renders the FindingDetailPage, THE Dashboard SHALL NOT display any button labeled "Fix," "Create PR," or "Commit."
6. WHEN the Dashboard renders the ProjectDetailPage, THE Dashboard SHALL NOT display the `githubAppInstallationId` field or any GitHub App installation reference.
7. THE Dashboard SHALL remove the `AutoFixPanel.tsx` component file or render it as a no-op, as it references the `autoFixPRs` Convex table which contradicts the zero-exfiltration model.
8. WHEN the Dashboard renders the OverviewPage, THE Dashboard SHALL NOT display the `AiFixesCard` component that implies cloud-side AI fix generation.

### Requirement 2: Zero-Exfil Onboarding — Project Creation Modal

**User Story:** As a new user, I want a stark, minimalist project creation experience that requires only a project name, so that onboarding reflects the zero-exfiltration model and removes all GitHub App OAuth steps.

#### Acceptance Criteria

1. WHEN a user navigates to the onboarding flow, THE Dashboard SHALL display a modal or full-screen form requiring only a `Project Name` text input (required) with no GitHub OAuth or repository connection fields.
2. WHEN the user submits the project creation form with a valid project name, THE Dashboard SHALL call the existing `projects.create` Convex mutation and receive back the `projectApiKey` and `projectId`.
3. IF the project name field is empty when the user submits, THEN THE Dashboard SHALL display an inline validation error and SHALL NOT submit the form.
4. WHEN the project creation form is displayed, THE Dashboard SHALL NOT include a "Repository URL" input field, a "Connect GitHub" button, or any OAuth redirect.
5. WHEN the project is successfully created, THE Dashboard SHALL immediately transition to the Terminal_Handshake waiting room screen without requiring any additional user input.
6. THE Dashboard SHALL display introductory copy stating that code never leaves the user's machine (e.g., "Your code never leaves your machine — scanning happens locally via the CLI.").

### Requirement 3: Zero-Exfil Onboarding — Terminal Handshake Waiting Room

**User Story:** As a new user, I want a terminal-style waiting room that shows me exactly which CLI commands to run, so that I can connect my local environment to the dashboard without any ambiguity.

#### Acceptance Criteria

1. WHEN the Terminal_Handshake screen is displayed, THE Dashboard SHALL render a styled terminal UI block containing the following commands in order: `npm install -g sicario-cli` (or the Homebrew equivalent), `sicario login --token=<PROJECT_API_KEY>`, `sicario link --project=<PROJECT_ID>`, `sicario scan .`.
2. WHEN the Terminal_Handshake screen is displayed, THE Dashboard SHALL display the actual `Project_API_Key` value (from the `projects.create` response) in the terminal block, visually highlighted to indicate it is a secret.
3. WHEN the Terminal_Handshake screen is displayed, THE Dashboard SHALL display the actual `projectId` value in the terminal block.
4. THE Dashboard SHALL provide a "Copy All" button that copies all four commands (with the real key and project ID substituted) to the clipboard as a single string.
5. WHEN the Terminal_Handshake screen is displayed, THE Dashboard SHALL show a pulsing animated indicator with the text "Waiting for edge telemetry…" to communicate that the app is waiting for the first CLI scan.
6. WHILE the Terminal_Handshake screen is displayed, THE Dashboard SHALL poll or subscribe (via Convex reactive query) to the project's `provisioningState` field and automatically navigate to the project dashboard WHEN the state transitions to `"active"`.
7. WHEN the project's `provisioningState` transitions to `"failed"`, THE Dashboard SHALL display an error state with a "Start over" button that returns the user to the project creation form.

### Requirement 4: Zero-Exfil Onboarding — Demo Mode Bypass

**User Story:** As a prospective user or evaluator, I want to explore the dashboard with realistic mock data before running a real scan, so that I can understand the product's value without needing to install the CLI first.

#### Acceptance Criteria

1. WHEN the Terminal_Handshake screen is displayed, THE Dashboard SHALL render a muted ghost button labeled "Explore Dashboard (Demo Mode)" below the terminal block.
2. WHEN the user clicks "Explore Dashboard (Demo Mode)", THE Dashboard SHALL unlock the full dashboard UI and populate it with a hard-coded DemoProject containing mock vulnerabilities (at least one Critical, one High, one Medium, one Low finding), truncated code snippets, and a mock Execution_Audit_Trail.
3. WHILE Demo_Mode is active, THE Dashboard SHALL display a persistent banner at the top of every dashboard page with the text "Viewing Demo Data. Run 'sicario scan .' locally to see live vulnerabilities." and a primary button labeled "Connect Your Code."
4. WHILE Demo_Mode is active, THE Dashboard SHALL NOT make any Convex queries for real project data — all displayed data SHALL come from the hard-coded DemoProject state.
5. WHEN the user clicks "Connect Your Code" in the Demo Mode banner, THE Dashboard SHALL open a modal overlay displaying the user's real `Project_API_Key`, `projectId`, and the four copyable terminal commands from Requirement 3.
6. THE Dashboard SHALL store the Demo_Mode state in React component state (not persisted to the backend), so that refreshing the page exits Demo Mode.

### Requirement 5: Zero-Exfil Onboarding — Go-Live Reactive Transition

**User Story:** As a user in Demo Mode, I want the dashboard to automatically switch to live data the moment my first real scan arrives, so that the transition from demo to production is seamless and dramatic.

#### Acceptance Criteria

1. WHILE the "Connect Your Code" modal is open, THE Dashboard SHALL subscribe to incoming telemetry for the user's real project via a Convex reactive query on the project's `provisioningState` field.
2. WHEN the Convex_Backend registers the first valid `POST /api/v1/telemetry/scan` for the project (causing `provisioningState` to transition to `"active"`), THE Dashboard SHALL automatically close the "Connect Your Code" modal.
3. WHEN the LiveTransition occurs, THE Dashboard SHALL purge all DemoProject mock data from React state and re-render all dashboard components using live Convex queries.
4. WHEN the LiveTransition occurs, THE Dashboard SHALL display a success toast notification with the text "Edge telemetry established. Live mode active."
5. WHEN the LiveTransition occurs, THE Dashboard SHALL NOT require any user interaction — the transition SHALL be fully automatic.

### Requirement 6: Command Center — Global Overview (Read-Only)

**User Story:** As a security engineer or CISO, I want a high-density, read-only overview of my project's security posture, so that I can monitor telemetry without any confusion about whether the cloud can trigger actions.

#### Acceptance Criteria

1. THE Dashboard SHALL display the following read-only metrics on the OverviewPage: Total Vulnerabilities Intercepted (total findings count), Edge Scans Executed (total scans count), and Mean Time to Remediate (MTTR in hours).
2. WHEN the OverviewPage is rendered, THE Dashboard SHALL NOT display any "Scan Now" button, "Trigger Scan" button, or any control that implies the cloud can initiate a scan.
3. THE Dashboard SHALL display a severity breakdown (Critical, High, Medium, Low counts) as stat cards with links to the filtered findings view.
4. THE Dashboard SHALL display a "Top Vulnerable Projects" table showing projects ranked by open finding count with severity mini-bars.
5. WHEN the OverviewPage has no findings data, THE Dashboard SHALL display an empty state that directs the user to run `sicario scan . --publish` locally, with no "Scan Now" button.
6. THE Dashboard SHALL apply the brutalist dark aesthetic: background `#0A0A0A`, high-contrast white text, muted slate gray secondary text, muted red for critical severity, matrix green for success states.

### Requirement 7: Command Center — Finding View (The Core Trust UI)

**User Story:** As a security engineer, I want the finding detail view to visually prove that only a truncated snippet exists on the server, so that I can demonstrate the zero-exfiltration guarantee to auditors and customers.

#### Acceptance Criteria

1. WHEN the FindingDetailPage renders a code snippet, THE Dashboard SHALL display the snippet in a monospace code block with a maximum of 500 characters rendered.
2. WHEN the FindingDetailPage renders a code snippet, THE Dashboard SHALL apply a CSS fade-out gradient at the top and bottom edges of the code block to visually imply that the rest of the file does not exist on the server.
3. WHEN the FindingDetailPage renders a code snippet, THE Dashboard SHALL display a caption or label beneath the code block stating that the snippet is truncated and the full file is never stored on the server (e.g., "Snippet only — full file never stored on this server").
4. WHEN the FindingDetailPage renders a finding with an AI-generated exploit explanation, THE Dashboard SHALL display the explanation in a dedicated "Vulnerability Proof" section.
5. THE Dashboard SHALL use JetBrains Mono or Geist Mono for all code snippets, file paths, and telemetry data displayed in the FindingDetailPage.
6. WHEN the FindingDetailPage renders a finding, THE Dashboard SHALL display the file path, line number, severity, CWE ID (if present), OWASP category (if present), confidence score, and fingerprint (truncated to 16 characters).

### Requirement 8: Command Center — Remediation Handoff (Replacing Auto-Fix)

**User Story:** As a CISO or security lead, I want a dedicated "Local Remediation Command" panel on the finding detail page, so that I can instantly copy a `sicario fix` command and paste it into Slack for my developers — without any cloud-side code modification.

#### Acceptance Criteria

1. WHEN the FindingDetailPage renders a finding, THE Dashboard SHALL display a "Local Remediation Command" panel containing a styled terminal block with the command `sicario fix --id=<FINDING_ID>` where `<FINDING_ID>` is the actual finding ID.
2. THE Dashboard SHALL provide a large, prominent "Copy to Clipboard" button in the Remediation_Handoff panel so that the command can be instantly shared.
3. WHEN the FindingDetailPage renders a finding, THE Dashboard SHALL NOT display any button labeled "Fix," "Auto-Fix," "Create PR," "Commit," or any control that implies the cloud can modify code.
4. THE Dashboard SHALL render the `sicario fix --id=<FINDING_ID>` command in a dark terminal block using monospace font, styled consistently with the Terminal_Handshake block from onboarding.
5. WHEN the user copies the remediation command, THE Dashboard SHALL display a brief visual confirmation (e.g., "Copied!" replacing the button label for 2 seconds).

### Requirement 9: Command Center — Execution Audit Trail

**User Story:** As a security auditor, I want a read-only, chronological execution trace displayed beneath the remediation command, so that I can verify exactly how the CLI detected the vulnerability.

#### Acceptance Criteria

1. WHEN the FindingDetailPage renders a finding that has a non-empty `executionTrace` array, THE Dashboard SHALL display an "Execution Audit Trail" section directly beneath the Remediation_Handoff panel.
2. THE Dashboard SHALL render each entry in the `executionTrace` array as a chronological timeline item in a read-only, monospace interface (e.g., `[14:02:01] ⚡ Local AST parsed in 0.04s`).
3. WHEN the FindingDetailPage renders a finding with an empty or absent `executionTrace`, THE Dashboard SHALL display a placeholder message (e.g., "No execution trace available for this finding.") in the Execution_Audit_Trail section.
4. THE Dashboard SHALL render the Execution_Audit_Trail in a scrollable container with a maximum height, so that long traces do not push other content off-screen.
5. THE Dashboard SHALL NOT provide any controls to edit, delete, or add entries to the Execution_Audit_Trail — it is strictly read-only.

### Requirement 10: Project Settings — CLI Integration Tab

**User Story:** As a developer, I want a dedicated CLI Integration tab in project settings that shows my project credentials and CLI commands, so that I can always retrieve my API key and re-run the setup commands.

#### Acceptance Criteria

1. THE Dashboard SHALL implement a `ProjectSettingsView` accessible from the ProjectDetailPage, with a left-hand sidebar navigating four tabs: "CLI Integration" (default), "Telemetry API Keys," "Alerting & Notifications," and "Danger Zone."
2. WHEN the "CLI Integration" tab is active, THE Dashboard SHALL display the Project Name, the raw `projectId` with a copy icon, and a terminal UI block containing `sicario login --token=<PROJECT_API_KEY>` and `sicario link --project=<PROJECT_ID>` commands.
3. WHEN the "CLI Integration" tab is active, THE Dashboard SHALL NOT display any GitHub repository connection string, OAuth button, or cloud LLM key input.
4. THE Dashboard SHALL provide individual copy buttons for the `projectId` and each CLI command in the "CLI Integration" tab.

### Requirement 11: Project Settings — Telemetry API Keys Tab

**User Story:** As a DevOps engineer, I want to manage multiple telemetry API keys for CI runners and local CLIs, so that I can rotate keys without disrupting all environments simultaneously.

#### Acceptance Criteria

1. WHEN the "Telemetry API Keys" tab is active, THE Dashboard SHALL display a table of active API keys showing: key name/label, masked key value (e.g., `sic_proj_••••••••••••••••`), creation date, and last-used date (if available).
2. WHEN the "Telemetry API Keys" tab is active, THE Dashboard SHALL provide a "Generate New Key" button that creates a new `Project_API_Key` via the `projects.regenerateApiKey` mutation.
3. WHEN a new key is generated, THE Dashboard SHALL display the full, unmasked key value exactly once in a modal or inline reveal, with a prominent warning that the key will not be shown again.
4. AFTER the new key modal is dismissed, THE Dashboard SHALL display the key in masked form only (e.g., `sic_proj_••••••••••••••••`).
5. THE Dashboard SHALL provide a "Revoke" action for each key that, when confirmed, invalidates the key so it can no longer authenticate telemetry submissions.
6. WHEN the user clicks "Revoke," THE Dashboard SHALL display a confirmation dialog before executing the revocation.

### Requirement 12: Project Settings — Alerting & Notifications Tab

**User Story:** As a security lead, I want to configure Slack webhook alerts for new findings above a severity threshold, so that my team is notified of critical vulnerabilities without polling the dashboard.

#### Acceptance Criteria

1. WHEN the "Alerting & Notifications" tab is active, THE Dashboard SHALL display an input form with a "Slack Webhook URL" text field.
2. WHEN the "Alerting & Notifications" tab is active, THE Dashboard SHALL display a dropdown to select the minimum severity threshold for outbound alerts, with options: "Critical only," "Critical & High," "Critical, High & Medium," "All severities."
3. WHEN the user saves the Slack webhook configuration, THE Dashboard SHALL validate that the URL begins with `https://hooks.slack.com/` before saving.
4. IF the Slack webhook URL is invalid, THEN THE Dashboard SHALL display an inline validation error and SHALL NOT save the configuration.
5. THE Dashboard SHALL provide a "Test Webhook" button that sends a test payload to the configured Slack webhook URL.

### Requirement 13: Project Settings — Danger Zone Tab

**User Story:** As a project admin, I want a clearly demarcated "Danger Zone" section for destructive actions, so that accidental data loss is prevented through explicit confirmation steps.

#### Acceptance Criteria

1. WHEN the "Danger Zone" tab is active, THE Dashboard SHALL display a section with a red border and red accent styling to visually communicate the destructive nature of the actions.
2. WHEN the "Danger Zone" tab is active, THE Dashboard SHALL display a "Purge Telemetry Data" action that, when confirmed, deletes all findings and scan records for the project.
3. WHEN the user clicks "Purge Telemetry Data," THE Dashboard SHALL display a confirmation dialog before executing the purge.
4. WHEN the "Danger Zone" tab is active, THE Dashboard SHALL display a "Delete Project" action that, when confirmed, destroys the project record and revokes all associated API keys.
5. WHEN the user clicks "Delete Project," THE Dashboard SHALL require the user to type the exact project name into a text input before the delete button becomes enabled.
6. WHEN the user types the correct project name and confirms deletion, THE Dashboard SHALL call the appropriate Convex mutation and redirect the user to the projects list page.
7. THE Dashboard SHALL NOT include any GitHub App disconnection, repository unlinking, or cloud LLM key deletion actions in the Danger Zone.

### Requirement 14: Visual Design System — Brutalist Dark Aesthetic

**User Story:** As a product owner, I want the dashboard to have a premium, brutalist, dark-mode aesthetic with high data density, so that it communicates security authority and reinforces the zero-exfiltration brand.

#### Acceptance Criteria

1. THE Dashboard SHALL use `#0A0A0A` (absolute black) as the primary background color for all dashboard pages.
2. THE Dashboard SHALL use high-contrast white (`#FFFFFF` or near-white) for primary text and muted slate gray for secondary/helper text.
3. THE Dashboard SHALL use muted red (e.g., `#DC2626` or similar) as the accent color for Critical severity indicators and destructive actions.
4. THE Dashboard SHALL use matrix green (e.g., `#22C55E` or similar) as the accent color for success states, "Live mode active" indicators, and clean scan results.
5. THE Dashboard SHALL use Inter or Geist as the sans-serif font for all UI text (labels, headings, body copy).
6. THE Dashboard SHALL use JetBrains Mono or Geist Mono as the monospace font for all code snippets, CLI commands, file paths, API keys, project IDs, and telemetry data.
7. THE Dashboard SHALL apply the monospace font to all terminal UI blocks (Terminal_Handshake, Remediation_Handoff, Execution_Audit_Trail, CLI Integration tab).
8. WHEN the Dashboard renders terminal UI blocks, THE Dashboard SHALL style them with a dark background (`#0D0D0D`), a macOS-style title bar with three colored dots (red/yellow/green), and a monospace font for all content.

### Requirement 15: Convex Backend — Purge Telemetry Mutation

**User Story:** As a project admin, I want a backend mutation that deletes all findings and scans for a project, so that the "Purge Telemetry Data" action in the Danger Zone has a safe, authorized implementation.

#### Acceptance Criteria

1. THE Convex_Backend SHALL expose a `projects.purgeTelemetry` mutation that accepts `projectId`, `userId`, and `orgId` arguments.
2. WHEN `projects.purgeTelemetry` is called, THE Convex_Backend SHALL verify that the calling user has at least the "manager" role in the specified organization before executing the purge.
3. WHEN `projects.purgeTelemetry` is called with valid authorization, THE Convex_Backend SHALL delete all `findings` records where `projectId` matches the specified project.
4. WHEN `projects.purgeTelemetry` is called with valid authorization, THE Convex_Backend SHALL delete all `scans` records where `projectId` matches the specified project.
5. IF the calling user does not have the required role, THEN THE Convex_Backend SHALL throw an authorization error without deleting any data.

### Requirement 16: Convex Backend — Delete Project Mutation

**User Story:** As a project admin, I want a backend mutation that destroys a project and revokes its API keys, so that the "Delete Project" action in the Danger Zone has a safe, authorized implementation.

#### Acceptance Criteria

1. THE Convex_Backend SHALL expose a `projects.deleteProject` mutation that accepts `projectId`, `userId`, and `orgId` arguments.
2. WHEN `projects.deleteProject` is called, THE Convex_Backend SHALL verify that the calling user has the "admin" role in the specified organization before executing the deletion.
3. WHEN `projects.deleteProject` is called with valid authorization, THE Convex_Backend SHALL delete the `projects` record for the specified project.
4. WHEN `projects.deleteProject` is called with valid authorization, THE Convex_Backend SHALL also execute the same purge logic as `projects.purgeTelemetry` (delete all associated findings and scans).
5. IF the calling user does not have the required role, THEN THE Convex_Backend SHALL throw an authorization error without deleting any data.
6. FOR ALL valid `deleteProject` calls, the project record SHALL NOT exist in the database after the mutation completes (deletion idempotency property).

### Requirement 17: Convex Backend — Slack Alerting Webhook Storage

**User Story:** As a backend developer, I want a schema and mutation for storing per-project Slack webhook configurations, so that the Alerting & Notifications tab has a persistent backend.

#### Acceptance Criteria

1. THE Convex_Backend SHALL add a `slackWebhookUrl` optional field (type `v.optional(v.string())`) to the `projects` table schema.
2. THE Convex_Backend SHALL add a `slackAlertSeverityThreshold` optional field (type `v.optional(v.string())`) to the `projects` table schema, accepting values `"Critical"`, `"High"`, `"Medium"`, `"Low"`.
3. THE Convex_Backend SHALL expose a `projects.updateAlertingConfig` mutation that accepts `projectId`, `userId`, `orgId`, `slackWebhookUrl`, and `slackAlertSeverityThreshold` arguments.
4. WHEN `projects.updateAlertingConfig` is called, THE Convex_Backend SHALL verify that the calling user has at least the "manager" role before saving.
5. WHEN `projects.updateAlertingConfig` is called with valid authorization, THE Convex_Backend SHALL update the `slackWebhookUrl` and `slackAlertSeverityThreshold` fields on the project record.

### Requirement 18: Demo Mode Data Integrity

**User Story:** As a developer, I want the Demo Mode mock data to be structurally identical to real telemetry data, so that the UI components render correctly in both demo and live modes without conditional branching.

#### Acceptance Criteria

1. THE Dashboard SHALL define the DemoProject mock data as a TypeScript constant that conforms to the same shape as the Convex `findings`, `scans`, and `projects` query return types.
2. THE DemoProject SHALL include at least one finding of each severity level: Critical, High, Medium, and Low.
3. THE DemoProject SHALL include at least one finding with a non-empty `executionTrace` array containing at least three entries in the format `[HH:MM:SS] <emoji> <description>`.
4. THE DemoProject SHALL include at least one finding with a truncated code snippet (50–500 characters) that demonstrates the fade-out visual effect.
5. FOR ALL DemoProject findings, the `snippet` field SHALL be 500 characters or fewer, consistent with the server-side truncation guarantee.
6. THE DemoProject SHALL include mock scan metadata (repository name, branch, commit SHA, duration, files scanned) that renders correctly in the scan history view.

### Requirement 19: Snippet Fade-Out Visual Correctness

**User Story:** As a product designer, I want the code snippet fade-out effect to be implemented as a pure CSS gradient overlay, so that it works correctly regardless of snippet length and does not clip actual vulnerability content.

#### Acceptance Criteria

1. THE Dashboard SHALL implement the snippet fade-out effect using a CSS `linear-gradient` overlay positioned absolutely over the top and bottom edges of the code block container.
2. THE Dashboard SHALL apply the fade-out gradient from the container background color (`#0A0A0A` or `#0D0D0D`) to transparent, covering approximately 20% of the container height at each edge.
3. THE Dashboard SHALL ensure the fade-out gradient does NOT obscure the vulnerable line itself — the gradient SHALL only apply to the context lines above and below the primary finding line.
4. WHEN the snippet contains only one line (no context lines), THE Dashboard SHALL NOT apply the fade-out gradient.
5. THE Dashboard SHALL ensure the code block container has `overflow: hidden` so that the gradient overlay clips correctly without scrollbars appearing within the fade zone.

### Requirement 20: Accessibility — Read-Only Monitor Compliance

**User Story:** As an accessibility-conscious developer, I want all read-only data displays to have appropriate ARIA labels and keyboard navigation, so that the dashboard is usable with assistive technologies.

#### Acceptance Criteria

1. THE Dashboard SHALL provide `aria-label` attributes on all data tables (findings table, scan history table, API keys table) describing their purpose.
2. THE Dashboard SHALL ensure all copy-to-clipboard buttons have `aria-label` attributes describing what will be copied (e.g., `aria-label="Copy sicario fix command"`).
3. THE Dashboard SHALL ensure the Demo Mode persistent banner has `role="alert"` so that screen readers announce it when it appears.
4. THE Dashboard SHALL ensure the "Waiting for edge telemetry…" pulsing indicator has `aria-live="polite"` so that screen readers announce status changes.
5. THE Dashboard SHALL ensure all terminal UI blocks have `role="region"` with a descriptive `aria-label` (e.g., `aria-label="CLI setup commands"`).
6. THE Dashboard SHALL ensure the Execution_Audit_Trail timeline has `role="list"` with each entry as a `role="listitem"`.


### Requirement 21: Findings List Page (FindingsPage)

**User Story:** As a security engineer, I want a high-density, filterable findings table that shows all telemetry-ingested vulnerabilities, so that I can triage and prioritize work without any cloud-side actions.

#### Acceptance Criteria

1. THE Dashboard SHALL display all findings in a sortable, paginated data table on the FindingsPage with columns: Severity, Rule ID, File Path, Line, Triage State, Project, and Age.
2. THE Dashboard SHALL provide filter controls for: severity (multi-select chips), triage state (multi-select), project (dropdown), and a text search across rule ID and file path.
3. WHEN the user applies filters, THE Dashboard SHALL update the URL query parameters so filtered views are shareable via URL.
4. WHEN the user clicks a finding row, THE Dashboard SHALL navigate to the FindingDetailPage for that finding.
5. THE Dashboard SHALL display the total count of findings matching current filters above the table.
6. WHEN the FindingsPage has no findings matching the current filters, THE Dashboard SHALL display an empty state with the message "No findings match your filters" and a "Clear filters" link.
7. WHEN the FindingsPage has no findings at all (empty project), THE Dashboard SHALL display an empty state directing the user to run `sicario scan . --publish` locally — with no "Scan Now" button.
8. THE Dashboard SHALL NOT display any bulk "Auto-Fix" or "Create PR" action in the findings table toolbar.
9. THE Dashboard SHALL support bulk triage state updates (e.g., mark as Ignored, mark as ToFix) via a checkbox selection and a triage dropdown — these are metadata-only operations that do not touch code.

### Requirement 22: Projects List Page (ProjectsPage)

**User Story:** As a team lead, I want a projects list that shows each project's telemetry health at a glance, so that I can quickly identify which repositories have the most critical findings.

#### Acceptance Criteria

1. THE Dashboard SHALL display all projects in a card grid or table on the ProjectsPage showing: project name, project ID (truncated with copy icon), last scan date, total findings count, and a severity mini-bar (Critical/High/Medium/Low breakdown).
2. WHEN the user clicks a project card or row, THE Dashboard SHALL navigate to the ProjectDetailPage for that project.
3. THE Dashboard SHALL provide a "New Project" button that opens the minimalist project creation modal (name only — no GitHub OAuth, no repository URL required).
4. WHEN the ProjectsPage has no projects, THE Dashboard SHALL display an empty state with a prominent "Create your first project" call-to-action.
5. THE Dashboard SHALL NOT display any "Connect Repository," "Install GitHub App," or "Sync Repos" button on the ProjectsPage.
6. THE Dashboard SHALL display each project's `provisioningState` as a status badge: "Pending" (waiting for first scan), "Active" (has received telemetry), or "Failed."
7. WHEN a project has `provisioningState: "pending"`, THE Dashboard SHALL display a "Setup CLI" link that navigates to the Terminal_Handshake screen for that project.

### Requirement 23: Project Detail Page (ProjectDetailPage)

**User Story:** As a developer, I want a project detail page that shows scan history, finding summaries, and CLI integration info — all read-only — so that I can monitor a specific project's security posture.

#### Acceptance Criteria

1. THE Dashboard SHALL display the ProjectDetailPage with the following sections: Project metadata (name, ID, creation date), CLI Integration summary (project API key masked, link to full settings), Findings severity breakdown, and Scan history table.
2. WHEN the ProjectDetailPage renders, THE Dashboard SHALL NOT display any "Connect Repository," "Install GitHub App," "Sync," or "Scan Now" button.
3. THE Dashboard SHALL display a "Settings" button/link that navigates to the ProjectSettingsView (4-tab layout from Requirements 10–13).
4. THE Dashboard SHALL display the project's `provisioningState` prominently — if `"pending"`, show the Terminal_Handshake instructions inline.
5. THE Dashboard SHALL display a scan history table scoped to the project with columns: Scan ID (truncated), Branch, Commit SHA (truncated, copy icon), Duration, Files Scanned, Findings Count, and Timestamp.
6. WHEN the user clicks a scan row, THE Dashboard SHALL navigate to the ScanDetailPage for that scan.
7. THE Dashboard SHALL display a findings severity breakdown bar for the project (total Critical/High/Medium/Low counts) with links to the filtered FindingsPage.

### Requirement 24: Scans List Page (ScansPage)

**User Story:** As a developer, I want a scan history page that shows all CLI-submitted scans across all projects, so that I can audit scanning activity and investigate specific scan results.

#### Acceptance Criteria

1. THE Dashboard SHALL display all scans in a paginated table on the ScansPage with columns: Scan ID (truncated), Repository, Branch, Commit SHA (truncated with copy icon), Duration, Files Scanned, Findings Count, and Timestamp.
2. WHEN the user clicks a scan row, THE Dashboard SHALL navigate to the ScanDetailPage for that scan.
3. THE Dashboard SHALL provide filter controls for: project/repository name and branch.
4. WHEN the ScansPage has no scans, THE Dashboard SHALL display an empty state directing the user to run `sicario scan . --publish` locally — with no "Trigger Scan" button.
5. THE Dashboard SHALL NOT display any "Trigger Scan," "Re-run Scan," or "Schedule Scan" button — scans are always initiated locally by the CLI.
6. THE Dashboard SHALL display each scan's source as "Edge CLI" to reinforce that scans originate locally.

### Requirement 25: Scan Detail Page (ScanDetailPage)

**User Story:** As a developer, I want a scan detail page that shows the full metadata and findings for a specific CLI scan, so that I can investigate what was found in a particular commit.

#### Acceptance Criteria

1. THE Dashboard SHALL display the ScanDetailPage with: full scan metadata (repository, branch, commit SHA, duration, files scanned, rules loaded, language breakdown), and a findings table filtered to that scan.
2. THE Dashboard SHALL display the commit SHA in full with a copy-to-clipboard button.
3. THE Dashboard SHALL display the language breakdown as a horizontal bar chart or percentage list.
4. WHEN the user clicks a finding row in the scan's findings table, THE Dashboard SHALL navigate to the FindingDetailPage for that finding.
5. THE Dashboard SHALL NOT display any "Re-run," "Trigger," or "Schedule" button on the ScanDetailPage.
6. THE Dashboard SHALL display a "Source: Edge CLI" badge on the ScanDetailPage to reinforce the zero-exfiltration model.
7. WHEN the ScanDetailPage has no findings, THE Dashboard SHALL display an empty state with the message "No findings detected in this scan — clean edge scan."

### Requirement 26: OWASP Compliance Page (OwaspPage)

**User Story:** As a compliance officer, I want an OWASP Top 10 compliance view that maps telemetry findings to OWASP categories, so that I can assess compliance posture from CLI-submitted scan data.

#### Acceptance Criteria

1. THE Dashboard SHALL display the OwaspPage with a table mapping each OWASP Top 10 category to: finding count, severity breakdown, and compliance status (pass/fail/warning based on open findings).
2. WHEN the user clicks an OWASP category row, THE Dashboard SHALL navigate to the FindingsPage filtered by that OWASP category.
3. THE Dashboard SHALL display a compliance score as a percentage based on resolved vs. total findings per category.
4. THE Dashboard SHALL display a "Data source: Edge CLI telemetry" label to reinforce that compliance data comes from local scans, not cloud-side analysis.
5. THE Dashboard SHALL NOT display any "Run Compliance Scan" or "Trigger OWASP Scan" button.
6. THE Dashboard SHALL support exporting the OWASP compliance report as a PDF.

### Requirement 27: Analytics Page (AnalyticsPage)

**User Story:** As a security lead, I want an analytics page with trend charts and MTTR metrics derived from CLI telemetry, so that I can track security posture improvement over time.

#### Acceptance Criteria

1. THE Dashboard SHALL display the AnalyticsPage with: a findings trend area chart (open, new, fixed over last 30 days), a severity distribution chart, an MTTR bar chart broken down by severity, and a scan frequency chart.
2. ALL charts on the AnalyticsPage SHALL be derived from telemetry data ingested via `POST /api/v1/telemetry/scan` — no cloud-side analysis.
3. THE Dashboard SHALL display a "Data source: Edge CLI telemetry" label on the AnalyticsPage.
4. THE Dashboard SHALL NOT display any "Run Analysis," "Trigger Scan," or "Refresh Data" button that implies cloud-side computation.
5. WHEN the AnalyticsPage has insufficient data (fewer than 2 scans), THE Dashboard SHALL display an empty state directing the user to run more scans locally.
6. THE Dashboard SHALL provide interactive tooltips on all charts showing exact values on hover.

### Requirement 28: Settings Page (SettingsPage — Org Level)

**User Story:** As an org admin, I want an org-level settings page for managing members, teams, and webhooks — without any GitHub App or cloud scanning configuration, so that settings reflect the zero-exfiltration architecture.

#### Acceptance Criteria

1. THE Dashboard SHALL display the SettingsPage with sections for: Members, Teams, Webhooks, and Account.
2. THE Dashboard SHALL NOT display any "GitHub App," "Repository Connection," "Cloud Scanning," or "LLM API Keys" section in the SettingsPage.
3. WHEN the Members section is displayed, THE Dashboard SHALL show a table of org members with columns: User, Role, Teams, and Actions (edit role, remove).
4. THE Dashboard SHALL provide an "Invite Member" form with email input and role selector (admin, manager, developer).
5. WHEN the Webhooks section is displayed, THE Dashboard SHALL show a table of configured webhooks with URL, events, and enabled/disabled status — these are outbound notification webhooks, not GitHub inbound webhooks.
6. THE Dashboard SHALL provide a "Create Webhook" form for outbound notification webhooks (URL, event types, optional secret).
7. THE Dashboard SHALL NOT display any "GitHub Webhook Secret," "GitHub App Installation," or "Repository Sync" configuration in the Webhooks section.

### Requirement 29: Dashboard Layout — Sidebar Navigation & Demo Banner

**User Story:** As a user, I want the sidebar navigation and global layout to reinforce the zero-exfiltration model, so that every page communicates that the dashboard is a read-only telemetry monitor.

#### Acceptance Criteria

1. THE Dashboard sidebar SHALL display the following navigation items grouped as shown in the existing UI: MAIN (Overview, Findings, Projects, Scans), REPORTS (OWASP, Analytics), SYSTEM (Settings).
2. THE Dashboard sidebar SHALL display a "Zero-Exfiltration: Telemetry Mode" badge or indicator at the bottom of the sidebar to permanently reinforce the architecture.
3. WHILE Demo_Mode is active, THE Dashboard SHALL display the persistent demo banner (from Requirement 4) at the very top of the main content area on every page, above all other content.
4. THE Dashboard sidebar SHALL NOT display any "GitHub," "Repositories," "Auto-Fix," or "PR Checks" navigation item.
5. THE Dashboard layout SHALL apply the brutalist dark aesthetic globally: `#0A0A0A` background, no rounded corners on primary containers, high-contrast borders using `1px solid` slate gray lines.
6. THE Dashboard layout SHALL be fully responsive, collapsing the sidebar to an icon-only rail on viewports below 768px.

### Requirement 30: PR Check Detail Page (PrCheckDetailPage)

**User Story:** As a CI pipeline operator, I want the PR check detail page to show CLI-submitted CI scan results without any GitHub Check Run references, so that the page accurately reflects the zero-exfiltration model.

#### Acceptance Criteria

1. THE Dashboard SHALL retain the PrCheckDetailPage route (`/dashboard/pr-checks/:checkId`) for displaying CI scan results submitted via the Telemetry_Endpoint with a `prNumber` field.
2. WHEN the PrCheckDetailPage renders, THE Dashboard SHALL NOT display the `githubCheckRunId` field or any "View on GitHub" link.
3. THE Dashboard SHALL display the PR check result as: PR number, repository URL, status (passed/failed/blocked), findings count, critical count, high count, and the associated scan ID.
4. WHEN the PrCheckDetailPage renders a failed check, THE Dashboard SHALL display the `sicario fix --id=<FINDING_ID>` Remediation_Handoff command for each critical/high finding.
5. THE Dashboard SHALL display a "Source: Edge CLI (CI pipeline)" label to indicate the check was submitted by the CLI running in CI, not by a GitHub App.
6. WHEN the PrCheckDetailPage has no associated findings, THE Dashboard SHALL display "No findings — clean CI scan."

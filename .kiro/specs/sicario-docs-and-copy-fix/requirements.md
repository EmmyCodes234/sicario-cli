# Requirements Document

## Introduction

This feature covers three related workstreams for the Sicario project:

1. **Copy Fixes** — Correct 15 factual inconsistencies found across the existing pages (`Home.tsx`, `Product.tsx`, `Pricing.tsx`, `FAQ.tsx`, `Docs.tsx`, `Download.tsx`, `Privacy.tsx`). These range from a critical license misrepresentation (MIT vs. FSL-1.1) to wrong CLI flags, wrong URLs, and missing feature details.

2. **Multi-Page Docs System** — Replace the current single-page `Docs.tsx` with a proper multi-page documentation experience. Each of the 16 documentation sections becomes its own React page under `sicario-frontend/src/pages/docs/`, routed at `/docs/<section>`. The existing `/docs` route redirects to `/docs/overview`.

3. **Homebrew Tap** — Create the `sicario-labs/homebrew-sicario-cli` GitHub repository with a working `Formula/sicario.rb`, and add an auto-update step to `.github/workflows/release.yml` so the formula SHA256 and version are bumped automatically on every release tag. This makes `brew install sicario-labs/sicario-cli/sicario` functional, which is currently documented but broken (the tap repo does not exist).

The canonical sources of truth are: `README.md`, `sicario-cli/src/key_manager/provider_registry.rs` (19 LLM providers), `sicario-cli/src/config/global_config.rs` (config keys), `sicario-cli/src/remediation/llm_client.rs` (AI remediation), `install.sh` (installation URLs), and `.github/workflows/release.yml` (release artifact naming).

---

## Glossary

- **Copy_Fix_System**: The subsystem responsible for correcting factual copy errors across existing frontend pages.
- **Docs_System**: The multi-page documentation subsystem rendered under the `/docs/*` routes.
- **Docs_Page**: A single React component representing one documentation section, located in `sicario-frontend/src/pages/docs/`.
- **Sidebar**: The left-hand navigation component shared across all Docs_Pages, grouping sections and highlighting the active route.
- **CodeBlock**: The existing reusable component that renders a syntax-highlighted code snippet with a copy-to-clipboard button.
- **Router**: The React Router v6 instance that manages all frontend routes.
- **FSL-1.1**: The Functional Source License version 1.1 — the actual license governing Sicario CLI.
- **BYOK**: Bring Your Own Key — the model where users supply their own LLM API key.
- **MCP_Server**: The Model Context Protocol server built into the Sicario CLI for AI assistant integration.
- **OSV**: The Open Source Vulnerabilities database (osv.dev) used by the SCA scanner.
- **SARIF**: Static Analysis Results Interchange Format v2.1.0.
- **OAuth_Device_Flow**: The OAuth 2.0 device authorization grant flow used by `sicario login` — browser approval, no token copy-paste.
- **Provider_Registry**: The static list of 19 supported LLM provider presets defined in `provider_registry.rs`.
- **Homebrew_Tap**: The `sicario-labs/homebrew-sicario-cli` GitHub repository that Homebrew clones when a user runs `brew tap sicario-labs/sicario-cli` or `brew install sicario-labs/sicario-cli/sicario`.
- **Homebrew_Formula**: The Ruby file at `Formula/sicario.rb` inside the tap repo that describes how to install the Sicario binary on macOS.
- **HOMEBREW_TAP_TOKEN**: A GitHub Personal Access Token with `repo` write scope on the tap repo, stored as a secret on `sicario-labs/sicario-cli`, used by the release workflow to auto-commit formula updates.
- **bump-homebrew-formula-action**: The `mislav/bump-homebrew-formula-action` GitHub Action that updates the formula version and SHA256 checksums after each release.

---

## Requirements

### Requirement 1: License Representation

**User Story:** As a user reading any page on the Sicario website, I want to see the correct license name, so that I understand the actual legal terms governing the software.

#### Acceptance Criteria

1. THE Copy_Fix_System SHALL replace every occurrence of "MIT licensed" or "MIT license" with "FSL-1.1 (Functional Source License)" across all frontend pages.
2. THE Copy_Fix_System SHALL update the Download page trust badge that currently reads "MIT licensed, auditable" to read "FSL-1.1 licensed, source-available".
3. WHEN a user views the Docs page Licensing section, THE Docs_System SHALL state that Sicario is governed by the Functional Source License 1.1 (FSL-1.1) with Apache License 2.0 as the Change License.
4. THE Docs_System SHALL state that FSL-1.1 converts to Apache 2.0 two years after each version's first public release.

---

### Requirement 2: `sicario publish` Command Description

**User Story:** As a developer reading the documentation, I want an accurate description of what `sicario publish` does, so that I use it correctly.

#### Acceptance Criteria

1. THE Copy_Fix_System SHALL update the Docs page description of `sicario publish` from "Publish custom rules to the Sicario Cloud registry" to "Upload scan results to the Sicario Cloud dashboard".
2. WHEN a user views the `publish` command section in the Docs_System, THE Docs_System SHALL describe `sicario publish` as the command that uploads locally-generated scan results to the Sicario Cloud dashboard for team visibility.
3. THE Docs_System SHALL NOT describe `sicario publish` as publishing custom rules.

---

### Requirement 3: `sicario fix` Rule ID Format

**User Story:** As a developer using `sicario fix`, I want the documented rule ID format to match the actual CLI format, so that my commands work without trial and error.

#### Acceptance Criteria

1. THE Copy_Fix_System SHALL replace all occurrences of the `SQL-001`-style rule ID format with the canonical `language/rule-name` format (e.g., `js/sql-injection`) across all frontend pages.
2. WHEN a user views the `fix` command documentation in the Docs_System, THE Docs_System SHALL show example invocations using the `language/rule-name` format (e.g., `sicario fix src/db.js --rule js/sql-injection`).
3. THE Docs_System SHALL NOT show rule IDs in the `LANG-NNN` numeric format.

---

### Requirement 4: AI Remediation Template Fallback

**User Story:** As a developer without an LLM API key, I want to know that template-based fixes are available, so that I can still remediate common vulnerabilities.

#### Acceptance Criteria

1. THE Copy_Fix_System SHALL add a mention of template-based fallback fixes to every page that describes AI remediation, noting that fixes for SQL injection, XSS, and command injection work without an API key.
2. WHEN a user views the AI Remediation section in the Docs_System, THE Docs_System SHALL document that template-based fallback fixes are available for SQL injection, XSS, and command injection without requiring an LLM API key.
3. WHEN a user views the Pricing page Community tier, THE Copy_Fix_System SHALL add AI remediation (BYOK + template fallbacks) to the list of Community tier features.

---

### Requirement 5: MCP Server Integration List

**User Story:** As a developer wanting to connect Sicario to my AI assistant, I want an accurate list of supported AI assistants, so that I know whether my tool is supported.

#### Acceptance Criteria

1. THE Copy_Fix_System SHALL replace all occurrences of "Cursor, Copilot" or "Cursor, GitHub Copilot" in MCP server descriptions with "Claude, Cursor, Kiro".
2. WHEN a user views the MCP Server section in the Docs_System, THE Docs_System SHALL list Claude, Cursor, and Kiro as the confirmed supported AI assistants.
3. THE Docs_System SHALL NOT list GitHub Copilot as a confirmed MCP integration.

---

### Requirement 6: SCA Description Completeness

**User Story:** As a developer evaluating Sicario's SCA capabilities, I want to know about the local SQLite cache and which manifest files are supported, so that I can assess compatibility with my project.

#### Acceptance Criteria

1. THE Copy_Fix_System SHALL update all SCA descriptions to mention the local SQLite cache and the supported manifest files: `package.json`, `Cargo.toml`, and `requirements.txt`.
2. WHEN a user views the SCA section in the Docs_System, THE Docs_System SHALL state that vulnerability data is cached locally in a SQLite database.
3. WHEN a user views the SCA section in the Docs_System, THE Docs_System SHALL list `package.json`, `Cargo.toml`, and `requirements.txt` as the supported manifest files.

---

### Requirement 7: Installation URL Consistency

**User Story:** As a developer installing Sicario, I want all installation URLs to be correct and consistent, so that my install command succeeds on the first try.

#### Acceptance Criteria

1. THE Copy_Fix_System SHALL replace all occurrences of `https://install.usesicario.xyz` with `https://usesicario.xyz/install.sh` across all frontend pages.
2. WHEN a user views any installation instruction in the Docs_System, THE Docs_System SHALL use `https://usesicario.xyz/install.sh` as the canonical curl installer URL.
3. THE Docs_System SHALL NOT reference `https://install.usesicario.xyz` or any other non-canonical installation URL.

---

### Requirement 8: Homebrew Tap Correctness

**User Story:** As a macOS developer installing Sicario via Homebrew, I want the correct tap and formula name, so that `brew install` succeeds.

#### Acceptance Criteria

1. THE Copy_Fix_System SHALL replace all occurrences of `brew install sicario` with `brew install sicario-labs/sicario-cli/sicario` across all frontend pages.
2. WHEN a user views Homebrew installation instructions in the Docs_System, THE Docs_System SHALL show the full tap command: `brew install sicario-labs/sicario-cli/sicario`.
3. THE Docs_System SHALL NOT show `brew install sicario` without the tap prefix.

---

### Requirement 9: OAuth Flow Type Accuracy

**User Story:** As a developer setting up authentication, I want an accurate description of the OAuth flow, so that I understand what to expect when running `sicario login`.

#### Acceptance Criteria

1. THE Copy_Fix_System SHALL replace all descriptions of "OAuth 2.0 + PKCE browser flow" with "OAuth device flow — browser approval, no token copy-paste" across all frontend pages.
2. WHEN a user views the Authentication section in the Docs_System, THE Docs_System SHALL describe `sicario login` as using the OAuth device flow, where the user approves access in a browser without copying or pasting tokens.
3. THE Docs_System SHALL NOT describe the authentication flow as "OAuth 2.0 + PKCE" in user-facing copy.

---

### Requirement 10: Product Page "Read the Docs" Button

**User Story:** As a user clicking the "Read the Docs" button on the Product page, I want to be navigated to the documentation, so that I can learn more about Sicario.

#### Acceptance Criteria

1. THE Copy_Fix_System SHALL replace the non-functional `<button>` element labeled "Read the Docs" in `Product.tsx` with a `<Link to="/docs">` component.
2. WHEN a user clicks the "Read the Docs" element on the Product page, THE Router SHALL navigate the user to `/docs`.
3. THE Copy_Fix_System SHALL preserve the existing visual styling of the button when converting it to a Link.

---

### Requirement 11: Comparison Table Completeness

**User Story:** As a developer evaluating security tools, I want the comparison table to include Snyk and Checkmarx, so that I can make an informed decision.

#### Acceptance Criteria

1. THE Copy_Fix_System SHALL add Snyk and Checkmarx columns to the comparison table in `Product.tsx`.
2. WHEN a user views the comparison table on the Product page, THE Copy_Fix_System SHALL display Snyk and Checkmarx alongside Semgrep, Bandit, and ESLint Security.
3. THE Copy_Fix_System SHALL populate the Snyk and Checkmarx columns with accurate capability data matching the README comparison table.

---

### Requirement 12: AI Remediation in Pricing Tiers

**User Story:** As a developer evaluating the Community tier, I want to know that AI remediation is available for free, so that I don't unnecessarily upgrade.

#### Acceptance Criteria

1. THE Copy_Fix_System SHALL add "AI remediation (BYOK + template fallbacks)" to the Community tier feature list in `Pricing.tsx`.
2. WHEN a user views the Community tier on the Pricing page, THE Copy_Fix_System SHALL display AI remediation as an included feature.
3. THE Copy_Fix_System SHALL clarify that BYOK means the user supplies their own LLM API key, and that template fallbacks require no API key.

---

### Requirement 13: SARIF Output Flag Correctness

**User Story:** As a developer integrating Sicario into CI/CD, I want the correct SARIF output flags, so that my pipeline commands work without modification.

#### Acceptance Criteria

1. THE Copy_Fix_System SHALL replace all occurrences of `--output sarif` with `--format sarif --sarif-output results.sarif` across all frontend pages.
2. WHEN a user views SARIF output examples in the Docs_System, THE Docs_System SHALL use `--format sarif --sarif-output results.sarif` as the canonical flag combination.
3. THE Docs_System SHALL NOT show `--output sarif` as a valid flag.

---

### Requirement 14: Dynamic Version in Docs Footer

**User Story:** As a developer reading the documentation, I want the displayed CLI version to stay current, so that I am not misled by a stale hardcoded version number.

#### Acceptance Criteria

1. THE Copy_Fix_System SHALL remove the hardcoded "Sicario CLI v1.0.0" string from the Docs page footer.
2. WHEN a user views the Docs_System footer, THE Docs_System SHALL display the version as "Sicario CLI" without a hardcoded version number, or link to the GitHub releases page for the current version.
3. THE Docs_System SHALL NOT hardcode any specific version string in the footer.

---

### Requirement 15: Privacy Policy Infrastructure Accuracy

**User Story:** As a user reading the Privacy Policy, I want accurate information about the infrastructure provider, so that I can make an informed decision about data handling.

#### Acceptance Criteria

1. THE Copy_Fix_System SHALL replace "AWS/Google Cloud" with "Convex" in the Privacy Policy's Third-Party Services section.
2. WHEN a user views the Privacy Policy, THE Copy_Fix_System SHALL state that the backend infrastructure runs on Convex.
3. THE Copy_Fix_System SHALL preserve all other content in the Privacy Policy section unchanged.

---

### Requirement 16: Multi-Page Docs System — Routing and Navigation

**User Story:** As a developer reading the documentation, I want a multi-page docs experience with a persistent sidebar, so that I can navigate between sections without losing my place.

#### Acceptance Criteria

1. THE Router SHALL register routes for all 16 documentation sections under the `/docs/*` path pattern (e.g., `/docs/overview`, `/docs/installation`, `/docs/cli-reference`).
2. WHEN a user navigates to `/docs`, THE Router SHALL redirect the user to `/docs/overview`.
3. THE Sidebar SHALL display all 16 documentation sections grouped into logical categories matching the existing Docs.tsx sidebar pattern.
4. WHEN a user is viewing a Docs_Page, THE Sidebar SHALL highlight the active section using a visual indicator consistent with the existing design system.
5. WHEN the viewport width is below the `lg` Tailwind breakpoint, THE Sidebar SHALL collapse and be accessible via a toggle control.
6. THE Docs_System SHALL use anchor links within each Docs_Page to support deep linking to specific subsections.

---

### Requirement 17: Multi-Page Docs System — Design Consistency

**User Story:** As a user navigating the documentation, I want the docs pages to look and feel consistent with the rest of the site, so that the experience feels cohesive.

#### Acceptance Criteria

1. THE Docs_System SHALL use the existing dark theme with `#121212` / `neutral-950` background and `#ADFF2F` accent color.
2. THE Docs_System SHALL reuse the existing `CodeBlock` component pattern (syntax label, copy button, monospace font) for all code examples.
3. THE Docs_System SHALL use the same typography scale and spacing conventions as the existing `Docs.tsx` page.
4. WHEN a user views a Docs_Page on a mobile viewport, THE Docs_System SHALL render the content in a single-column layout without a visible sidebar.

---

### Requirement 18: Multi-Page Docs System — Content Accuracy

**User Story:** As a developer using the documentation as a reference, I want all documented CLI commands, URLs, and feature descriptions to be accurate, so that I can rely on the docs without cross-checking the README.

#### Acceptance Criteria

1. THE Docs_System SHALL document all 13 CLI commands: `scan`, `tui`, `fix`, `report`, `baseline`, `hook install`, `benchmark`, `rules test`, `login`, `publish`, `whoami`, `config set`, `config set-provider`.
2. THE Docs_System SHALL list all 19 LLM providers from the Provider_Registry in the AI Remediation section: openai, anthropic, gemini, azure, bedrock, deepseek, groq, cerebras, together, fireworks, openrouter, mistral, ollama, lmstudio, xai, perplexity, cohere, deepinfra, novita.
3. WHEN a user views the Installation section, THE Docs_System SHALL show the canonical curl installer URL `https://usesicario.xyz/install.sh`, the Homebrew tap `brew install sicario-labs/sicario-cli/sicario`, and the PowerShell installer `irm https://usesicario.xyz/install.ps1 | iex`.
4. WHEN a user views the CI/CD Integration section, THE Docs_System SHALL show SARIF output using `--format sarif --sarif-output results.sarif`.
5. WHEN a user views the Authentication section, THE Docs_System SHALL describe `sicario login` as using the OAuth device flow.
6. THE Docs_System SHALL document the global config file path as `~/.sicario/config.toml` and the project config path as `.sicario/config.yaml`.
7. THE Docs_System SHALL document the `sicario fix` command using the `language/rule-name` rule ID format.
8. THE Docs_System SHALL state the license as FSL-1.1 in the Licensing section.

---

### Requirement 19: Multi-Page Docs System — Parser and Serializer Round-Trip

**User Story:** As a developer, I want the documentation system's routing to be deterministic and reversible, so that every URL maps to exactly one page and back.

#### Acceptance Criteria

1. FOR ALL valid documentation section slugs, THE Router SHALL resolve the slug to exactly one Docs_Page component.
2. FOR ALL Docs_Page components, THE Sidebar SHALL generate a navigation link whose `href` resolves back to the same Docs_Page (round-trip property: `slug → page → link → slug`).
3. IF a user navigates to an unrecognized `/docs/<slug>` path, THEN THE Router SHALL render a 404 or redirect to `/docs/overview`.

---

### Requirement 20: Multi-Page Docs System — Accessibility

**User Story:** As a user with accessibility needs, I want the documentation to be navigable with a keyboard and screen reader, so that I can use the docs without a mouse.

#### Acceptance Criteria

1. THE Sidebar SHALL use semantic `<nav>` and `<ul>/<li>` elements for navigation links.
2. THE Docs_System SHALL use semantic heading hierarchy (`<h1>` for page title, `<h2>` for major sections, `<h3>` for subsections) within each Docs_Page.
3. WHEN a user activates the mobile sidebar toggle, THE Docs_System SHALL manage focus appropriately so keyboard users can navigate the sidebar.
4. THE CodeBlock component SHALL include an accessible `aria-label` on the copy button describing the action.

---

### Requirement 21: Homebrew Tap Setup and Automation

**User Story:** As a macOS developer, I want `brew install sicario-labs/sicario-cli/sicario` to work, so that I can install Sicario using my preferred package manager without manually downloading a binary.

#### Acceptance Criteria

1. A GitHub repository named `homebrew-sicario-cli` SHALL exist under the `sicario-labs` organization, making the tap address `sicario-labs/sicario-cli` resolvable by Homebrew.
2. THE Homebrew_Tap SHALL contain a file at `Formula/sicario.rb` that is a valid Homebrew formula for the `sicario` package.
3. THE Homebrew_Formula SHALL install the correct pre-built binary for both Apple Silicon (`aarch64-apple-darwin`) and Intel (`x86_64-apple-darwin`) Macs using `on_macos` / `Hardware::CPU.arm?` conditional blocks.
4. THE Homebrew_Formula SHALL reference the macOS release tarballs produced by the existing `release.yml` workflow: `sicario-darwin-arm64.tar.gz` and `sicario-darwin-amd64.tar.gz`.
5. THE Homebrew_Formula SHALL include a `test do` block that runs `sicario --version` to verify the installation.
6. THE `release.yml` workflow SHALL include a step using `mislav/bump-homebrew-formula-action` that runs after the GitHub Release is created and automatically commits an updated `Formula/sicario.rb` (with the new version tag and correct SHA256 checksums) to the tap repo.
7. THE auto-update step SHALL be gated on a `HOMEBREW_TAP_TOKEN` repository secret; IF the secret is absent, THEN the step SHALL fail with a clear error rather than silently skipping.
8. WHEN a user runs `brew install sicario-labs/sicario-cli/sicario` on a supported macOS machine after the tap is live, THEN Homebrew SHALL successfully install the `sicario` binary to the user's PATH.
9. THE Homebrew_Formula version field SHALL always match the latest published GitHub Release tag after the auto-update step runs.

---

### Requirement 22: Pricing Page Accuracy — Feature Gates Must Match Implementation

**User Story:** As a developer evaluating Sicario's pricing, I want the features listed in each tier to exactly match what is actually gated in the backend, so that I am not misled about what I get at each price point.

#### Background

The authoritative feature gate table is defined in `convex/convex/billing.ts` (`PLAN_LIMITS`) and `.kiro/specs/sicario-monetization-and-llm/design.md` (Plan Feature Gates Summary). The current `Pricing.tsx` page has multiple inaccuracies against this source of truth.

#### Acceptance Criteria

**Free tier (renamed from "Community") — `Pricing.tsx` SHALL list:**

1. Full local CLI access (unlimited scans, no authentication required)
2. SAST scanning with 500+ rules
3. Secret scanning
4. SCA dependency auditing
5. Compiler-style diagnostics
6. AI remediation (BYOK + template fallbacks, runs locally)
7. Cloud dashboard access (1 project, 500 findings, 30-day retention)
8. THE Free tier SHALL NOT claim features that require Pro or above (e.g., webhooks, OWASP reports, SARIF exports)
9. THE tier label "Community" SHALL be replaced with "Free" everywhere in `Pricing.tsx`, `Docs.tsx`, and any other frontend page that references it

**Pro ($19/mo) tier — `Pricing.tsx` SHALL list:**

10. Everything in Free, plus:
11. Up to 10 active projects
12. Up to 5,000 findings stored (90-day retention)
13. Slack / Microsoft Teams webhook notifications
14. SARIF and OWASP report generation and download from the Dashboard
15. THE Pro tier SHALL NOT list PR check integration (see Requirement 22 note below)
16. THE Pro tier SHALL NOT claim features that require Team or above (e.g., team management, custom rule uploads, baseline management)

**Team ($35/mo) tier — `Pricing.tsx` SHALL list:**

17. Everything in Pro, plus:
18. Unlimited active projects and findings stored (365-day retention)
19. Team management (invite members, assign roles: admin / manager / developer)
20. Custom YAML rule uploads via the Dashboard
21. Baseline management (save, compare, trend)
22. Execution audit trail

**Enterprise tier — `Pricing.tsx` SHALL list:**

23. Everything in Team, plus:
24. SSO (SAML 2.0 / OIDC)
25. Compliance data exports
26. Custom retention periods (per contract)
27. Dedicated support and SLA guarantees
28. Manual enterprise provisioning (bypasses Whop checkout)
29. THE Enterprise tier SHALL NOT list "on-premise deployment" unless that capability is implemented and gated in the backend

**General accuracy rules:**

30. THE Pricing page SHALL display the project and finding storage limits for the Free and Pro tiers (1 project / 500 findings and 10 projects / 5,000 findings respectively)
31. THE Pricing page SHALL NOT list any feature in a tier that is not enforced by the Plan_Enforcer in `convex/convex/planEnforcer.ts` or `convex/convex/billing.ts`
32. WHEN a feature is added to or removed from a plan gate in the backend, THE Pricing page copy SHALL be updated in the same pull request to stay in sync

**Note on PR check integration and zero-exfiltration:**

PR check integration as currently implemented in `PrCheckDetailPage.tsx` stores and displays a `snippet` field containing raw source code in the Convex cloud database. This violates Sicario's zero-exfiltration guarantee ("your source never leaves your machine"). Therefore:

33. THE Pricing page SHALL NOT advertise PR check integration as a feature until the `snippet` field is removed from all cloud-stored finding records and replaced with non-code metadata only (file path, line number, rule ID, severity, CWE ID)
34. THE `PrCheckDetailPage.tsx` snippet column SHALL be removed from the findings table, or replaced with a "Run `sicario fix --id=<id>` locally to view" handoff instruction
35. THE zero-exfiltration claim on the Download page, Home page, and Docs SHALL remain accurate: the cloud receives only structured finding metadata — never source code snippets

---

### Requirement 23: Dashboard.tsx — Legacy Prototype Copy Cleanup

**User Story:** As a user of the Sicario dashboard, I want the UI to reflect accurate product information, so that I am not confused by placeholder data or wrong branding.

`Dashboard.tsx` is a legacy prototype page that contains several copy and data issues that must be fixed before it is shown to real users.

#### Acceptance Criteria

1. THE `Dashboard.tsx` tier state SHALL be renamed from `'COMMUNITY' | 'TEAM'` to `'free' | 'team'` to match the canonical plan names used everywhere else in the codebase.
2. ALL references to `tier === 'COMMUNITY'` in `Dashboard.tsx` SHALL be updated to `tier === 'free'`.
3. THE upgrade modal in `Dashboard.tsx` SHALL replace "Upgrade for $49/mo" with "Upgrade to Pro — $19/mo" and add a separate "Upgrade to Team — $35/mo" option, or link to the pricing page.
4. THE upgrade modal footer SHALL replace "Secure payment via Lemon Squeezy" with "Secure payment via Whop" — Whop is the actual payment processor; Lemon Squeezy is not used.
5. THE upgrade modal feature list SHALL be updated to match the actual Team plan features (matching Requirement 22), not the current inaccurate list.
6. THE hardcoded email address `immanuelenyi@gmail.com` SHALL be removed from `Dashboard.tsx` and replaced with the authenticated user's actual email from the Convex identity.
7. THE mock finding rule IDs (`JS-EVAL-001`, `SQL-INJ-003`, `SEC-HARDCODED-002`) SHALL be updated to use the canonical `language/rule-name` format (`js/eval-injection`, `js/sql-injection`, `js/hardcoded-secret`) to be consistent with the actual rule ID format.
8. THE hardcoded version string `v0.6.4-stable` in the "Run Your First Scan" empty state SHALL be removed — version strings SHALL NOT be hardcoded in the frontend.

---

### Requirement 24: "Edge CLI" Terminology — Define or Replace

**User Story:** As a new user reading the dashboard, I want to understand what "Edge CLI" means, so that I am not confused by unexplained jargon.

The term "Edge CLI" appears in `ScansPage.tsx`, `ScanDetailPage.tsx`, `PrCheckDetailPage.tsx`, `AnalyticsPage.tsx`, and `OwaspPage.tsx` as a data source label, but is never defined or explained anywhere in the product.

#### Acceptance Criteria

1. THE "Edge CLI" label in `ScansPage.tsx`, `ScanDetailPage.tsx`, `AnalyticsPage.tsx`, and `OwaspPage.tsx` SHALL be replaced with "Sicario CLI" — this is the actual product name and is self-explanatory.
2. THE "Source: Edge CLI (CI pipeline)" label in `PrCheckDetailPage.tsx` SHALL be replaced with "Source: Sicario CLI (CI pipeline)".
3. THE "Data source: Edge CLI telemetry" label in `AnalyticsPage.tsx` and `OwaspPage.tsx` SHALL be replaced with "Data source: Sicario CLI telemetry".
4. THE term "Edge CLI" SHALL NOT appear anywhere in user-facing copy.

---

### Requirement 25: OWASP Top 10 Version Reference

**User Story:** As a compliance officer using the OWASP compliance view, I want the correct OWASP Top 10 version referenced, so that I know which standard my findings are mapped against.

#### Acceptance Criteria

1. THE `OwaspPage.tsx` subtitle "Findings mapped to OWASP Top 10 (2021) categories" SHALL be updated to "Findings mapped to OWASP Top 10 (2021) categories" — the 2021 edition remains the current published standard as of 2026; this is correct and SHALL NOT be changed to 2024 unless OWASP officially publishes a 2024 edition.
2. IF OWASP publishes a new Top 10 edition after this spec is implemented, THE version reference SHALL be updated in the same release that updates the underlying category mappings.

---

### Requirement 26: Docs.tsx Licensing Section — "Community" and Missing Pro Tier

**User Story:** As a developer reading the Docs licensing section, I want accurate tier names and a complete list of plans, so that I understand what I get at each price point.

The Docs.tsx licensing section currently:
- Uses "Community (Free)" instead of "Free"
- Skips the Pro tier entirely (jumps from Free to Team at $49/mo, which is wrong on both counts)
- Describes Team as $49/mo (the actual prices are Pro: $19/mo, Team: $35/mo)

#### Acceptance Criteria

1. THE Docs.tsx licensing section SHALL rename "Community (Free)" to "Free".
2. THE Docs.tsx licensing section SHALL add a Pro tier entry ($19/mo) between Free and Team.
3. THE Team tier price SHALL be updated to $35/mo (the actual Team plan price).
4. THE licensing section tier descriptions SHALL match the feature gates defined in Requirement 22.

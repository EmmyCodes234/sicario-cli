# Execution Roadmap: sicario-docs-and-copy-fix

---

## Phase 1: Copy Fixes — Existing Pages

### 1.1 License, Infrastructure, and OAuth Copy (Reqs 1, 9, 15)

- [x] In `Download.tsx`, replace the trust badge text `"MIT licensed, auditable"` with `"FSL-1.1 licensed, source-available"`
- [x] In `Privacy.tsx` section 04, replace `"payment processing (Stripe) and infrastructure (AWS/Google Cloud)"` with `"payment processing (Whop) and backend infrastructure (Convex)"`
- [x] In `Docs.tsx` auth section, replace `"browser-based OAuth 2.0 + PKCE"` with `"OAuth device flow — browser approval, no token copy-paste"`
- [x] In `Docs.tsx` command-login section, replace `"OAuth 2.0 + PKCE authentication"` with `"OAuth device flow"`

### 1.2 `sicario publish` Description (Req 2)

- [x] In `Docs.tsx`, update the command-publish section heading from `"Command: publish — Publish Custom Rules"` to `"Command: publish — Upload Scan Results"`
- [x] In `Docs.tsx`, update the command-publish body text from `"Publish custom YAML-based security rules to the Sicario Cloud registry for team-wide use."` to `"Upload locally-generated scan results to the Sicario Cloud dashboard for team visibility."`

### 1.3 Rule ID Format (Req 3)

- [x] In `Product.tsx` code block, replace `sicario fix src/handler.js --rule SQL-001` with `sicario fix src/handler.js --rule js/eval-injection`
- [x] In `Docs.tsx` command-fix section, replace `sicario fix src/handler.js --rule SQL-001` with `sicario fix src/db.js --rule js/sql-injection`

### 1.4 AI Remediation Template Fallback Mentions (Req 4)

- [x] In `Home.tsx` AI Remediation bento card description, append: `" Template-based fixes for SQL injection, XSS, and command injection work without an API key."`
- [x] In `Product.tsx` AI-Powered Remediation section body, append: `" Template-based fixes for SQL injection, XSS, and command injection are available without any API key."`

### 1.5 MCP Integration List (Req 5)

- [x] In `Home.tsx` MCP Server bento card description, replace `"Connect Sicario to Cursor, Copilot, and other AI coding tools."` with `"Connect Sicario to Claude, Cursor, and Kiro."`
- [x] In `Product.tsx` MCP Server module description, replace `"...with Cursor, Copilot, and more."` with `"...with Claude, Cursor, and Kiro."`
- [x] In `Product.tsx` Developer Experience section, replace `"MCP server integration for AI assistants like Cursor and Copilot."` with `"MCP server integration for AI assistants like Claude, Cursor, and Kiro."`
- [x] In `FAQ.tsx` MCP answer, replace `"Cursor, GitHub Copilot, and other MCP-compatible tools"` with `"Claude, Cursor, and Kiro"`

### 1.6 SCA Description Completeness (Req 6)

- [x] In `Home.tsx` SCA Scanner bento card description, append: `" Vulnerability data is cached locally in a SQLite database. Supports package.json, Cargo.toml, and requirements.txt."`
- [x] In `Product.tsx` SCA Scanner module description, append: `" Supports package.json, Cargo.toml, and requirements.txt. Vulnerability data is cached locally in SQLite."`

### 1.7 Installation URL and SARIF Flag (Reqs 7, 13)

- [x] In `FAQ.tsx` install answer, replace `https://install.usesicario.xyz` with `https://usesicario.xyz/install.sh`
- [x] In `FAQ.tsx` install answer, replace `brew install sicario` with `brew install sicario-labs/sicario-cli/sicario`
- [x] In `Download.tsx` quick-start block, replace `sicario scan . --output sarif > results.sarif` with `sicario scan . --format sarif --sarif-output results.sarif`

### 1.8 "Read the Docs" Button → Link (Req 10)

- [x] In `Product.tsx` hero CTA, replace the `<button className="...">Read the Docs</button>` element with `<Link to="/docs" className="...">Read the Docs</Link>`, preserving the existing `className` string verbatim
- [x] Add `import { Link } from 'react-router-dom'` to `Product.tsx` if not already present

### 1.9 Comparison Table — Add Snyk and Checkmarx (Req 11)

- [x] In `Product.tsx` comparison table `<thead>`, add `<th>` cells for `Snyk` and `Checkmarx` after the `ESLint Security` column, matching the existing header styling
- [x] In `Product.tsx` comparison table `<tbody>`, add `snyk` and `checkmarx` fields to each row data object and render them with the same conditional color logic as the existing columns, using the capability data from the design document

### 1.10 Docs Footer Version String (Req 14)

- [x] In `Docs.tsx` footer, remove the hardcoded `v1.0.0` from `"Sicario CLI v1.0.0"` so it reads `"Sicario CLI"`

### 1.11 Docs.tsx Licensing Section (Req 26)

- [x] In `Docs.tsx` licensing section, rename `"Community (Free)"` to `"Free"`
- [x] In `Docs.tsx` licensing section, add a Pro tier entry at `$19/mo` between Free and Team
- [x] In `Docs.tsx` licensing section, update the Team tier price from `$49/mo` to `$35/mo`
- [x] In `Docs.tsx` licensing section, update the tier descriptions to match the feature gates defined in Req 22 (Free: local CLI + cloud 1 project/500 findings; Pro: 10 projects/5k findings + webhooks + SARIF; Team: unlimited + team mgmt + baseline + audit trail)
- [x] In `Docs.tsx` licensing section, update the "Upgrade to Team" CTA button to link to `/pricing` instead of `/auth`

---

## Phase 2: Copy Fixes — Pricing Page Restructure (Reqs 12, 22)

### 2.1 Pricing Tier Restructure

- [x] In `Pricing.tsx`, change the grid from `grid-cols-1 md:grid-cols-3` to `grid-cols-1 md:grid-cols-2 lg:grid-cols-4` to accommodate 4 tiers
- [x] In `Pricing.tsx`, rename the "Community" tier card heading to `"Free"` and update its description
- [x] In `Pricing.tsx`, add AI remediation feature item to the Free tier: `"AI remediation (BYOK + template fallbacks)"` with a sub-note: `"BYOK: bring your own LLM key. Template fixes need no key."`
- [x] In `Pricing.tsx`, add the project and finding storage limits to the Free tier: `"1 project · 500 findings · 30-day retention"`
- [x] In `Pricing.tsx`, remove features from the Free tier that require Pro or above (webhooks, OWASP reports, SARIF exports)

### 2.2 Add Pro Tier Card

- [x] In `Pricing.tsx`, insert a new Pro tier card at `$19/mo` between Free and Team
- [x] Move the `border-[#ADFF2F]/30` highlight border, `shadow-2xl shadow-[#ADFF2F]/5`, and `"RECOMMENDED"` badge from the Team card to the Pro card
- [x] Pro tier feature list: Everything in Free, plus: up to 10 active projects, up to 5,000 findings stored (90-day retention), Slack / Microsoft Teams webhook notifications, SARIF and OWASP report generation and download
- [x] Pro tier CTA: `<Link to="/auth">` with text `"Start Free Trial"`

### 2.3 Update Team and Enterprise Tier Cards

- [x] In `Pricing.tsx`, update the Team tier price from `$49` to `$35`
- [x] In `Pricing.tsx`, update the Team tier feature list: Everything in Pro, plus: unlimited active projects and findings (365-day retention), team management (invite members, assign roles), custom YAML rule uploads, baseline management, execution audit trail
- [x] In `Pricing.tsx`, remove the Team tier's `border-[#ADFF2F]/30` highlight (moved to Pro)
- [x] In `Pricing.tsx`, update the Enterprise tier feature list: remove `"On-premise deployment"` (not implemented); add `"Compliance data exports"`, `"Custom retention periods"`, `"Manual enterprise provisioning"`

---

## Phase 3: Copy Fixes — Dashboard Pages (Reqs 23, 24, 22.34)

### 3.1 Dashboard.tsx Tier Names and Modal (Req 23)

- [x] In `Dashboard.tsx`, change the tier type from `'COMMUNITY' | 'TEAM'` to `'free' | 'team'`
- [x] In `Dashboard.tsx`, change the initial tier state from `'COMMUNITY'` to `'free'`
- [x] In `Dashboard.tsx`, update all `tier === 'COMMUNITY'` comparisons to `tier === 'free'`
- [x] In `Dashboard.tsx`, update the tier badge display from `{tier}` to `{tier === 'free' ? 'Free' : 'Team'}`
- [x] In `Dashboard.tsx`, update the upgrade modal heading from `"Upgrade to Team"` to `"Upgrade to Pro — $19/mo"`
- [x] In `Dashboard.tsx`, update the upgrade modal CTA button text from `"Upgrade for $49/mo"` to `"Upgrade to Pro — $19/mo"`
- [x] In `Dashboard.tsx`, update the upgrade modal footer from `"Secure payment via Lemon Squeezy"` to `"Secure payment via Whop"`
- [x] In `Dashboard.tsx`, update the upgrade modal feature list to match the actual Pro plan features: unlimited cloud finding sync, Slack/Teams webhooks, SARIF and OWASP reports, up to 10 projects / 5,000 findings

### 3.2 Dashboard.tsx Hardcoded Data (Req 23)

- [x] In `Dashboard.tsx`, replace the hardcoded email `immanuelenyi@gmail.com` in the sidebar user section with the authenticated user's email from Convex; use `useQuery(api.auth.currentUser)` (or the equivalent query already used in other dashboard pages) and fall back to `"your@email.com"` if unauthenticated
- [x] In `Dashboard.tsx`, remove the hardcoded version string `v0.6.4-stable` from the "Run Your First Scan" empty state header
- [x] In `Dashboard.tsx`, update the `MOCK_FINDINGS` rule IDs: `'JS-EVAL-001'` → `'js/eval-injection'`, `'SQL-INJ-003'` → `'js/sql-injection'`, `'SEC-HARDCODED-002'` → `'js/hardcoded-secret'`

### 3.3 "Edge CLI" → "Sicario CLI" (Req 24)

- [x] In `ScansPage.tsx`, replace all occurrences of `"Edge CLI"` with `"Sicario CLI"`
- [x] In `ScanDetailPage.tsx`, replace all occurrences of `"Edge CLI"` with `"Sicario CLI"`
- [x] In `PrCheckDetailPage.tsx`, replace `"Source: Edge CLI (CI pipeline)"` with `"Source: Sicario CLI (CI pipeline)"` and all other `"Edge CLI"` occurrences with `"Sicario CLI"`
- [x] In `AnalyticsPage.tsx`, replace `"Edge CLI"` with `"Sicario CLI"` and `"Data source: Edge CLI telemetry"` with `"Data source: Sicario CLI telemetry"`
- [x] In `OwaspPage.tsx`, replace `"Edge CLI"` with `"Sicario CLI"` and `"Data source: Edge CLI telemetry"` with `"Data source: Sicario CLI telemetry"`

### 3.4 PR Check Snippet Removal (Req 22.34)

- [x] In `PrCheckDetailPage.tsx`, remove the `snippet` column from the findings table header and all corresponding data cells
- [x] In `PrCheckDetailPage.tsx`, add a replacement cell in each finding row with the text: `Run sicario fix --id=<id> locally to view` (where `<id>` is the finding ID), styled as a monospace code hint

---

## Phase 4: Multi-Page Docs System — Infrastructure (Reqs 16, 17, 19, 20)

### 4.1 Extract `CodeBlock` Component

- [x] Create `sicario-frontend/src/pages/docs/CodeBlock.tsx` by extracting the `CodeBlock` component from `Docs.tsx` verbatim
- [x] Add `aria-label="Copy code to clipboard"` to the copy button inside `CodeBlock`
- [x] Update `Docs.tsx` to import `CodeBlock` from `./docs/CodeBlock` instead of defining it inline

### 4.2 `DocsLayout` Component

- [x] Create `sicario-frontend/src/pages/docs/DocsLayout.tsx` with the full sidebar and layout shell
- [x] Define the `NAV_GROUPS` constant with all 16 slugs grouped into 5 categories as specified in the design
- [x] Implement active link detection using `useLocation().pathname` compared against `/docs/<slug>`; apply `text-white` and the `ChevronRight` indicator to the active link, matching the existing `Docs.tsx` sidebar style
- [x] Implement mobile sidebar toggle: below the `lg` breakpoint, hide the sidebar by default; render a hamburger button in the content area that sets `isSidebarOpen: true`; when open, render the sidebar as a fixed overlay with a `bg-black/50` backdrop
- [x] Implement focus management: when `isSidebarOpen` transitions to `true`, use `useRef` + `useEffect` to call `.focus()` on the first `<a>` element inside the sidebar
- [x] Wrap the sidebar in a `<nav aria-label="Documentation">` element containing a `<ul>` with `<li>` children for each link
- [x] Render `<Outlet />` in the main content area for child page injection
- [x] Add a nested `<Routes>` block inside `DocsLayout` with all 16 page routes plus a catch-all `<Navigate to="overview" replace />`

### 4.3 Router Updates in `App.tsx`

- [x] In `App.tsx`, replace `<Route path="/docs" element={<Docs />} />` with:
  - `<Route path="/docs" element={<Navigate to="/docs/overview" replace />} />`
  - `<Route path="/docs/*" element={<DocsLayout />} />`
- [x] Add `DocsLayout` as a `lazy()` import in `App.tsx`, consistent with the existing dashboard lazy-loading pattern
- [x] Add `Navigate` to the `react-router-dom` import in `App.tsx` if not already present

---

## Phase 5: Multi-Page Docs System — Page Content (Reqs 17, 18)

### 5.1 Getting Started Pages

- [x] Create `DocsOverviewPage.tsx`: `<h1>` "Sicario: Next-Generation Security Scanner", summary of capabilities (SAST/SCA/secrets/AI remediation), quick-start links to Installation and CLI Reference sections
- [x] Create `DocsInstallationPage.tsx`: `<h1>` "Installation"; `<h2>` sections for Homebrew (`brew install sicario-labs/sicario-cli/sicario`), curl installer (`https://usesicario.xyz/install.sh`), PowerShell (`irm https://usesicario.xyz/install.ps1 | iex`), and cargo build; all commands in `CodeBlock`
- [x] Create `DocsAuthPage.tsx`: `<h1>` "Authentication"; describe `sicario login` as using the OAuth device flow — browser approval, no token copy-paste; `CodeBlock` for `sicario login`; note that credentials are stored in the OS keyring

### 5.2 CLI Reference Page

- [x] Create `DocsCliReferencePage.tsx`: `<h1>` "CLI Reference"; one `<h2>` per command for all 13 commands: `scan`, `tui`, `fix`, `report`, `baseline`, `hook install`, `benchmark`, `rules test`, `login`, `publish`, `whoami`, `config set`, `config set-provider`
- [x] For `fix`, show example using `language/rule-name` format: `sicario fix src/db.js --rule js/sql-injection`
- [x] For `publish`, describe it as uploading scan results to the Sicario Cloud dashboard (not publishing rules)
- [x] For `scan`, show SARIF example using `--format sarif --sarif-output results.sarif`
- [x] For `config set` and `config set-provider`, document `~/.sicario/config.toml` as the global config path and `.sicario/config.yaml` as the project config path

### 5.3 Capabilities Pages

- [x] Create `DocsSastPage.tsx`: `<h1>` "SAST Scanning"; tree-sitter AST parsing, 500+ rules, 5 languages (Go, Java, JavaScript/TypeScript, Python, Rust), data-flow reachability
- [x] Create `DocsScaPage.tsx`: `<h1>` "SCA Scanning"; OSV and GitHub Security Advisory databases; SQLite local cache; supported manifests: `package.json`, `Cargo.toml`, `requirements.txt`
- [x] Create `DocsSecretsPage.tsx`: `<h1>` "Secret Detection"; entropy-based detection, provider-specific verification, near-zero false positives
- [x] Create `DocsAiRemediationPage.tsx`: `<h1>` "AI Remediation"; BYOK model; list all 19 providers from the Provider_Registry (openai, anthropic, gemini, azure, bedrock, deepseek, groq, cerebras, together, fireworks, openrouter, mistral, ollama, lmstudio, xai, perplexity, cohere, deepinfra, novita); template-based fallback fixes for SQL injection, XSS, and command injection (no API key required); AI disclaimer
- [x] Create `DocsReachabilityPage.tsx`: `<h1>` "Reachability Analysis"; inter-procedural taint analysis, source-to-sink tracing, confidence scoring, false positive reduction
- [x] Create `DocsReportingPage.tsx`: `<h1>` "Reporting"; SARIF v2.1.0 output with `--format sarif --sarif-output results.sarif`; OWASP Top 10 (2021) compliance reports; GitHub Code Scanning integration
- [x] Create `DocsMcpPage.tsx`: `<h1>` "MCP Server"; Model Context Protocol server built into the CLI; confirmed supported assistants: Claude, Cursor, Kiro; configuration instructions

### 5.4 Integration Pages

- [x] Create `DocsCiCdPage.tsx`: `<h1>` "CI/CD Integration"; GitHub Actions example using `sicario scan .`; SARIF upload step using `--format sarif --sarif-output results.sarif`; exit code behavior (0 = clean, 1 = findings above threshold, 2 = internal error); `--severity-threshold` flag
- [x] Create `DocsConfigPage.tsx`: `<h1>` "Configuration"; global config at `~/.sicario/config.toml`; project config at `.sicario/config.yaml`; `sicario config set` and `sicario config set-provider` commands; `.sicarioignore` file
- [x] Create `DocsBaselinePage.tsx`: `<h1>` "Baseline Management"; `sicario baseline save --tag <tag>`, `sicario baseline compare`, `sicario baseline trend`; use case: suppress known issues, focus on new findings
- [x] Create `DocsSuppressionPage.tsx`: `<h1>` "Suppressions"; `sicario-ignore`, `sicario-ignore-next-line`, `sicario-ignore:<rule-id>` directives; supported comment styles (`//`, `#`, `/* */`, `<!-- -->`)

### 5.5 Licensing Page

- [x] Create `DocsLicensingPage.tsx`: `<h1>` "Licensing"; state that Sicario is governed by the Functional Source License 1.1 (FSL-1.1) with Apache License 2.0 as the Change License; state that FSL-1.1 converts to Apache 2.0 two years after each version's first public release; include the 4-tier plan table (Free / Pro $19 / Team $35 / Enterprise Custom) with feature gates matching Req 22; link to `/pricing` for upgrade

---

## Phase 6: Homebrew Tap (Req 21)

### 6.1 Homebrew Formula

- [x] Create `homebrew-sicario-cli/Formula/sicario.rb` with the formula structure from the design: `desc`, `homepage`, `version`, `on_macos` block with `Hardware::CPU.arm?` conditional selecting `sicario-darwin-arm64.tar.gz` vs `sicario-darwin-amd64.tar.gz`, `def install` installing the `sicario` binary to `bin`, and a `test do` block running `sicario --version` and asserting the version string is present
- [x] Create `homebrew-sicario-cli/README.md` with tap installation instructions: `brew tap sicario-labs/sicario-cli` and `brew install sicario-labs/sicario-cli/sicario`

### 6.2 Release Workflow Auto-Update

- [x] In `.github/workflows/release.yml`, add a `bump-homebrew-formula` job that runs after the release creation job, using `mislav/bump-homebrew-formula-action@v3`
- [x] Configure the step with: `formula-name: sicario`, `formula-path: Formula/sicario.rb`, `homebrew-tap: sicario-labs/homebrew-sicario-cli`, `tag-name: ${{ github.ref_name }}`
- [x] Gate the step on `if: ${{ secrets.HOMEBREW_TAP_TOKEN != '' }}` so it fails visibly (not silently) when the secret is absent
- [x] Set `COMMITTER_TOKEN: ${{ secrets.HOMEBREW_TAP_TOKEN }}` in the step's `env` block
- [x] Document `HOMEBREW_TAP_TOKEN` in the repo's secrets documentation (add a comment in the workflow file explaining the required scope: `repo` write on `sicario-labs/homebrew-sicario-cli`)

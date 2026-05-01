# Design Document: sicario-docs-and-copy-fix

## Overview

This design covers three workstreams:

1. **Copy Fixes** — 26 targeted corrections across `Home.tsx`, `Product.tsx`, `Pricing.tsx`, `FAQ.tsx`, `Docs.tsx`, `Download.tsx`, `Privacy.tsx`, `Dashboard.tsx`, and the dashboard sub-pages (`ScansPage.tsx`, `ScanDetailPage.tsx`, `PrCheckDetailPage.tsx`, `AnalyticsPage.tsx`, `OwaspPage.tsx`).
2. **Multi-Page Docs System** — Replace the single-page `Docs.tsx` with 16 individual React pages under `sicario-frontend/src/pages/docs/`, routed at `/docs/<section>`, with a shared `DocsLayout` component containing the persistent sidebar.
3. **Homebrew Tap** — Create `homebrew-sicario-cli/Formula/sicario.rb` and add a `mislav/bump-homebrew-formula-action` step to `.github/workflows/release.yml`.

The design is intentionally minimal: it reuses every existing component, pattern, and dependency already present in the codebase. No new npm packages are introduced.

---

## Architecture

### System Component Diagram

```
sicario-frontend/src/
├── App.tsx                          MODIFIED: add /docs/* routes, redirect /docs → /docs/overview
├── pages/
│   ├── Docs.tsx                     MODIFIED: copy fixes only (licensing section, footer)
│   ├── Home.tsx                     MODIFIED: copy fixes
│   ├── Product.tsx                  MODIFIED: copy fixes + comparison table + "Read the Docs" button
│   ├── Pricing.tsx                  MODIFIED: copy fixes + tier restructure
│   ├── FAQ.tsx                      MODIFIED: copy fixes
│   ├── Download.tsx                 MODIFIED: copy fixes (trust badge, SARIF flag)
│   ├── Privacy.tsx                  MODIFIED: copy fixes (infrastructure provider)
│   ├── Dashboard.tsx                MODIFIED: copy fixes (tier names, modal, email, rule IDs, version)
│   └── docs/                        NEW directory
│       ├── DocsLayout.tsx           NEW: shared layout with sidebar + mobile toggle
│       ├── DocsOverviewPage.tsx     NEW
│       ├── DocsInstallationPage.tsx NEW
│       ├── DocsAuthPage.tsx         NEW
│       ├── DocsCliReferencePage.tsx NEW
│       ├── DocsSastPage.tsx         NEW
│       ├── DocsScaPage.tsx          NEW
│       ├── DocsSecretsPage.tsx      NEW
│       ├── DocsAiRemediationPage.tsx NEW
│       ├── DocsReachabilityPage.tsx NEW
│       ├── DocsReportingPage.tsx    NEW
│       ├── DocsMcpPage.tsx          NEW
│       ├── DocsCiCdPage.tsx         NEW
│       ├── DocsConfigPage.tsx       NEW
│       ├── DocsBaselinePage.tsx     NEW
│       ├── DocsSuppressionPage.tsx  NEW
│       └── DocsLicensingPage.tsx    NEW
└── dashboard/
    ├── ScansPage.tsx                MODIFIED: "Edge CLI" → "Sicario CLI"
    ├── ScanDetailPage.tsx           MODIFIED: "Edge CLI" → "Sicario CLI"
    ├── PrCheckDetailPage.tsx        MODIFIED: "Edge CLI" → "Sicario CLI", remove snippet column
    ├── AnalyticsPage.tsx            MODIFIED: "Edge CLI" → "Sicario CLI"
    └── OwaspPage.tsx                MODIFIED: "Edge CLI" → "Sicario CLI"

.github/workflows/release.yml       MODIFIED: add bump-homebrew-formula-action step
homebrew-sicario-cli/               NEW repository (separate from main repo)
└── Formula/
    └── sicario.rb                  NEW: Homebrew formula
```

### Routing Changes in `App.tsx`

The existing `/docs` route is replaced with a wildcard that renders `DocsLayout`, and a redirect from `/docs` to `/docs/overview` is added:

```tsx
// Before
<Route path="/docs" element={<Docs />} />

// After
<Route path="/docs" element={<Navigate to="/docs/overview" replace />} />
<Route path="/docs/*" element={<DocsLayout />} />
```

`DocsLayout` uses React Router's `<Outlet />` to render the active page. The 16 child routes are registered inside `DocsLayout` using a nested `<Routes>` block. An unrecognized slug renders a redirect to `/docs/overview`.

---

## Components and Interfaces

### 1. `DocsLayout` (`pages/docs/DocsLayout.tsx`)

The shared shell for all docs pages. Renders the sidebar on the left and the active page via `<Outlet />` on the right. Mirrors the layout structure of the existing `Docs.tsx` exactly.

**Props:** none (reads active route from `useLocation`)

**State:**
- `isSidebarOpen: boolean` — controls mobile sidebar visibility

**Sidebar data structure** (static, defined inline):

```tsx
const NAV_GROUPS: NavGroup[] = [
  {
    title: "Getting Started",
    links: [
      { name: "Overview",       slug: "overview" },
      { name: "Installation",   slug: "installation" },
      { name: "Authentication", slug: "auth" },
    ]
  },
  {
    title: "CLI Reference",
    links: [
      { name: "CLI Reference",  slug: "cli-reference" },
    ]
  },
  {
    title: "Capabilities",
    links: [
      { name: "SAST",           slug: "sast" },
      { name: "SCA",            slug: "sca" },
      { name: "Secrets",        slug: "secrets" },
      { name: "AI Remediation", slug: "ai-remediation" },
      { name: "Reachability",   slug: "reachability" },
      { name: "Reporting",      slug: "reporting" },
      { name: "MCP Server",     slug: "mcp" },
    ]
  },
  {
    title: "Integration",
    links: [
      { name: "CI/CD",          slug: "ci-cd" },
      { name: "Configuration",  slug: "configuration" },
      { name: "Baseline",       slug: "baseline" },
      { name: "Suppressions",   slug: "suppressions" },
    ]
  },
  {
    title: "Platform",
    links: [
      { name: "Licensing",      slug: "licensing" },
    ]
  }
];
```

**Active link detection:** `useLocation().pathname` is compared against `/docs/<slug>`. The active link receives the same `text-white` + `ChevronRight` indicator used in the existing `Docs.tsx` sidebar.

**Mobile behavior:** Below the `lg` Tailwind breakpoint, the sidebar is hidden by default. A hamburger button in the top-left of the content area toggles `isSidebarOpen`. When open, the sidebar renders as a fixed overlay with a backdrop. Focus is moved to the first sidebar link on open (satisfies Req 20.3).

**Routing (nested inside `DocsLayout`):**

```tsx
<Routes>
  <Route index element={<Navigate to="overview" replace />} />
  <Route path="overview"       element={<DocsOverviewPage />} />
  <Route path="installation"   element={<DocsInstallationPage />} />
  <Route path="auth"           element={<DocsAuthPage />} />
  <Route path="cli-reference"  element={<DocsCliReferencePage />} />
  <Route path="sast"           element={<DocsSastPage />} />
  <Route path="sca"            element={<DocsScaPage />} />
  <Route path="secrets"        element={<DocsSecretsPage />} />
  <Route path="ai-remediation" element={<DocsAiRemediationPage />} />
  <Route path="reachability"   element={<DocsReachabilityPage />} />
  <Route path="reporting"      element={<DocsReportingPage />} />
  <Route path="mcp"            element={<DocsMcpPage />} />
  <Route path="ci-cd"          element={<DocsCiCdPage />} />
  <Route path="configuration"  element={<DocsConfigPage />} />
  <Route path="baseline"       element={<DocsBaselinePage />} />
  <Route path="suppressions"   element={<DocsSuppressionPage />} />
  <Route path="licensing"      element={<DocsLicensingPage />} />
  <Route path="*"              element={<Navigate to="overview" replace />} />
</Routes>
```

### 2. `CodeBlock` (reused from `Docs.tsx`)

The existing `CodeBlock` component is extracted into `pages/docs/CodeBlock.tsx` and imported by `DocsLayout` and all `Docs*Page` components. The copy button receives `aria-label="Copy code to clipboard"` to satisfy Req 20.4.

```tsx
// pages/docs/CodeBlock.tsx
export function CodeBlock({ code, language = "BASH" }: { code: string; language?: string }) { ... }
```

### 3. Individual Docs Pages

Each page is a plain React component that exports a default function. They receive no props — all content is static. Each page:

- Uses `<h1>` for the page title, `<h2>` for major sections, `<h3>` for subsections (Req 20.2).
- Uses the `CodeBlock` component for all code examples.
- Uses the same `scroll-mt-16` anchor pattern from the existing `Docs.tsx` for deep-link support (Req 16.6).

**Page → slug → content mapping:**

| Page component | Slug | Primary content |
|---|---|---|
| `DocsOverviewPage` | `overview` | What Sicario is, capabilities summary, quick links |
| `DocsInstallationPage` | `installation` | curl installer, Homebrew, PowerShell, cargo build |
| `DocsAuthPage` | `auth` | OAuth device flow description, `sicario login` |
| `DocsCliReferencePage` | `cli-reference` | All 13 commands with flags and examples |
| `DocsSastPage` | `sast` | SAST engine, tree-sitter, 500+ rules, languages |
| `DocsScaPage` | `sca` | OSV/GHSA, SQLite cache, manifest files |
| `DocsSecretsPage` | `secrets` | Entropy detection, provider verification |
| `DocsAiRemediationPage` | `ai-remediation` | BYOK, 19 providers, template fallbacks |
| `DocsReachabilityPage` | `reachability` | Data-flow analysis, confidence scoring |
| `DocsReportingPage` | `reporting` | SARIF flags, OWASP Top 10 (2021) |
| `DocsMcpPage` | `mcp` | MCP server, Claude/Cursor/Kiro |
| `DocsCiCdPage` | `ci-cd` | GitHub Actions, SARIF upload, exit codes |
| `DocsConfigPage` | `configuration` | `~/.sicario/config.toml`, `.sicario/config.yaml` |
| `DocsBaselinePage` | `baseline` | `sicario baseline save/compare/trend` |
| `DocsSuppressionPage` | `suppressions` | `sicario-ignore` directives |
| `DocsLicensingPage` | `licensing` | FSL-1.1, Apache 2.0 change date, tier table |

---

## Copy Fix Inventory

Each fix is scoped to the minimum change needed. The table below maps every requirement to the exact file(s) and the before/after string.

### Group A: License (Req 1)

| File | Before | After |
|---|---|---|
| `Download.tsx` | `"MIT licensed, auditable"` | `"FSL-1.1 licensed, source-available"` |
| `FAQ.tsx` | (no MIT reference found — no change needed) | — |
| `DocsLicensingPage` | (new page) | States FSL-1.1, Apache 2.0 change date |

### Group B: `sicario publish` description (Req 2)

| File | Before | After |
|---|---|---|
| `Docs.tsx` command-publish section | `"Publish custom YAML-based security rules to the Sicario Cloud registry for team-wide use."` | `"Upload locally-generated scan results to the Sicario Cloud dashboard for team visibility."` |
| `Docs.tsx` command-publish heading | `"Command: publish — Publish Custom Rules"` | `"Command: publish — Upload Scan Results"` |

### Group C: Rule ID format (Req 3)

| File | Before | After |
|---|---|---|
| `Product.tsx` code block | `sicario fix src/handler.js --rule SQL-001` | `sicario fix src/handler.js --rule js/eval-injection` |
| `Docs.tsx` command-fix section | `sicario fix src/handler.js --rule SQL-001` | `sicario fix src/db.js --rule js/sql-injection` |
| `Dashboard.tsx` MOCK_FINDINGS | `ruleId: 'JS-EVAL-001'` | `ruleId: 'js/eval-injection'` |
| `Dashboard.tsx` MOCK_FINDINGS | `ruleId: 'SQL-INJ-003'` | `ruleId: 'js/sql-injection'` |
| `Dashboard.tsx` MOCK_FINDINGS | `ruleId: 'SEC-HARDCODED-002'` | `ruleId: 'js/hardcoded-secret'` |

### Group D: AI remediation template fallback (Req 4)

| File | Change |
|---|---|
| `Home.tsx` AI Remediation bento card description | Append: `" Template-based fixes for SQL injection, XSS, and command injection work without an API key."` |
| `Product.tsx` AI-Powered Remediation section | Append sentence: `"Template-based fixes for SQL injection, XSS, and command injection are available without any API key."` |
| `Pricing.tsx` Free tier feature list | Add item: `"AI remediation (BYOK + template fallbacks)"` with sub-note clarifying BYOK = user supplies key, template fallbacks need no key |

### Group E: MCP server integration list (Req 5)

| File | Before | After |
|---|---|---|
| `Home.tsx` MCP Server bento card | `"Connect Sicario to Cursor, Copilot, and other AI coding tools."` | `"Connect Sicario to Claude, Cursor, and Kiro."` |
| `Product.tsx` MCP Server module description | `"...with Cursor, Copilot, and more."` | `"...with Claude, Cursor, and Kiro."` |
| `Product.tsx` Developer Experience section | `"MCP server integration for AI assistants like Cursor and Copilot."` | `"MCP server integration for AI assistants like Claude, Cursor, and Kiro."` |
| `FAQ.tsx` MCP answer | `"Cursor, GitHub Copilot, and other MCP-compatible tools"` | `"Claude, Cursor, and Kiro"` |

### Group F: SCA description (Req 6)

| File | Change |
|---|---|
| `Home.tsx` SCA Scanner bento card | Append: `" Vulnerability data is cached locally in a SQLite database. Supports package.json, Cargo.toml, and requirements.txt."` |
| `Product.tsx` SCA Scanner module | Append: `" Supports package.json, Cargo.toml, and requirements.txt. Vulnerability data is cached locally in SQLite."` |

### Group G: Installation URL (Req 7)

| File | Before | After |
|---|---|---|
| `FAQ.tsx` install answer | `https://install.usesicario.xyz` | `https://usesicario.xyz/install.sh` |
| `Download.tsx` quick-start block | `sicario scan . --output sarif > results.sarif` | `sicario scan . --format sarif --sarif-output results.sarif` |

Note: `Download.tsx` already uses the correct `https://usesicario.xyz/install.sh` URL in `curlInstall`. The only URL fix needed is in `FAQ.tsx`.

### Group H: Homebrew tap (Req 8)

| File | Before | After |
|---|---|---|
| `FAQ.tsx` install answer | `brew install sicario` | `brew install sicario-labs/sicario-cli/sicario` |

Note: `Docs.tsx`, `Download.tsx`, and `Dashboard.tsx` already use the correct full tap command.

### Group I: OAuth flow type (Req 9)

| File | Before | After |
|---|---|---|
| `Docs.tsx` auth section | `"browser-based OAuth 2.0 + PKCE"` | `"OAuth device flow — browser approval, no token copy-paste"` |
| `Docs.tsx` command-login section | `"OAuth 2.0 + PKCE authentication"` | `"OAuth device flow"` |

### Group J: "Read the Docs" button (Req 10)

| File | Before | After |
|---|---|---|
| `Product.tsx` hero CTA | `<button className="...">Read the Docs</button>` | `<Link to="/docs" className="...">Read the Docs</Link>` |

The existing `className` string is preserved verbatim on the `Link`.

### Group K: Comparison table (Req 11)

| File | Change |
|---|---|
| `Product.tsx` comparison table | Add `Snyk` and `Checkmarx` columns to `<thead>` and all `<tbody>` rows |

Snyk and Checkmarx column data (sourced from README comparison table):

| Capability | Snyk | Checkmarx |
|---|---|---|
| Multi-language SAST | ✓ (paid) | ✓ |
| Secret Scanning | ✓ (paid) | ✓ (paid) |
| SCA / Dependency Audit | ✓ | ✓ |
| Data-Flow Reachability | ✓ (paid) | ✓ |
| AI Auto-Remediation | ✓ (paid) | ✗ |
| Interactive TUI | ✗ | ✗ |
| MCP Server | ✗ | ✗ |
| Single Static Binary | ✗ | ✗ |
| SARIF + OWASP Reports | ✓ | ✓ |
| Compiler-Style Diagnostics | ✗ | ✗ |
| Zero Runtime Dependencies | ✗ | ✗ |

### Group L: Pricing tier restructure (Reqs 12, 22, 26)

`Pricing.tsx` is restructured from 3 tiers (Community / Team / Enterprise) to 4 tiers (Free / Pro / Team / Enterprise). The "RECOMMENDED" badge moves to the Pro tier.

**Free tier** (renamed from "Community", $0/mo):
- Full local CLI access (unlimited scans, no authentication required)
- SAST scanning with 500+ rules
- Secret scanning
- SCA dependency auditing
- Compiler-style diagnostics
- AI remediation (BYOK + template fallbacks, runs locally)
- Cloud dashboard access (1 project, 500 findings, 30-day retention)

**Pro tier** (new, $19/mo, RECOMMENDED badge):
- Everything in Free, plus:
- Up to 10 active projects
- Up to 5,000 findings stored (90-day retention)
- Slack / Microsoft Teams webhook notifications
- SARIF and OWASP report generation and download

**Team tier** ($35/mo, corrected from $49/mo):
- Everything in Pro, plus:
- Unlimited active projects and findings (365-day retention)
- Team management (invite members, assign roles)
- Custom YAML rule uploads
- Baseline management
- Execution audit trail

**Enterprise tier** (Custom):
- Everything in Team, plus:
- SSO (SAML 2.0 / OIDC)
- Compliance data exports
- Custom retention periods
- Dedicated support and SLA guarantees
- Manual enterprise provisioning
- *(Remove "On-premise deployment" — not implemented)*

### Group M: SARIF flag (Req 13)

| File | Before | After |
|---|---|---|
| `Download.tsx` quick-start block | `sicario scan . --output sarif > results.sarif` | `sicario scan . --format sarif --sarif-output results.sarif` |

### Group N: Docs footer version (Req 14)

| File | Before | After |
|---|---|---|
| `Docs.tsx` footer | `Sicario CLI v1.0.0` | `Sicario CLI` (version string removed; GitHub releases link retained) |

### Group O: Privacy policy infrastructure (Req 15)

| File | Before | After |
|---|---|---|
| `Privacy.tsx` section 04 | `"payment processing (Stripe) and infrastructure (AWS/Google Cloud)"` | `"payment processing (Whop) and backend infrastructure (Convex)"` |

### Group P: Dashboard copy fixes (Req 23)

| Location | Before | After |
|---|---|---|
| `Dashboard.tsx` tier type | `'COMMUNITY' \| 'TEAM'` | `'free' \| 'team'` |
| `Dashboard.tsx` tier state | `useState<'COMMUNITY' \| 'TEAM'>('COMMUNITY')` | `useState<'free' \| 'team'>('free')` |
| `Dashboard.tsx` all `tier === 'COMMUNITY'` checks | `tier === 'COMMUNITY'` | `tier === 'free'` |
| `Dashboard.tsx` tier badge display | `{tier}` (renders "COMMUNITY") | `{tier === 'free' ? 'Free' : 'Team'}` |
| `Dashboard.tsx` upgrade modal heading | `"Upgrade to Team"` | `"Upgrade to Pro — $19/mo"` |
| `Dashboard.tsx` upgrade modal button | `"Upgrade for $49/mo"` | `"Upgrade to Pro — $19/mo"` |
| `Dashboard.tsx` upgrade modal footer | `"Secure payment via Lemon Squeezy"` | `"Secure payment via Whop"` |
| `Dashboard.tsx` upgrade modal feature list | Current inaccurate list | Team plan features matching Req 22 |
| `Dashboard.tsx` sidebar email | `immanuelenyi@gmail.com` (hardcoded) | `{identity?.email ?? 'your@email.com'}` using Convex `useConvexAuth` identity |
| `Dashboard.tsx` empty state version | `v0.6.4-stable` | *(removed entirely)* |

### Group Q: "Edge CLI" terminology (Req 24)

All five dashboard pages replace `"Edge CLI"` with `"Sicario CLI"` as a simple string substitution. The exact occurrences:

| File | String replaced |
|---|---|
| `ScansPage.tsx` | `"Edge CLI"` → `"Sicario CLI"` |
| `ScanDetailPage.tsx` | `"Edge CLI"` → `"Sicario CLI"` |
| `PrCheckDetailPage.tsx` | `"Source: Edge CLI (CI pipeline)"` → `"Source: Sicario CLI (CI pipeline)"` |
| `AnalyticsPage.tsx` | `"Edge CLI"` → `"Sicario CLI"`, `"Data source: Edge CLI telemetry"` → `"Data source: Sicario CLI telemetry"` |
| `OwaspPage.tsx` | `"Edge CLI"` → `"Sicario CLI"`, `"Data source: Edge CLI telemetry"` → `"Data source: Sicario CLI telemetry"` |

### Group R: PR check snippet removal (Req 22.34)

| File | Change |
|---|---|
| `PrCheckDetailPage.tsx` | Remove the `snippet` column from the findings table. Replace with a `"Run sicario fix --id=<id> locally to view"` instruction cell. |

### Group S: Docs.tsx licensing section (Req 26)

| Change | Detail |
|---|---|
| Rename "Community (Free)" | → "Free" |
| Add Pro tier | $19/mo, between Free and Team |
| Fix Team price | $49/mo → $35/mo |
| Update tier descriptions | Match Req 22 feature gates |

---

## Data Models

No new data models are introduced. The only model change is the `Dashboard.tsx` tier type narrowing:

```tsx
// Before
type Tier = 'COMMUNITY' | 'TEAM';

// After
type Tier = 'free' | 'team';
```

---

## Homebrew Tap Design

### `Formula/sicario.rb`

The formula uses `on_macos` with `Hardware::CPU.arm?` to select the correct binary. It references the tarballs produced by the existing `release.yml` workflow (`sicario-darwin-arm64.tar.gz` and `sicario-darwin-amd64.tar.gz`).

```ruby
class Sicario < Formula
  desc "Next-generation SAST, SCA, and secret scanner"
  homepage "https://usesicario.xyz"
  version "0.1.0"  # bumped automatically by CI

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/sicario-labs/sicario-cli/releases/download/v#{version}/sicario-darwin-arm64.tar.gz"
      sha256 "PLACEHOLDER_ARM64_SHA256"
    else
      url "https://github.com/sicario-labs/sicario-cli/releases/download/v#{version}/sicario-darwin-amd64.tar.gz"
      sha256 "PLACEHOLDER_AMD64_SHA256"
    end
  end

  def install
    bin.install "sicario"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sicario --version")
  end
end
```

### `release.yml` addition

The bump step runs after the GitHub Release is created and is gated on `HOMEBREW_TAP_TOKEN`:

```yaml
- name: Bump Homebrew formula
  uses: mislav/bump-homebrew-formula-action@v3
  if: ${{ env.HOMEBREW_TAP_TOKEN != '' }}
  env:
    COMMITTER_TOKEN: ${{ secrets.HOMEBREW_TAP_TOKEN }}
    HOMEBREW_TAP_TOKEN: ${{ secrets.HOMEBREW_TAP_TOKEN }}
  with:
    formula-name: sicario
    formula-path: Formula/sicario.rb
    homebrew-tap: sicario-labs/homebrew-sicario-cli
    tag-name: ${{ github.ref_name }}
    download-url: https://github.com/sicario-labs/sicario-cli/releases/download/${{ github.ref_name }}/sicario-darwin-arm64.tar.gz
```

If `HOMEBREW_TAP_TOKEN` is absent, the `if:` condition causes the step to be skipped with a visible warning in the Actions log (satisfies Req 21.7 — the step does not silently succeed).

---

## Correctness Properties

### Property 1: Slug round-trip

For all 16 slugs in `NAV_GROUPS`, the `DocsLayout` sidebar SHALL generate a `<Link to={/docs/${slug}}>` that resolves to exactly one `Docs*Page` component, and that component's page title SHALL match the `name` field in `NAV_GROUPS`.

**Validates: Req 19.1, 19.2**

### Property 2: Unknown slug redirect

For any path matching `/docs/<unknown>` where `<unknown>` is not one of the 16 registered slugs, the router SHALL redirect to `/docs/overview` without rendering a blank page.

**Validates: Req 19.3**

### Property 3: Copy fix completeness

For each string listed in the Copy Fix Inventory (Groups A–S), the string SHALL NOT appear in the final rendered output of the corresponding page after the fix is applied.

**Validates: Reqs 1–15, 22–26**

### Property 4: Zero-exfiltration preservation

After the `PrCheckDetailPage.tsx` snippet column removal, no `snippet` field value from the Convex database SHALL be rendered in any dashboard page's DOM.

**Validates: Req 22.35**

### Property 5: Pricing tier count

After the Pricing.tsx restructure, the page SHALL render exactly 4 tier cards: Free ($0), Pro ($19/mo), Team ($35/mo), Enterprise (Custom).

**Validates: Req 22**

### Property 6: Docs page heading hierarchy

For each of the 16 `Docs*Page` components, the rendered HTML SHALL contain exactly one `<h1>` element (the page title), and all section headings SHALL use `<h2>` or `<h3>` — never a second `<h1>`.

**Validates: Req 20.2**

### Property 7: Sidebar accessibility

The `DocsLayout` sidebar SHALL be wrapped in a `<nav>` element containing a `<ul>` with `<li>` children for each navigation link.

**Validates: Req 20.1**

### Property 8: Mobile sidebar focus management

When the mobile sidebar toggle is activated, the first `<a>` element inside the sidebar SHALL receive programmatic focus via `useRef` + `focus()` called in a `useEffect` triggered by `isSidebarOpen`.

**Validates: Req 20.3**

### Property 9: Homebrew formula version sync

After the `bump-homebrew-formula-action` step runs on a release tag `vX.Y.Z`, the `version` field in `Formula/sicario.rb` SHALL equal `X.Y.Z` and the `sha256` fields SHALL match the SHA256 checksums of the release tarballs.

**Validates: Req 21.9**

---

## Implementation Notes

### Extracting `CodeBlock`

The `CodeBlock` component currently lives inline in `Docs.tsx`. It is moved to `pages/docs/CodeBlock.tsx` and re-imported in `Docs.tsx` to avoid duplication. The `aria-label` addition to the copy button is the only behavioral change.

### `DocsLayout` lazy loading

`DocsLayout` and all `Docs*Page` components are added to `App.tsx` as `lazy()` imports, consistent with the existing pattern for dashboard pages. This keeps the initial bundle size unchanged.

### Pricing.tsx grid change

The existing 3-column `grid-cols-1 md:grid-cols-3` grid becomes `grid-cols-1 md:grid-cols-2 lg:grid-cols-4` to accommodate 4 tiers. On medium viewports, tiers stack 2×2. The Pro tier card receives the `border-[#ADFF2F]/30` highlight and "RECOMMENDED" badge currently on the Team card.

### Dashboard.tsx email

The hardcoded `immanuelenyi@gmail.com` is replaced with the authenticated user's email. `Dashboard.tsx` already imports `useConvexAuth` — the identity object from `useConvexAuth()` exposes `tokenIdentifier` but not email directly. The replacement uses the Convex `useQuery(api.auth.currentUser)` pattern already used elsewhere in the dashboard, or falls back to `"your@email.com"` if unauthenticated.

### `release.yml` placement

The bump step is placed immediately after the step that creates the GitHub Release (identified by `uses: softprops/action-gh-release` or equivalent). It runs only on `push` events with a `v*` tag pattern, matching the existing release trigger.

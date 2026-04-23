# Requirements Document

## Introduction

The Sicario Frontend Overhaul is a comprehensive redesign of the existing React + Vite + Tailwind CSS v4 landing page and cloud dashboard. The current frontend content is themed around a fictional "autonomous red-teaming swarm" with AI agents, but Sicario is actually a next-generation SAST/SCA/Secret scanning CLI tool built in Rust with AI remediation capabilities. All pages must be rewritten to accurately reflect Sicario's real product identity — a single-binary security scanner providing static analysis, dependency auditing, secret detection, AI-powered code fixes, compiler-style diagnostics, an interactive TUI, MCP server integration, SARIF/OWASP reporting, and a cloud dashboard — while preserving the existing dark-theme design system and aesthetic (backgrounds, accent colors, fonts, noise textures, grid backgrounds, bento cards, shimmer effects, rotating conic gradient borders, marquee animations, and chromatic aberration hover effects).

## Glossary

- **Landing_Page**: The public-facing marketing website comprising Home, Product, Pricing, FAQ, and Docs pages
- **Cloud_Dashboard**: The authenticated web application for viewing scan results, findings, projects, and OWASP reports (Dashboard.tsx)
- **Auth_Page**: The authentication page for signing into the Sicario Cloud Dashboard (Auth.tsx)
- **Navbar**: The top navigation bar rendered in App.tsx with links, dropdowns, and CTAs
- **Footer**: The site-wide footer rendered in App.tsx with links, branding, and badges
- **Design_System**: The preserved visual language including #121212/#1C1C1C/#0A0A0A backgrounds, #ADFF2F accent, Inter/JetBrains Mono fonts, noise texture, grid backgrounds, bento cards, shimmer text, rotating conic borders, marquee animations, and chromatic aberration effects
- **Home_Page**: The landing page hero and feature overview (Home.tsx)
- **Product_Page**: The detailed product capabilities page (Product.tsx)
- **Pricing_Page**: The pricing tiers page (Pricing.tsx)
- **FAQ_Page**: The frequently asked questions page (FAQ.tsx)
- **Docs_Page**: The documentation page for CLI commands and usage (Docs.tsx)
- **Icons_Component**: The shared SVG icon component library (Icons.tsx)
- **Terms_Page**: The Terms of Service page (Terms.tsx)
- **Privacy_Page**: The Privacy Policy page (Privacy.tsx)

## Requirements

### Requirement 1: Home Page Overhaul

**User Story:** As a visitor, I want the home page to clearly communicate that Sicario is a SAST/SCA/Secret scanning CLI tool with AI remediation, so that I immediately understand the product's value proposition.

#### Acceptance Criteria

1. THE Home_Page SHALL display a hero section with headline text communicating Sicario's identity as a security scanning CLI tool, replacing all references to "red-teaming swarm", "hunting", "siege", and "deploy a siege"
2. THE Home_Page SHALL display a subheadline describing Sicario's core capabilities: SAST with 500+ rules across 5 languages, SCA, secret scanning, and AI-powered remediation
3. THE Home_Page SHALL include two CTA buttons: one linking to the Auth_Page labeled for getting started, and one linking to the Docs_Page labeled for reading documentation
4. THE Home_Page SHALL display a bento grid feature section with cards representing actual Sicario capabilities: SAST engine, SCA scanning, secret detection, AI remediation, compiler-style diagnostics, interactive TUI, MCP server, and SARIF/OWASP reporting
5. THE Home_Page SHALL display a technology marquee showing the 5 supported languages (Go, Java, JavaScript/TypeScript, Python, Rust) instead of frontend frameworks
6. THE Home_Page SHALL include a terminal-style code preview showing realistic `sicario scan .` output with compiler-style diagnostics including severity, CWE headers, source context, and span underlines
7. THE Home_Page SHALL preserve all Design_System elements including the bg-grid, noise overlay, bento card layout, shimmer text effect, chromatic aberration hover, and marquee animations

### Requirement 2: Product Page Overhaul

**User Story:** As a visitor, I want the product page to showcase Sicario's actual technical capabilities, so that I can evaluate the tool against competitors.

#### Acceptance Criteria

1. THE Product_Page SHALL replace all 7 fictional AI agent descriptions (Cartographer, Breacher, Critic, Ghost, Accountant, Admin, Scribe) with actual Sicario capability modules: SAST Engine, SCA Scanner, Secret Scanner, AI Remediation, Data-Flow Reachability, Compiler Diagnostics, Interactive TUI, and MCP Server
2. THE Product_Page SHALL display a hero section with headline text communicating Sicario's position as a next-generation security CLI replacing legacy Python and Node.js scanners
3. THE Product_Page SHALL include a feature comparison section showing Sicario's advantages over Semgrep, Bandit, and ESLint Security across capabilities such as multi-language support, secret scanning, SCA, data-flow reachability, AI auto-remediation, interactive TUI, MCP server, single static binary, and SARIF/OWASP reports
4. THE Product_Page SHALL display a code section showing realistic CLI usage examples with actual Sicario commands (`sicario scan .`, `sicario tui`, `sicario fix`, `sicario report`) instead of fictional SDK code
5. THE Product_Page SHALL include a capabilities grid using the existing bento card design pattern with icons representing each module
6. THE Product_Page SHALL replace the swarm SVG diagram with a visual representing Sicario's architecture: Parser, Engine, Scanner, Remediation, Output, Auth, Cloud, and MCP modules
7. THE Product_Page SHALL preserve all Design_System elements including the bg-grid, shimmer text, and card hover effects

### Requirement 3: Pricing Page Overhaul

**User Story:** As a visitor, I want to see realistic pricing tiers for a SAST tool, so that I can choose the right plan for my team.

#### Acceptance Criteria

1. THE Pricing_Page SHALL replace the "Shadow" tier with a "Community" free tier describing: full CLI access, SAST scanning with all 500+ rules, secret scanning, SCA scanning, compiler-style diagnostics, and local-only usage
2. THE Pricing_Page SHALL replace the "Operator" tier with a "Team" tier at a reasonable price point describing: everything in Community plus cloud dashboard access, team collaboration, OWASP compliance reports, webhook integrations, and priority support
3. THE Pricing_Page SHALL replace the "State-Actor" tier with an "Enterprise" tier with custom pricing describing: everything in Team plus SSO/SAML, dedicated support, custom rule development, SLA guarantees, and on-premise deployment options
4. THE Pricing_Page SHALL remove all red-team language including "hunters", "hits", "sieges", and "swarm" from tier descriptions and feature lists
5. THE Pricing_Page SHALL update CTA button labels to reflect actual actions: "Install CLI" for Community, "Start Free Trial" for Team, and "Contact Sales" for Enterprise
6. THE Pricing_Page SHALL preserve the Design_System card layout, accent colors, and the "RECOMMENDED" badge on the middle tier

### Requirement 4: FAQ Page Overhaul

**User Story:** As a visitor, I want to read FAQs about Sicario's actual capabilities, so that I can resolve common questions about the tool.

#### Acceptance Criteria

1. THE FAQ_Page SHALL replace all red-teaming FAQs with questions relevant to a SAST/SCA/Secret scanning CLI tool
2. THE FAQ_Page SHALL include FAQs covering: supported languages, installation methods (Homebrew, curl installer, cargo build), CI/CD integration, AI remediation capabilities, false positive reduction via data-flow reachability, custom YAML rules, MCP server integration, and cloud dashboard features
3. THE FAQ_Page SHALL contain a minimum of 8 FAQ entries covering the breadth of Sicario's capabilities
4. THE FAQ_Page SHALL preserve the existing expand-on-hover interaction pattern and Design_System styling

### Requirement 5: Docs Page Overhaul

**User Story:** As a developer, I want the documentation page to describe actual Sicario CLI commands and usage, so that I can learn how to use the tool effectively.

#### Acceptance Criteria

1. THE Docs_Page SHALL replace all fictional commands (`hit`, `watch`, `siege`) with actual Sicario CLI commands: `scan`, `tui`, `fix`, `report`, `login`, `publish`, `baseline`, `hook install`, `benchmark`, and `rules test`
2. THE Docs_Page SHALL document installation methods: Homebrew (`brew install`), shell installer (`curl | sh`), and building from source (`cargo build --release`)
3. THE Docs_Page SHALL document authentication via `sicario login` using OAuth 2.0 + PKCE device flow instead of API key-based authentication
4. THE Docs_Page SHALL include code blocks with copy functionality showing realistic command examples with actual flags and options (e.g., `sicario scan . --format sarif`, `sicario scan . --severity-threshold high`, `sicario fix path/to/file.js --rule SQL-001`)
5. THE Docs_Page SHALL document key capabilities sections: SAST scanning, SCA scanning, secret scanning, AI remediation with backup/rollback, SARIF/OWASP reporting, TUI dashboard, MCP server, git hooks, and baseline management
6. THE Docs_Page SHALL replace all references to "swarm", "siege", "hit", "nodes", "Shadow DOM piercing", "live-fire", and "Scribe patches" with accurate Sicario terminology
7. THE Docs_Page SHALL update the sidebar navigation to reflect actual documentation sections
8. THE Docs_Page SHALL preserve the existing CodeBlock component with copy functionality and the sidebar navigation layout

### Requirement 6: Dashboard Page Overhaul

**User Story:** As an authenticated user, I want the cloud dashboard to show scan results, findings, and OWASP reports, so that I can monitor my team's security posture.

#### Acceptance Criteria

1. THE Cloud_Dashboard SHALL replace "Mission Control" with a "Dashboard" or "Overview" view showing scan statistics: total findings, findings by severity (Critical, High, Medium, Low, Info), recent scans, and projects
2. THE Cloud_Dashboard SHALL replace "Perimeter Targets" with a "Projects" view listing scanned repositories/projects
3. THE Cloud_Dashboard SHALL replace "Breach Reports" with a "Findings" view showing detected vulnerabilities with severity, CWE ID, file path, and rule ID
4. THE Cloud_Dashboard SHALL replace "Remediation Vault" with an "AI Fixes" view showing applied and pending AI-generated patches
5. THE Cloud_Dashboard SHALL replace "Live Swarm Feed" with a "Scan History" view showing past scan runs with timestamps, duration, and finding counts
6. THE Cloud_Dashboard SHALL replace all swarm-themed stat cards (Swarm Status, Breaches Isolated, Scribe Patches, Last Siege) with security-relevant metrics: Total Findings, Critical Issues, Scans Run, and Last Scan timestamp
7. THE Cloud_Dashboard SHALL replace the "Deploy Your First Swarm" onboarding flow with a "Run Your First Scan" flow showing: install Sicario CLI, authenticate with `sicario login`, and run `sicario scan .`
8. THE Cloud_Dashboard SHALL update the sidebar navigation labels and icons to reflect actual dashboard sections
9. THE Cloud_Dashboard SHALL replace the upgrade modal content from swarm/red-team language to SAST tool features: unlimited cloud syncs, team collaboration, OWASP compliance reports, and webhook integrations
10. THE Cloud_Dashboard SHALL preserve the existing sidebar layout, stat card grid, and Design_System styling

### Requirement 7: Auth Page Overhaul

**User Story:** As a user, I want the authentication page to reference the Sicario Cloud Dashboard accurately, so that I understand what I am signing into.

#### Acceptance Criteria

1. THE Auth_Page SHALL replace "Sign in to your Mission Control" with "Sign in to Sicario Cloud"
2. THE Auth_Page SHALL replace the right-pane testimonial quote about "red-teaming" and "nation-state actor" with a testimonial about Sicario's scanning speed, accuracy, and AI remediation capabilities relevant to a SAST tool
3. THE Auth_Page SHALL preserve the existing two-pane layout, OAuth buttons (GitHub, SSO), email/password form, and Design_System styling

### Requirement 8: Navbar and Footer Overhaul

**User Story:** As a visitor, I want the navigation and footer to reflect Sicario's actual product structure, so that I can navigate the site effectively.

#### Acceptance Criteria

1. THE Navbar SHALL replace the Product dropdown containing "Core Swarm" and "Specialized Nodes" sections with dropdown sections reflecting actual Sicario capabilities: "Analysis" (SAST, SCA, Secrets, Reachability) and "Tools" (AI Remediation, TUI Dashboard, MCP Server, SARIF Reports)
2. THE Navbar SHALL update the primary CTA button from "Start Hunting" to a label reflecting actual usage such as "Get Started" or "Install CLI"
3. THE Navbar SHALL update the mobile menu CTA from "Deploy a Siege" to match the updated desktop CTA
4. THE Footer SHALL replace the tagline "The autonomous red-teaming swarm. Stop scanning. Start hunting." with a tagline reflecting Sicario's actual identity as a SAST/SCA/Secret scanning CLI
5. THE Footer SHALL update the security badges from "Zero-Footprint Architecture" and "Fully Local Execution" to badges relevant to Sicario such as "Single Binary, Zero Dependencies" and "500+ Security Rules"
6. THE Footer SHALL preserve the existing layout structure, link groups, and Design_System styling

### Requirement 9: Icons Component Update

**User Story:** As a developer, I want the Icons component to include security-themed icons appropriate for a SAST tool, so that the UI accurately represents Sicario's capabilities.

#### Acceptance Criteria

1. THE Icons_Component SHALL retain all existing generic utility icons (IconMenu, IconX, IconChevronDown, IconCheck, IconGithub, IconShield, IconZap, IconTerminal) and technology brand icons
2. THE Icons_Component SHALL add new security-themed icons as needed for: SAST scanning, SCA/dependency analysis, secret detection, AI remediation/fix, data-flow/reachability, report generation, and cloud sync
3. WHEN swarm-themed icons (IconCartographer, IconBreacher, IconCritic, IconGhost, IconAccountant, IconAdmin, IconScribe) are no longer referenced by any page, THE Icons_Component SHALL remove them or repurpose them with appropriate names
4. THE Icons_Component SHALL maintain the existing SVG icon pattern: functional components accepting a `className` prop with consistent viewBox, stroke, and fill attributes

### Requirement 10: Terms and Privacy Pages Update

**User Story:** As a visitor, I want the legal pages to accurately describe Sicario as a SAST tool, so that the terms and privacy policy are consistent with the product.

#### Acceptance Criteria

1. THE Terms_Page SHALL replace "autonomous red-teaming swarm" and "Swarm Nodes" references with descriptions of Sicario as a static application security testing CLI tool
2. THE Terms_Page SHALL replace "sieges" and "targets" language with "scans" and "projects" language appropriate for a SAST tool
3. THE Privacy_Page SHALL replace "siege frequency, target URLs" data collection descriptions with "scan frequency, project metadata" descriptions appropriate for a SAST tool
4. THE Privacy_Page SHALL replace "Siege results and vulnerability reports" with "Scan results and vulnerability findings" language
5. THE Privacy_Page SHALL replace "AI swarm's accuracy" with "scanning engine's accuracy" language
6. BOTH pages SHALL preserve the existing numbered section layout, card styling, and Design_System elements

### Requirement 11: Design System Preservation

**User Story:** As a stakeholder, I want the existing visual design system preserved across all pages, so that the overhaul maintains brand consistency and aesthetic quality.

#### Acceptance Criteria

1. THE Landing_Page SHALL preserve background colors: #121212, #1C1C1C, #0A0A0A for page backgrounds and #111111, #232323 for card backgrounds
2. THE Landing_Page SHALL preserve the #ADFF2F accent color for CTAs, highlights, active states, and hover effects
3. THE Landing_Page SHALL preserve border colors: #2E2E2E and white/5 for card and section borders
4. THE Landing_Page SHALL preserve the Inter font for body text and JetBrains Mono font for code and monospace elements
5. THE Landing_Page SHALL preserve the noise texture overlay, grid background with radial mask, and all CSS animations defined in index.css
6. THE Landing_Page SHALL preserve the rotating conic gradient border effect on hover for interactive cards
7. THE Landing_Page SHALL preserve the shimmer text effect, chromatic aberration hover effect, and marquee animations
8. THE Landing_Page SHALL preserve the bento card layout pattern with min-height, overflow-hidden, group hover states, and abstract background visuals

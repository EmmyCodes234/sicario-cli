# Implementation Plan: Sicario Frontend Overhaul

## Overview

Content-in-place replacement across 11 React component files to rebrand the Sicario frontend from a fictional "autonomous red-teaming swarm" to its actual identity as a SAST/SCA/Secret scanning CLI tool with AI remediation. No new routes, dependencies, or structural changes. Icons.tsx is done first (shared dependency), then App.tsx (shared shell), then remaining pages in order.

## Tasks

- [x] 1. Update Icons.tsx — Replace swarm-themed icons with security-tool icons
  - [x] 1.1 Replace swarm icon components with security-tool equivalents
    - Rename/replace `IconCartographer` → `IconSast`, `IconBreacher` → `IconSca`, `IconCritic` → `IconSecrets`, `IconGhost` → `IconReachability`, `IconAccountant` → `IconAiFix`, `IconAdmin` → `IconCloudSync`, `IconScribe` → `IconReport`
    - Each new icon must be a hand-crafted SVG following the existing pattern: functional component accepting `className` prop, `viewBox="0 0 24 24"`, `fill="none"`, `stroke="currentColor"`, `strokeWidth="1.5"`, `strokeLinecap="square"`
    - _Requirements: 9.3, 9.4_
  - [x] 1.2 Add new icons for additional capabilities
    - Add `IconTui` (interactive TUI dashboard), `IconMcp` (MCP server), `IconRust`, `IconGo`, `IconJava`, `IconPython` (language brand icons)
    - Retain all existing generic utility icons (IconMenu, IconX, IconChevronDown, IconCheck, IconGithub, IconShield, IconZap, IconTerminal) and technology brand icons unchanged
    - _Requirements: 9.1, 9.2, 9.4_

- [x] 2. Update App.tsx — Overhaul Navbar and Footer content
  - [x] 2.1 Update Navbar product dropdown and CTAs
    - Replace "Core Swarm" / "Specialized Nodes" dropdown sections with "Analysis" (SAST, SCA, Secrets, Reachability) and "Tools" (AI Remediation, TUI Dashboard, MCP Server, SARIF Reports)
    - Update icon imports from old swarm names to new security-tool names (IconSast, IconSca, etc.)
    - Change CTA button "Start Hunting" → "Get Started"
    - Change mobile CTA "Deploy a Siege" → "Get Started"
    - _Requirements: 8.1, 8.2, 8.3_
  - [x] 2.2 Update Footer content
    - Replace tagline "The autonomous red-teaming swarm. Stop scanning. Start hunting." → "Next-generation SAST, SCA, and secret scanning. One binary. Zero compromise."
    - Update security badges: "Zero-Footprint Architecture" → "Single Binary, Zero Dependencies"; "Fully Local Execution" → "500+ Security Rules"
    - Update "Read our architecture doc" → "Read our documentation" linking to `/docs`
    - Update GitHub URL to `https://github.com/EmmyCodes234/sicario-cli`
    - Replace NPM link with Homebrew or appropriate link
    - _Requirements: 8.4, 8.5, 8.6_

- [ ] 3. Checkpoint — Verify shared components
  - Ensure Icons.tsx and App.tsx compile without errors. Run `npm run build` and `npm run lint` in `sicario-frontend/`. Ask the user if questions arise.

- [x] 4. Update Home.tsx — Overhaul landing page content
  - [x] 4.1 Update hero section and CTAs
    - Replace headline "Stop scanning. Start hunting." with SAST-focused headline (e.g., "Find vulnerabilities. Fix them automatically.")
    - Replace subheadline from swarm description to Sicario's actual value prop (SAST with 500+ rules, SCA, secret scanning, AI remediation)
    - Change CTA "Deploy a Siege" → "Get Started"; keep "Read the Docs"
    - _Requirements: 1.1, 1.2, 1.3_
  - [x] 4.2 Update marquee and bento grid sections
    - Replace frontend framework icons (React, Next.js, Node.js, Docker, AWS) with supported language icons (Go, Java, JavaScript/TypeScript, Python, Rust) in the marquee
    - Update marquee caption to "500+ rules across 5 languages."
    - Replace 8 swarm-themed bento cards with 8 Sicario capability cards: SAST Engine (wide), SCA Scanner, Secret Detection, AI Remediation, Compiler Diagnostics, Interactive TUI, MCP Server, SARIF/OWASP Reports
    - Update icon imports from swarm names to new security-tool names
    - _Requirements: 1.4, 1.5, 1.7_
  - [x] 4.3 Add terminal preview and update bottom CTA
    - Add a terminal-style code block showing realistic `sicario scan .` output with compiler-style diagnostics (severity, CWE header, source context, span underlines, help text, summary footer)
    - Replace bottom CTA "Deploy against any architecture" → "Scan any codebase"
    - Update bottom technology marquee to show supported languages instead of frontend frameworks
    - _Requirements: 1.6, 1.7_

- [x] 5. Update Product.tsx — Overhaul product capabilities page
  - [x] 5.1 Update hero section and SVG diagram
    - Replace red-team headline with SAST tool positioning (e.g., "Next-gen security scanning (without the Python overhead)")
    - Replace subheadline from swarm description to Sicario capabilities
    - Replace CTAs: "Deploy a Siege" → "Get Started"
    - Replace swarm SVG node diagram with architecture diagram showing Parser → Engine → Scanner → Remediation → Output modules
    - _Requirements: 2.2, 2.6_
  - [x] 5.2 Update feature sections and code block
    - Replace 3 swarm-themed feature blocks (Stealth, Logic-First, Realtime Siege) with 3 Sicario feature blocks: Deep Static Analysis, AI-Powered Remediation, Developer Experience
    - Replace fictional SDK code with actual CLI usage examples (`sicario scan .`, `sicario tui`, `sicario fix`, `sicario report`)
    - Update SDK language tags to CLI/CI-CD/SARIF/OWASP context tags
    - _Requirements: 2.4, 2.7_
  - [x] 5.3 Update extensions grid and add comparison table
    - Replace 7 swarm nodes with 8 Sicario capability module cards using new security-themed icons
    - Remove or replace "MORE_NODES_IN_DEV" placeholder
    - Add feature comparison table vs Semgrep, Bandit, and ESLint Security (sourced from README)
    - Update final CTA from "Ready to start the siege?" to SAST-appropriate language
    - _Requirements: 2.1, 2.3, 2.5_

- [x] 6. Update Pricing.tsx — Overhaul pricing tiers
  - Replace "Shadow" tier → "Community" ($0/month) with features: full CLI access, SAST with 500+ rules, secret scanning, SCA, compiler diagnostics, local-only usage. CTA: "Install CLI"
  - Replace "Operator" tier → "Team" ($49/month) with features: everything in Community plus cloud dashboard, team collaboration, OWASP reports, webhooks, priority support. CTA: "Start Free Trial". Keep RECOMMENDED badge.
  - Replace "State-Actor" tier → "Enterprise" (custom pricing) with features: everything in Team plus SSO/SAML, dedicated support, custom rules, SLA, on-premise. CTA: "Contact Sales"
  - Remove all red-team language ("hunters", "hits", "sieges", "swarm") from descriptions and feature lists
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.6_

- [x] 7. Update FAQ.tsx — Replace FAQs with SAST-relevant content
  - Replace 4 red-team FAQs with 8+ SAST-relevant FAQ entries covering: supported languages, installation methods, CI/CD integration, AI remediation, false positive reduction via reachability, custom YAML rules, MCP server, cloud dashboard features
  - Preserve the existing expand-on-hover interaction pattern and Design_System styling
  - _Requirements: 4.1, 4.2, 4.3, 4.4_

- [x] 8. Update Docs.tsx — Overhaul documentation page
  - [x] 8.1 Update sidebar navigation and introduction
    - Replace sidebar groups ("The Arsenal", "Capabilities") with actual doc sections: Getting Started (Overview, Installation, Authentication), CLI Commands (scan, tui, fix, report, baseline, hook install, benchmark, rules test), Cloud (login, publish, whoami), Capabilities (SAST, SCA, Secrets, AI Remediation, Reachability, Reporting), Platform (Licensing)
    - Replace introduction from "Autonomous Red-Team Swarm" to Sicario's actual identity as a SAST/SCA/Secret scanning CLI
    - Update icon imports to new security-tool names
    - _Requirements: 5.6, 5.7, 5.8_
  - [x] 8.2 Update installation and authentication sections
    - Replace `npx sicario-red-team` with three installation methods: Homebrew, curl installer, cargo build
    - Replace API key auth ("Vault Key") with `sicario login` browser-based OAuth 2.0 + PKCE flow
    - _Requirements: 5.2, 5.3_
  - [x] 8.3 Update command sections and capabilities
    - Replace fictional commands (`hit`, `watch`, `siege`) with actual CLI commands: `scan`, `tui`, `fix`, `report`, `baseline`, `hook install`, `benchmark`, `rules test`
    - Include code blocks with copy functionality showing realistic command examples with actual flags
    - Document key capabilities: SAST, SCA, secret scanning, AI remediation, SARIF/OWASP reporting, TUI, MCP server, git hooks, baseline management
    - _Requirements: 5.1, 5.4, 5.5_
  - [x] 8.4 Update licensing section and footer
    - Replace "Shadow Tier" / "Operator Tier" with "Community" / "Team" terminology
    - Replace swarm language with SAST tool features
    - Update CTA from "Upgrade to Operator Tier" → "Upgrade to Team"
    - Update docs footer version and links (replace NPM with Homebrew, update GitHub URL)
    - _Requirements: 5.6, 5.8_

- [ ] 9. Checkpoint — Verify pages compile
  - Ensure all updated pages compile without errors. Run `npm run build` and `npm run lint` in `sicario-frontend/`. Ask the user if questions arise.

- [x] 10. Update Dashboard.tsx — Overhaul cloud dashboard content
  - [x] 10.1 Update sidebar navigation and stat cards
    - Replace sidebar nav labels: "Mission Control" → "Overview", "Perimeter Targets" → "Projects", "Live Swarm Feed" → "Scan History", "Breach Reports" → "Findings", "Remediation Vault" → "AI Fixes", "API Keys" → keep or update
    - Replace stat cards: "SWARM STATUS" → "TOTAL FINDINGS", "BREACHES ISOLATED" → "CRITICAL ISSUES", "SCRIBE PATCHES" → "SCANS RUN", "LAST SIEGE" → "LAST SCAN"
    - Update icon imports to new security-tool names
    - Replace `Breach` interface with `Finding` interface (id, ruleId, severity, cweId, filePath, message, time, fix)
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 6.8_
  - [x] 10.2 Update onboarding flow and upgrade modal
    - Replace "Deploy Your First Swarm" with "Run Your First Scan" showing: install Sicario CLI, `sicario login`, `sicario scan .`
    - Replace API key / "Vault Key" onboarding with OAuth-based `sicario login` flow
    - Replace "Waiting for handshake..." with "Waiting for first scan..."
    - Update upgrade modal: "Upgrade to Operator Tier" → "Upgrade to Team"; replace swarm features with Team tier features (cloud syncs, collaboration, OWASP reports, webhooks)
    - Replace all remaining swarm/siege/breach language in view content
    - _Requirements: 6.7, 6.9, 6.10_

- [x] 11. Update Auth.tsx — Overhaul authentication page
  - Replace "Sign in to your Mission Control" → "Sign in to Sicario Cloud"
  - Replace right-pane testimonial quote about "red-teaming" and "nation-state actor" with a testimonial about Sicario's scanning speed, accuracy, and AI remediation
  - Preserve two-pane layout, OAuth buttons, email/password form, and Design_System styling
  - _Requirements: 7.1, 7.2, 7.3_

- [x] 12. Update Terms.tsx — Replace red-team language with SAST terminology
  - Replace "autonomous red-teaming swarm" → "static application security testing CLI tool"
  - Replace "Swarm Nodes" → "scanning engine"
  - Replace "sieges" / "targets" → "scans" / "projects"
  - Preserve numbered section layout, card styling, and Design_System elements
  - _Requirements: 10.1, 10.2, 10.6_

- [x] 13. Update Privacy.tsx — Replace red-team language with SAST terminology
  - Replace "siege frequency, target URLs" → "scan frequency, project metadata"
  - Replace "Siege results and vulnerability reports" → "Scan results and vulnerability findings"
  - Replace "AI swarm's accuracy" → "scanning engine's accuracy"
  - Preserve numbered section layout, card styling, and Design_System elements
  - _Requirements: 10.3, 10.4, 10.5, 10.6_

- [ ] 14. Final build verification
  - Run `npm run build` and `npm run lint` in `sicario-frontend/` to ensure zero TypeScript errors across all 11 files
  - Verify no broken imports or missing icon references
  - Ensure all internal `<Link to="...">` routes still resolve correctly
  - Ensure all Design_System elements are preserved (backgrounds, accent colors, noise overlay, grid, animations)
  - _Requirements: 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7, 11.8_

## Notes

- No property-based tests — this is a UI content replacement with no pure functions or business logic to test
- Each task references specific requirements for traceability
- Checkpoints at tasks 3, 9, and 14 ensure incremental build verification
- Icons.tsx must be completed first as all other files depend on the exported icon names
- App.tsx (Navbar/Footer) should be second as it's the shared shell across pages

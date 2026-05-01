# Execution Roadmap: sicario-monetization-and-llm

---

## Phase 1: Core Convex Schema & API Updates (Whop Webhooks, Subscriptions Table)

### 1.1 Schema

- [x] Add `subscriptions` table to `convex/convex/schema.ts` with all fields from Req 22.1: `orgId`, `plan`, `status`, `billingCycle`, `seatCount`, `currentPeriodStart`, `currentPeriodEnd`, `whopUserId` (optional), `whopSubscriptionId` (optional), `trialEndsAt` (optional), `customRetentionDays` (optional), `csmIdentifier` (optional), `contractStartDate` (optional)
- [x] Add `by_orgId` index on `subscriptions`
- [x] Add `usageSummary` table to schema with fields: `orgId`, `periodStart`, `periodEnd`, `findingsStored`, `projectCount`, `scansSubmitted`
- [x] Add compound `by_orgId_periodStart` index on `usageSummary`
- [x] Add `auditLog` table to schema with fields: `orgId`, `userId` (optional), `eventType`, `payload`, `timestamp`
- [x] Add `by_orgId_timestamp` index on `auditLog`
- [x] Run `npx convex dev` to validate schema compiles without errors

### 1.2 Billing Service Mutations & Queries

- [x] Create `convex/convex/billing.ts` with the following mutations and queries:
  - [x] `createSubscription(orgId)` — inserts a `free/active/manual` subscription record; called from org creation flow
  - [x] `getSubscription(orgId)` — query by `by_orgId` index
  - [x] `updateSubscription(orgId, fields)` — patches plan, status, whopUserId, whopSubscriptionId, currentPeriodStart, currentPeriodEnd
  - [x] `resetSeatCount(orgId)` — sets `seatCount: 0`; called by billing period cron
  - [x] `upsertUsageSummary(orgId, periodStart, periodEnd, delta)` — increments counters atomically
  - [x] `getUsageSummary(orgId, periodStart)` — query by compound index
  - [x] `appendAuditLog(orgId, eventType, payload, userId?)` — insert-only, no update/delete exposed
  - [x] `listAuditLog(orgId, fromTimestamp, toTimestamp)` — query for compliance export
- [x] Wire `createSubscription` into the organization creation path in `convex/convex/organizations.ts`

### 1.3 Whop Webhook HTTP Endpoint

- [x] Add `WHOP_WEBHOOK_SECRET` to Convex environment variables (document in `.env.local.example`)
- [x] Define `WHOP_PRODUCT_PLAN_MAP` constant in `convex/convex/billing.ts` mapping Whop product IDs to plan names
- [x] Add `POST /whop-webhook` route to `convex/convex/http.ts`:
  - [x] Read raw request body as `ArrayBuffer` before parsing JSON (required for HMAC verification)
  - [x] Verify `x-whop-signature` header using HMAC-SHA256 over raw body with `WHOP_WEBHOOK_SECRET`; return HTTP 401 on failure
  - [x] Parse JSON body; extract `event` type and `metadata.custom_req` as `orgId`
  - [x] If `custom_req` is missing or `orgId` not found in `subscriptions`, return HTTP 400 and call `appendAuditLog` with `eventType: "whop_webhook.malformed"`
  - [x] On `membership.went_valid`: call `updateSubscription` with `status: "active"`, plan from `WHOP_PRODUCT_PLAN_MAP`, `whopSubscriptionId`, `whopUserId`; call `appendAuditLog` with `eventType: "subscription.upgraded"`
  - [x] On `membership.went_invalid`: call `updateSubscription` with `status: "canceled"`, `plan: "free"`; call `appendAuditLog` with `eventType: "subscription.canceled"`
  - [x] Return HTTP 200 for all successfully processed events
- [x] Add CORS preflight `OPTIONS /whop-webhook` handler

### 1.4 Plan Enforcer

- [x] Create `convex/convex/planEnforcer.ts` exporting a `checkLimits(ctx, orgId, incomingFindingsCount, isNewProject)` helper:
  - [x] Fetch subscription by `orgId`; treat `past_due` as `free`
  - [x] Fetch current `usageSummary` for the active billing period
  - [x] Return `{ allowed: false, reason: "findings" | "projects" }` if limits exceeded
  - [x] Return `{ allowed: true }` otherwise
- [x] Integrate `checkLimits` into the `/api/v1/telemetry/scan` HTTP action in `http.ts` (before scan insert, after org resolution)
- [x] Return HTTP 402 with the correct error message body when `allowed: false`
- [x] Call `appendAuditLog` with `eventType: "plan_enforcer.rejected"` on every 402 response
- [x] Ensure CLI exit code is 0 on HTTP 402 (document in CLI error handling, not a Convex change)

### 1.5 Usage Tracking & 80% Warning

- [x] After each accepted telemetry payload, call `upsertUsageSummary` to update `findingsStored`, `projectCount`, `scansSubmitted`
- [x] After updating `usageSummary`, check if `findingsStored / planLimit >= 0.80`; if so, enqueue a webhook notification to the org's configured webhook URL (if set)
- [x] Add a `crons.ts` entry to reset `seatCount` to zero at the start of each billing period

### 1.6 Enterprise Manual Provisioning

- [x] Add `provisionEnterprise(orgId, contractStartDate, customRetentionDays, csmIdentifier)` mutation to `billing.ts`
- [x] This mutation bypasses Whop and directly sets `plan: "enterprise"`, `status: "active"`, `billingCycle: "manual"`, and the contract fields
- [x] Call `appendAuditLog` with `eventType: "subscription.enterprise_provisioned"` and `triggerSource: "admin"`

---

## Phase 2: Rust CLI Local Telemetry & Contributor Counting

### 2.1 Contributor Count Computation

- [x] Add `count_contributors(repo_path: &Path) -> u32` function to `sicario-cli/src/telemetry/mod.rs` (create module if absent):
  - [x] Run `git log --since="90 days ago" --format=%ae` via `std::process::Command`
  - [x] Collect unique email addresses using a `HashSet<String>`
  - [x] Return the count as `u32`
  - [x] If the command fails (not a git repo, git not installed), return `1` as the default
- [x] Add unit tests for `count_contributors` covering: normal repo, empty repo, non-git directory

### 2.2 Telemetry Payload Schema

- [x] Add `contributor_count: u32` field to the telemetry payload struct in `sicario-cli/src/telemetry/mod.rs`
- [x] Populate `contributor_count` from `count_contributors` before serializing the payload
- [x] Ensure the serialized JSON field name is `contributorCount` (camelCase, matching Convex expectation)
- [x] Verify no author names, emails, or commit messages are included in the payload (code review gate)

### 2.3 HTTP 402 Handling in CLI

- [x] In the telemetry HTTP client, handle HTTP 402 responses:
  - [x] Parse the `error` field from the JSON response body
  - [x] Print the error message to stderr with a `[sicario]` prefix
  - [x] Exit with code 0 (not a scan failure)
- [x] Add integration test: mock server returns 402, assert CLI exits 0 and prints the message

### 2.4 `sicario scan --publish` Unauthenticated Guard

- [x] When `--publish` is passed and no `SICARIO_API_KEY` is set, display: `"Publishing requires a free account. Sign up at https://usesicario.xyz/auth"`
- [x] Exit with code 0 (not an error)

---

## Phase 3: Dashboard UI Updates (Whop Checkout Redirects, Usage Meters)

### 3.1 Whop Plan URL Configuration

- [x] Create `convex/src/lib/whopPlans.ts` (or equivalent config file) with constants:
  ```ts
  export const WHOP_PLAN_URLS = {
    pro:        "https://whop.com/checkout/plan_XXXX_pro",
    team:       "https://whop.com/checkout/plan_XXXX_team",
    enterprise: "https://whop.com/checkout/plan_XXXX_enterprise",
  } as const;
  ```
- [x] All "Upgrade" button click handlers must import from this single file — no hardcoded URLs elsewhere

### 3.2 Upgrade Button Wiring

- [x] Locate all existing "Upgrade" / "Get Pro" / "Upgrade Plan" buttons in the Dashboard
- [x] Replace any existing Stripe checkout session creation calls with a direct `window.location.href` redirect to `WHOP_PLAN_URLS[plan] + "?custom_req=" + orgId`
- [x] Remove any Stripe SDK imports and checkout session API calls from the frontend
- [x] Verify the `orgId` is always appended as `?custom_req=<orgId>` — never omitted

### 3.3 Post-Checkout Verification State

- [x] After redirect back from Whop (detect via URL param or route), show a "Verifying your subscription…" loading state
- [x] Poll `getSubscription(orgId)` every 2 seconds until `status === "active"` or 30 seconds elapse
- [x] On success: show a success toast and update the plan badge
- [x] On timeout: show "Subscription verification timed out. Please refresh the page or contact support."

### 3.4 Billing Dashboard Panel

- [x] Create or update the billing settings page to display:
  - [x] Current plan name and status badge
  - [x] Seat count (current period)
  - [x] Billing cycle
  - [x] Next renewal date (`currentPeriodEnd`)
- [x] Remove any "Manage Billing" link that pointed to the Stripe customer portal
- [x] For paid plans, add a "Manage on Whop" link pointing to the user's Whop membership page

### 3.5 Usage Meters

- [x] Add a "Usage" section to the billing settings page showing:
  - [x] Findings stored: progress bar (`findingsStored / planLimit`)
  - [x] Active projects: progress bar (`projectCount / planLimit`)
  - [x] Scans submitted this period: plain number
- [x] Color the progress bar amber at ≥80% and red at ≥100%
- [x] Fetch data from `getUsageSummary` Convex query

### 3.6 Plan Feature Gate UI

- [x] For features gated behind `pro`/`team`/`enterprise`, show a lock icon and "Upgrade to [Plan]" tooltip when the org is on a lower plan
- [x] Clicking the lock icon triggers the Whop redirect flow (same as the Upgrade button)
- [x] Ensure HTTP 402 responses from the backend surface as a dismissible banner: "You've reached your [findings/project] limit. Upgrade your plan."

---

## Phase 4: Rust CLI LLM BYOK Implementation (Anthropic Native, Ollama Auto-detect)

### 4.1 Provider Registry

- [x] Create `sicario-cli/src/key_manager/provider_registry.rs` with the `ProviderPreset` struct and `PROVIDERS` static slice containing all 19 entries from the design
- [x] Implement `find_provider(name: &str) -> Option<&'static ProviderPreset>` (case-insensitive)
- [x] Add unit test: all 19 provider names resolve correctly; unknown name returns `None`

### 4.2 `sicario config set-provider` Command

- [x] Add `set-provider <name>` subcommand to the `config` command group
- [x] On match: write `llm_endpoint` and `llm_model` to `~/.sicario/config.toml`
- [x] On no match: print error listing all valid provider names, exit code 2
- [x] Add integration test: `set-provider anthropic` writes correct endpoint and model

### 4.3 `sicario config show` Command

- [x] Update `config show` to print a table of all 19 providers (name, endpoint, default model, env var)
- [x] Below the table, print the resolved key source label (e.g. `Active key source: ANTHROPIC_API_KEY env var`) without revealing the key value
- [x] No network request is made during `config show`

### 4.4 Extended Key Manager Resolution Chain

- [x] Refactor `sicario-cli/src/key_manager/mod.rs` to implement the 9-step resolution chain from the design:
  1. `SICARIO_LLM_API_KEY` env var
  2. OS keyring entry
  3. `OPENAI_API_KEY` env var → set endpoint to OpenAI
  4. `ANTHROPIC_API_KEY` env var → set endpoint to Anthropic, flag `auth_style: XApiKey`
  5. `GROQ_API_KEY` env var → set endpoint to Groq
  6. `DEEPSEEK_API_KEY` env var → set endpoint to DeepSeek
  7. `CEREBRAS_API_KEY` env var → set endpoint to Cerebras
  8. `~/.sicario/config.toml` LLM key field
  9. Ollama auto-detection (see 4.6)
- [x] Ensure `SICARIO_API_KEY` is never used in this chain
- [x] Add unit tests for all 9 resolution steps, including precedence ordering

### 4.5 Native Anthropic Client

- [x] Add `AnthropicClient` struct to `sicario-cli/src/remediation/llm_client.rs` implementing the `LlmClient` trait
- [x] Request format: `POST https://api.anthropic.com/v1/messages` with headers `anthropic-version: 2023-06-01` and `x-api-key: <key>`
- [x] Request body: `{ model, max_tokens, system, messages: [{ role: "user", content }] }`
- [x] Response extraction: `response.content[0].text`
- [x] Error extraction: `response.error.message`
- [x] Dispatch in `LlmClient::complete`: if `auth_style == XApiKey`, use `AnthropicClient`; otherwise use existing OpenAI-compatible path
- [x] Add unit tests with mocked HTTP responses for success and error cases

### 4.6 Ollama and LM Studio Auto-Detection

- [x] In the Key_Manager, after step 8 fails, spawn a concurrent detection task:
  - [x] `GET http://localhost:11434/api/tags` with 500ms connect timeout
  - [x] On success: set `endpoint = "http://localhost:11434/v1/chat/completions"`, `model = tags.models[0].name`, `auth_style = None`
  - [x] Print: `"Using local Ollama model: <model_name>. Set ANTHROPIC_API_KEY or OPENAI_API_KEY to use a cloud provider."`
  - [x] On timeout/failure: attempt `GET http://localhost:1234/v1/models` with 500ms timeout (LM Studio)
  - [x] On LM Studio success: set `endpoint = "http://localhost:1234/v1/chat/completions"`, `model = models.data[0].id`
  - [x] On both failures: return the "No LLM API key configured" error with setup instructions
- [x] Ensure detection does not block the scan pipeline; run concurrently with rule loading
- [x] Add integration tests with mock local servers for both Ollama and LM Studio paths

### 4.7 Azure OpenAI Endpoint Construction

- [x] In the Key_Manager, when provider is `azure`, construct the endpoint from `AZURE_OPENAI_RESOURCE` and `AZURE_OPENAI_DEPLOYMENT` env vars (or config file equivalents)
- [x] Endpoint format: `https://<resource>.openai.azure.com/openai/deployments/<deployment>/chat/completions?api-version=2024-02-01`
- [x] Authentication: `api-key: <key>` header (not `Authorization: Bearer`)
- [x] Add unit test for endpoint construction with sample resource/deployment values

### 4.8 `--rules-dir` Flag

- [x] Add `--rules-dir <path>` flag to `sicario scan`
- [x] Load YAML rules from the specified directory and merge with built-in rules
- [x] User-provided rules take precedence on ID conflicts
- [x] If the path does not exist or contains no valid YAML rule files, print a warning and continue with built-in rules only
- [x] Add integration test: custom rule overrides a built-in rule with the same ID

### 4.9 `sicario scan --watch` Mode

- [x] Add `--watch` flag to `sicario scan`
- [x] Use the `notify` crate to watch the target directory for `Create`, `Modify`, `Remove` events
- [x] Debounce events by 100ms to coalesce rapid saves
- [x] On event: re-scan only the affected file; diff findings against previous scan for that file
- [x] Print new findings in standard diagnostic format; print `[resolved]` for disappeared findings
- [x] Update live summary line: `[watch] Critical: 0  High: 2  Medium: 5  Low: 1`
- [x] Respect `.gitignore` and `.sicarioignore` exclusion patterns
- [x] Handle `Ctrl+C` (SIGINT) with clean exit code 0
- [x] Add integration test: modify a file, assert new finding appears within 500ms

---

## Phase 5: Launch Narrative — Sandbox, AI Guardrail, and Zero-Exfiltration Receipt

### 5.1 Vulnerable Sandbox Repository ("Target Practice")

The goal is a public repo that lets any developer test Sicario's sub-50ms speed and zero-exfiltration guarantee without touching their own code. One vulnerable file per AST template, grouped by CWE.

- [x] Create `vuln-sandbox/` directory at the repo root with a `README.md` explaining its purpose: "A deliberately vulnerable monorepo for testing Sicario. Safe to scan. Never deploy."
- [x] Generate one vulnerable Node.js/Express file per supported AST template under `vuln-sandbox/node/cwe-<ID>/` — file names must match the rule ID (e.g. `sql-injection.js`, `path-traversal.js`)
- [x] Generate one vulnerable Python/Django file per supported AST template under `vuln-sandbox/python/cwe-<ID>/` using the same naming convention
- [x] Generate one vulnerable React/TypeScript file per supported AST template under `vuln-sandbox/react/cwe-<ID>/` where applicable (XSS, dangerouslySetInnerHTML, eval, etc.)
- [x] Each file must contain exactly one exploitable pattern that triggers the corresponding Sicario rule — no false positives, no extra noise
- [x] Add a `vuln-sandbox/MANIFEST.md` listing every file, its CWE, rule ID, and expected Sicario severity output — this doubles as a regression test manifest
- [x] Verify `sicario scan vuln-sandbox/` produces exactly one finding per file with the correct rule ID and severity (run as a CI smoke test)
- [x] Add `.sicarioignore` entry to exclude `vuln-sandbox/` from production scans so users who clone the repo don't accidentally publish sandbox findings

### 5.2 AI Fallback Opt-In Guardrail ("Zero Exfiltration by Default")

Sicario must never silently send code to an LLM. When the deterministic AST engine cannot find a template match, execution must halt and require explicit user consent before any LLM call is made.

- [x] In `sicario-cli/src/remediation/mod.rs` (or wherever template lookup occurs), add a `TemplateMatchResult` enum: `Found(Template)` | `NoMatch`
- [x] When `TemplateMatchResult::NoMatch` is returned, print the following to stderr and halt:
  ```
  [sicario] Deterministic engine: no template found for rule '<rule_id>' at <file>:<line>
  [sicario] Opt-in to AI Fallback? This will securely transmit the file context to the LLM. [y/N]:
  ```
- [x] Read a single line from stdin; proceed with LLM fallback only if the user types `y` or `yes` (case-insensitive)
- [x] If the user types anything else (including empty/Enter), print `[sicario] AI Fallback skipped. Run with --allow-ai to suppress this prompt.` and exit with code 0
- [x] Add `--allow-ai` flag to `sicario fix` that pre-approves the LLM fallback without the interactive prompt (for CI use)
- [x] When `--allow-ai` is active, print a one-line notice before the LLM call: `[sicario] --allow-ai: transmitting file context to LLM (consent pre-approved)`
- [x] Ensure the guardrail fires in both interactive (`sicario fix`) and watch mode (`sicario scan --watch` with auto-fix enabled)
- [x] Add unit test: `TemplateMatchResult::NoMatch` without `--allow-ai` returns `AiFallbackDeclined` without making any HTTP request
- [x] Add unit test: `TemplateMatchResult::NoMatch` with `--allow-ai` proceeds to LLM call with the notice printed

### 5.3 Zero-Exfiltration Receipt ("Tokens Burned: 0")

Every successful deterministic patch — in both `sicario fix` and `sicario scan --watch` — must print a receipt that makes the zero-exfiltration guarantee viscerally visible. This is the social-media-ready output that differentiates Sicario from every AI coding tool.

- [x] Define a `PatchReceipt` struct in `sicario-cli/src/remediation/receipt.rs`:
  ```rust
  pub struct PatchReceipt {
      pub rule_id:          String,
      pub file:             String,
      pub line:             u32,
      pub execution_ms:     u128,
      pub tokens_burned:    u32,   // always 0 for deterministic patches
      pub lines_exfiltrated: u32,  // always 0 for deterministic patches
      pub template_used:    String,
  }
  ```
- [x] Implement `PatchReceipt::print()` that renders the following tabular format to stdout:
  ```
  ╔══════════════════════════════════════════════╗
  ║           SICARIO PATCH RECEIPT              ║
  ╠══════════════════════════════════════════════╣
  ║  Rule        sql-injection                   ║
  ║  File        src/db/queries.js:42            ║
  ║  Template    parameterized-query             ║
  ║  Time        3ms                             ║
  ╠══════════════════════════════════════════════╣
  ║  Tokens Burned        0                      ║
  ║  Lines Exfiltrated    0                      ║
  ╚══════════════════════════════════════════════╝
  ```
- [x] Emit `PatchReceipt::print()` after every successful deterministic patch in `sicario fix`
- [x] Emit `PatchReceipt::print()` after every `[resolved]` event in `sicario scan --watch`
- [x] When AI Fallback is used (with `--allow-ai`), set `tokens_burned` to the actual token count from the LLM response (if available in the API response) and `lines_exfiltrated` to the line count of the transmitted context — making the cost of AI visible by contrast
- [x] Add `--no-receipt` flag to suppress the receipt output for users who want clean CI logs
- [x] Add unit test: deterministic patch always produces `tokens_burned: 0` and `lines_exfiltrated: 0`
- [x] Add unit test: receipt renders correctly with a known `PatchReceipt` value (snapshot test)

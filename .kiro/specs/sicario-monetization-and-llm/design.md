# Design Document: sicario-monetization-and-llm

## Overview

This design covers four interconnected areas that form the commercial and technical foundation for Sicario's growth:

1. **Monetization and Billing** — Whop-backed subscription tiers (Free/Pro/Team/Enterprise), per-contributing-developer seat counting computed locally from Git history, plan enforcement at telemetry ingestion, usage tracking, and SOC 2 audit logging.
2. **LLM Provider Expansion** — Native Anthropic Messages API client, a static provider preset registry covering 19 providers, Ollama/LM Studio auto-detection, and an extended 9-level Key_Manager resolution chain.
3. **License Migration** — Replace BSL 1.1 with FSL-1.1-Apache-2.0, add `COMMERCIAL_LICENSE.md` and `CLA.md`, update all references.
4. **Strategic Distribution** — GitHub Marketplace listing for `action.yml`, `sicario-rules` Apache 2.0 community library with `--rules-dir` CLI support, and `sicario scan --watch` continuous mode.

### Architectural Invariants

All four areas are constrained by Sicario's zero-exfiltration, zero-liability architecture:

- **Zero-Exfiltration**: The cloud backend never receives source code. Code snippets are capped at 500 characters server-side. LLM API keys never leave the developer's machine.
- **Zero-Liability**: The cloud never stores LLM API keys. `SICARIO_API_KEY` is strictly for authenticating HTTP requests to the Convex telemetry endpoint — never for LLM calls.
- **Read-Only Dashboard**: The dashboard never initiates scans and never pushes code. The only actionable output is a `sicario fix --id=<ID>` copy-paste command.
- **BYOK Always**: All LLM provider selection and key management is local-only. The cloud has no visibility into which LLM provider a user has configured.
- **Whop as MoR**: Sicario never handles raw payment data. Checkout, tax compliance, and global payment routing are fully delegated to Whop. The backend only reacts to Whop webhook events.

---

## Area 1: Monetization and Billing

### 1.1 Subscription Tier Model

Four plans are supported: `free`, `pro`, `team`, and `enterprise`. Limits are enforced at telemetry ingestion time by the Plan_Enforcer, not at query time, to keep the read path fast.

| Plan       | Projects | Findings | Retention | Seats    |
|------------|----------|----------|-----------|----------|
| free       | 1        | 500      | 30 days   | —        |
| pro        | 10       | 5,000    | 90 days   | counted  |
| team       | unlimited| unlimited| 365 days  | counted  |
| enterprise | contract | contract | contract  | contract |

A `past_due` subscription is treated as `free` for enforcement purposes. This is checked on every telemetry ingestion request using the `subscriptions` table index on `orgId`.

### 1.2 Whop Checkout Flow

Whop acts as the Merchant of Record. Sicario's frontend never creates payment sessions or handles card data. The flow is:

```
User clicks "Upgrade"
  → Dashboard redirects to https://whop.com/checkout/plan_XXXX?custom_req=<orgId>
  → User completes checkout on Whop's hosted page
  → Whop fires membership.went_valid webhook to /whop-webhook
  → Billing_Service verifies x-whop-signature, extracts orgId from metadata.custom_req
  → subscriptions table updated: status="active", plan=<tier>
  → Dashboard polls subscription status until active (max 30s)
```

Plan URL constants are stored in a single config file in the Convex deployment. Changing a plan's Whop product URL requires editing only that file.

**Webhook endpoint contract:**

```
POST /whop-webhook
Headers: x-whop-signature: <hmac-sha256>
Body: WhopWebhookEvent
```

Supported events:

| Event                  | Action                                                    |
|------------------------|-----------------------------------------------------------|
| `membership.went_valid`  | Set `status: "active"`, update plan from product ID map |
| `membership.went_invalid`| Set `status: "canceled"`, downgrade plan to `"free"`    |

The endpoint must respond HTTP 200 within 5 seconds. If `custom_req` is missing or maps to no known `orgId`, return HTTP 400 and write to the audit log for manual review.

**Product ID → Plan mapping** is a static lookup table in the Billing_Service:

```typescript
const WHOP_PRODUCT_PLAN_MAP: Record<string, Plan> = {
  "plan_XXXX_pro":        "pro",
  "plan_XXXX_team":       "team",
  "plan_XXXX_enterprise": "enterprise",
};
```

### 1.3 Per-Contributing-Developer Seat Counting

Seat counting is computed entirely on the developer's machine. The CLI runs:

```
git log --since="90 days ago" --format="%ae" | sort -u | wc -l
```

The resulting integer is included in the telemetry payload as `contributorCount`. The Billing_Service takes `MAX(current seatCount, submitted contributorCount)` within the billing period. At period rollover, `seatCount` resets to zero. No author names, emails, or commit messages are transmitted.

If the CLI is run outside a Git repository, `contributorCount` defaults to `1`.

### 1.4 Plan Enforcement at Telemetry Ingestion

The Plan_Enforcer runs inside the `/api/v1/telemetry/scan` HTTP action, before the scan is persisted. Checks are performed in this order:

1. Resolve `orgId` from the authenticated identity.
2. Fetch the `subscriptions` record by `orgId` index.
3. If `status` is `past_due`, treat as `free` for limit resolution.
4. Count current `findingsStored` from `usageSummary`.
5. If `findingsStored + incomingCount > planLimit`, return HTTP 402.
6. Count current `projectCount`. If this is a new project and `projectCount >= planLimit`, return HTTP 402.

HTTP 402 response body:
```json
{ "error": "Finding storage limit reached. Upgrade your plan at usesicario.xyz/pricing" }
```

The CLI treats HTTP 402 as a non-fatal warning (exit code 0) and displays the message to the user.

### 1.5 Usage Tracking

The `usageSummary` table holds one record per `(orgId, periodStart)`. On each accepted telemetry payload:

- `scansSubmitted` is incremented by 1.
- `findingsStored` is updated to the current total findings count for the org.
- `projectCount` is updated to the current active project count.

When `findingsStored` crosses 80% of the plan limit, the Billing_Service fires a warning to the org's configured webhook URL (if set). Records are retained for at least 12 billing periods.

### 1.6 Convex Schema

#### `subscriptions` table

```typescript
subscriptions: defineTable({
  orgId:               v.string(),
  plan:                v.union(v.literal("free"), v.literal("pro"), v.literal("team"), v.literal("enterprise")),
  status:              v.union(v.literal("active"), v.literal("trialing"), v.literal("past_due"), v.literal("canceled"), v.literal("paused")),
  billingCycle:        v.union(v.literal("monthly"), v.literal("annual"), v.literal("manual")),
  seatCount:           v.number(),
  currentPeriodStart:  v.string(),   // ISO-8601
  currentPeriodEnd:    v.string(),   // ISO-8601
  whopUserId:          v.optional(v.string()),
  whopSubscriptionId:  v.optional(v.string()),
  trialEndsAt:         v.optional(v.string()),
  customRetentionDays: v.optional(v.number()),
  csmIdentifier:       v.optional(v.string()),
  contractStartDate:   v.optional(v.string()),
}).index("by_orgId", ["orgId"]),
```

#### `usageSummary` table

```typescript
usageSummary: defineTable({
  orgId:           v.string(),
  periodStart:     v.string(),   // ISO-8601
  periodEnd:       v.string(),   // ISO-8601
  findingsStored:  v.number(),
  projectCount:    v.number(),
  scansSubmitted:  v.number(),
}).index("by_orgId_periodStart", ["orgId", "periodStart"]),
```

#### `auditLog` table

```typescript
auditLog: defineTable({
  orgId:      v.string(),
  userId:     v.optional(v.string()),
  eventType:  v.string(),   // e.g. "subscription.upgraded", "plan_enforcer.rejected"
  payload:    v.any(),      // structured JSON, no PII
  timestamp:  v.string(),   // ISO-8601
}).index("by_orgId_timestamp", ["orgId", "timestamp"]),
```

Audit log entries are append-only. No `update` or `delete` mutations are exposed on this table.

When an organization is created, the Billing_Service automatically inserts a `subscriptions` record with `plan: "free"`, `status: "active"`, `billingCycle: "manual"`, `seatCount: 0`.

### 1.7 SOC 2 Audit Logging

Every subscription state transition writes an `auditLog` entry with:
- `eventType`: e.g. `"subscription.upgraded"`, `"subscription.canceled"`
- `payload`: `{ previousPlan, newPlan, triggerSource: "whop_webhook" | "admin", whopEventId? }`
- `timestamp`: ISO-8601

Every Plan_Enforcer rejection writes an `auditLog` entry with:
- `eventType`: `"plan_enforcer.rejected"`
- `payload`: `{ endpoint, rejectionReason, limitExceeded, currentValue, planLimit }`

Every Dashboard admin action (project deletion, API key rotation, SSO config change) writes an `auditLog` entry with:
- `eventType`: e.g. `"admin.project_deleted"`, `"admin.sso_configured"`
- `payload`: `{ userId, action, targetId? }`

Enterprise compliance exports generate a JSON array of all `auditLog` entries for the org within the requested date range, served as a file download from the Dashboard.

---

## Area 2: LLM Provider Expansion

### 2.1 Provider Dispatch Architecture

The LLM_Client uses a two-path dispatch model:

```
LLM_Client::complete(prompt)
  ├── if provider == "anthropic"  → AnthropicClient (native Messages API)
  └── else                        → OpenAICompatibleClient (Bearer + /chat/completions)
```

The active provider is resolved by the Key_Manager before the request is made. The LLM_Client receives a resolved `LlmConfig { endpoint, model, api_key, auth_style }` struct and does not perform provider detection itself.

### 2.2 Native Anthropic Client

The Anthropic Messages API differs from OpenAI in three ways: endpoint path, authentication header, and request/response shape.

**Request:**
```
POST https://api.anthropic.com/v1/messages
Headers:
  anthropic-version: 2023-06-01
  x-api-key: <ANTHROPIC_API_KEY>
  content-type: application/json

Body:
{
  "model": "<model>",
  "max_tokens": <n>,
  "system": "<system_prompt>",
  "messages": [{ "role": "user", "content": "<user_prompt>" }]
}
```

**Response extraction:** `response.content[0].text`

**Error extraction:** `response.error.message`

The `AnthropicClient` is a new struct in `sicario-cli/src/remediation/llm_client.rs` that implements the same `LlmClient` trait as the existing OpenAI-compatible client.

### 2.3 Provider Registry

The `Provider_Registry` is a static `&[ProviderPreset]` defined at compile time in `sicario-cli/src/key_manager/provider_registry.rs`. Each entry:

```rust
pub struct ProviderPreset {
    pub name:          &'static str,   // canonical lowercase name
    pub endpoint:      &'static str,   // base URL
    pub default_model: &'static str,
    pub env_var:       &'static str,   // primary API key env var
    pub auth_style:    AuthStyle,      // Bearer | XApiKey | None (Ollama)
}
```

Full registry (19 providers):

| Name        | Endpoint                                                        | Default Model              | Env Var                  |
|-------------|-----------------------------------------------------------------|----------------------------|--------------------------|
| openai      | `https://api.openai.com/v1`                                     | gpt-4o                     | OPENAI_API_KEY           |
| anthropic   | `https://api.anthropic.com/v1`                                  | claude-opus-4-5            | ANTHROPIC_API_KEY        |
| gemini      | `https://generativelanguage.googleapis.com/v1beta/openai/`      | gemini-2.5-pro             | GEMINI_API_KEY           |
| azure       | `https://<resource>.openai.azure.com/openai/deployments/<dep>/` | gpt-4o                     | AZURE_OPENAI_API_KEY     |
| bedrock     | `https://bedrock-runtime.<region>.amazonaws.com`                | anthropic.claude-3-5-sonnet| AWS_ACCESS_KEY_ID        |
| deepseek    | `https://api.deepseek.com/v1`                                   | deepseek-chat              | DEEPSEEK_API_KEY         |
| groq        | `https://api.groq.com/openai/v1`                                | llama-3.3-70b-versatile    | GROQ_API_KEY             |
| cerebras    | `https://api.cerebras.ai/v1`                                    | llama3.1-70b               | CEREBRAS_API_KEY         |
| together    | `https://api.together.xyz/v1`                                   | meta-llama/Llama-3-70b     | TOGETHER_API_KEY         |
| fireworks   | `https://api.fireworks.ai/inference/v1`                         | accounts/fireworks/models/llama-v3p1-70b-instruct | FIREWORKS_API_KEY |
| openrouter  | `https://openrouter.ai/api/v1`                                  | openai/gpt-4o              | OPENROUTER_API_KEY       |
| mistral     | `https://api.mistral.ai/v1`                                     | mistral-large-latest       | MISTRAL_API_KEY          |
| ollama      | `http://localhost:11434/v1`                                     | (auto-detected)            | (none)                   |
| lmstudio    | `http://localhost:1234/v1`                                      | (auto-detected)            | (none)                   |
| xai         | `https://api.x.ai/v1`                                           | grok-3                     | XAI_API_KEY              |
| perplexity  | `https://api.perplexity.ai`                                     | llama-3.1-sonar-large-128k-online | PERPLEXITY_API_KEY |
| cohere      | `https://api.cohere.ai/compatibility/v1`                        | command-r-plus             | COHERE_API_KEY           |
| deepinfra   | `https://api.deepinfra.com/v1/openai`                           | meta-llama/Meta-Llama-3.1-70B-Instruct | DEEPINFRA_API_KEY |
| novita      | `https://api.novita.ai/v3/openai`                               | meta-llama/llama-3.1-70b-instruct | NOVITA_API_KEY   |

`sicario config set-provider <name>` writes `endpoint` and `default_model` to `~/.sicario/config.toml`. If the name is not found, exit code 2 with a list of valid names.

`sicario config show` prints a table of all 19 providers with endpoint, default model, and env var. No network request is made.

### 2.4 Key Manager Resolution Chain

The Key_Manager resolves credentials in this priority order, stopping at the first match:

| Priority | Source                          | Notes                                              |
|----------|---------------------------------|----------------------------------------------------|
| 1        | `SICARIO_LLM_API_KEY` env var   | Explicit override, any provider                    |
| 2        | OS keyring (`sicario config set-key`) | Persisted across sessions                   |
| 3        | `OPENAI_API_KEY` env var        | Sets endpoint to OpenAI if no override             |
| 4        | `ANTHROPIC_API_KEY` env var     | Sets endpoint to Anthropic, switches to native client |
| 5        | `GROQ_API_KEY` env var          | Sets endpoint to Groq                              |
| 6        | `DEEPSEEK_API_KEY` env var      | Sets endpoint to DeepSeek                          |
| 7        | `CEREBRAS_API_KEY` env var      | Sets endpoint to Cerebras                          |
| 8        | `~/.sicario/config.toml` LLM key field | Persisted provider config                   |
| 9        | Ollama auto-detection           | `GET localhost:11434/api/tags`, 500ms timeout      |

`SICARIO_API_KEY` is never consulted for LLM authentication. It is used exclusively for `Authorization: Bearer` on Convex HTTP endpoints.

`sicario config show` displays the resolved key source label (e.g. `"ANTHROPIC_API_KEY env var"`) without revealing the key value.

### 2.5 Ollama and LM Studio Auto-Detection

When no key is found from sources 1–8, the Key_Manager attempts:

1. `GET http://localhost:11434/api/tags` with a 500ms connect timeout.
   - On success: set endpoint to `http://localhost:11434/v1/chat/completions`, model to `tags.models[0].name`.
   - Display: `"Using local Ollama model: <model_name>. Set ANTHROPIC_API_KEY or OPENAI_API_KEY to use a cloud provider."`
2. If Ollama times out or refuses connection, attempt `GET http://localhost:1234/v1/models` with a 500ms timeout (LM Studio).
   - On success: set endpoint to `http://localhost:1234/v1/chat/completions`, model to `models.data[0].id`.
3. If both fail: display the existing "No LLM API key configured" error with setup instructions for both cloud and local options.

The detection check must not block the scan. It runs concurrently with rule loading and times out independently.

### 2.6 Azure OpenAI Endpoint Construction

Azure requires a deployment-scoped URL. The LLM_Client constructs it as:

```
https://<AZURE_OPENAI_RESOURCE>.openai.azure.com/openai/deployments/<AZURE_OPENAI_DEPLOYMENT>/chat/completions?api-version=2024-02-01
```

`AZURE_OPENAI_RESOURCE` and `AZURE_OPENAI_DEPLOYMENT` are read from environment variables or `~/.sicario/config.toml`. Authentication uses `api-key: <key>` header (not `Authorization: Bearer`).

---

## Area 3: License Migration

### 3.1 FSL-1.1-Apache-2.0

The `LICENSE` file is replaced with FSL-1.1 specifying:
- **Licensor**: Emmanuel Enyi
- **Licensed Work**: Sicario CLI and Template Registry
- **Change License**: Apache License 2.0
- **Change Date**: Two years from the first public release of each version

The non-compete clause prohibits running Sicario as a hosted security scanning service for third parties without a commercial agreement. Permitted uses (no agreement required): individual local use, internal CI/CD, open-source projects, non-profits.

### 3.2 Supporting Documents

`COMMERCIAL_LICENSE.md` covers:
- Enterprise licensing path and pricing model reference
- Contact information for licensing inquiries
- FSL-1.1 rationale section (simpler non-compete than BSL, 2-year Apache 2.0 conversion, Fair Source alignment)
- **Trademark Policy** section: "Sicario" and the logo are trademarks of the licensor. Factual descriptions ("powered by Sicario") are permitted. Use in product names, company names, domain names, or logo reproduction requires written permission.

`CLA.md` grants the licensor a perpetual, irrevocable, worldwide, royalty-free license to use, modify, sublicense, and relicense contributions under any license. Contributors retain copyright.

`CONTRIBUTING.md` is updated to:
- Add a "Contributor License Agreement" section with a link to `CLA.md` or the CLA signing service.
- Replace any "MIT License" references with FSL-1.1 and CLA language.
- Add a section on contributing rules to the `sicario-rules` repository.

All `README.md`, `Cargo.toml`, badge URLs, and inline comments referencing "BSL 1.1" are updated to "FSL-1.1".

---

## Area 4: Strategic Distribution

### 4.1 GitHub Marketplace Action

`action.yml` additions:

```yaml
description: "Zero-exfiltration SAST scanner for CI pipelines — finds vulns, generates AI fixes locally"  # ≤125 chars
branding:
  icon: shield
  color: red
inputs:
  args:
    description: "Arguments passed to sicario scan"
    default: "."
  version:
    description: "CLI version to install"
    default: "latest"
  fail-on:
    description: "Minimum severity that causes exit code 1"
    default: "High"
```

The action installs the specified binary version and runs `sicario <args>`. The `README.md` gains a "GitHub Marketplace" section with input/output documentation and an example workflow.

### 4.2 Sicario Rules Community Library

`sicario-rules` is a separate repository under Apache 2.0 containing only YAML rule files and test fixtures — no Rust source. The CLI gains a `--rules-dir <path>` flag that merges rules from the specified directory with built-in rules. User-provided rules take precedence on ID conflicts.

### 4.3 Continuous Watch Mode

`sicario scan --watch` uses the platform file-watcher (via the `notify` crate on Linux/macOS/Windows) to monitor the target directory. On any `Create`, `Modify`, or `Remove` event:

1. Debounce for 100ms to coalesce rapid saves.
2. Re-scan only the affected file.
3. Diff the finding set against the previous scan for that file.
4. Print new findings immediately in the standard diagnostic format.
5. Print `[resolved] <rule_id> at <file>:<line>` for findings that disappeared.
6. Update the live summary line: `[watch] Critical: 0  High: 2  Medium: 5  Low: 1`.

The re-scan must complete within 500ms of the file change event for typical file sizes. `.gitignore` and `.sicarioignore` patterns are respected. `Ctrl+C` exits cleanly with code 0.

---

## Cross-Cutting Concerns

### Serialization Correctness

All subscription records and telemetry payloads must survive JSON round-trips without data loss. The Billing_Service validates that all required `subscriptions` fields are present before persisting, returning a descriptive error identifying missing fields.

The `contributorCount` field in the telemetry payload is a plain integer. The Billing_Service rejects any payload containing fields named `llmApiKey`, `openaiKey`, `anthropicKey`, or any variant thereof.

### Zero-Exfiltration Billing Constraint

- The Billing_Service never stores, logs, or transmits LLM API keys.
- The `contributorCount` is a single integer — no author names, emails, or commit messages.
- The Dashboard displays contributor count as a number only, with no ability to enumerate individual identities.
- `SICARIO_API_KEY` documentation explicitly states it is for telemetry authentication only.

### Plan Feature Gates Summary

| Feature                          | free | pro | team | enterprise |
|----------------------------------|------|-----|------|------------|
| Local CLI scans (unlimited)      | ✓    | ✓   | ✓    | ✓          |
| Cloud telemetry publishing       | ✓    | ✓   | ✓    | ✓          |
| PR check integration             | ✗    | ✓   | ✓    | ✓          |
| Slack / Teams webhooks           | ✗    | ✓   | ✓    | ✓          |
| SARIF / OWASP exports            | ✗    | ✓   | ✓    | ✓          |
| Team management                  | ✗    | ✗   | ✓    | ✓          |
| Custom YAML rule uploads         | ✗    | ✗   | ✓    | ✓          |
| Baseline management              | ✗    | ✗   | ✓    | ✓          |
| Execution audit trail            | ✗    | ✗   | ✓    | ✓          |
| SSO (SAML 2.0 / OIDC)           | ✗    | ✗   | ✗    | ✓          |
| Compliance exports               | ✗    | ✗   | ✗    | ✓          |
| Custom retention periods         | ✗    | ✗   | ✗    | ✓          |
| Manual enterprise provisioning   | ✗    | ✗   | ✗    | ✓          |

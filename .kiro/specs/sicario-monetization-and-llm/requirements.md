# Requirements Document

## Introduction

This document covers four interconnected areas that together form the commercial and technical foundation for Sicario's growth: subscription monetization with Whop-backed billing, expanded LLM provider support under a strict Bring-Your-Own-Key (BYOK) model, license migration from BSL 1.1 to FSL-1.1-Apache-2.0, and strategic distribution improvements.

The overarching constraint across all four areas is Sicario's zero-exfiltration, zero-liability architecture: the cloud backend never receives source code, never stores LLM API keys, and never initiates scans. All analysis and LLM authentication happen locally on the developer's machine or CI runner. The cloud dashboard is a read-only telemetry monitor.

Billing is per-contributing-developer — defined as any Git author who committed to a scanned repository within the last 90 days. This aligns cost with actual usage and is verifiable locally without sending code to the cloud.

---

## Glossary

- **Billing_Service**: The Convex backend module responsible for subscription lifecycle, seat counting, and Whop webhook processing
- **CLI**: The Sicario command-line tool (`sicario-cli` Rust crate)
- **Contributing_Developer**: Any Git author with at least one commit to a scanned repository within the trailing 90-day window, as computed locally by the CLI
- **Dashboard**: The read-only Sicario web application at `usesicario.xyz`, backed by Convex
- **Key_Manager**: The existing `sicario-cli/src/key_manager/` module responsible for resolving LLM API keys from environment variables, OS keyring, and config files
- **LLM_Client**: The existing `sicario-cli/src/remediation/llm_client.rs` module that sends chat completion requests to LLM providers
- **Ollama**: A local LLM runtime that exposes an OpenAI-compatible API on `localhost:11434`
- **Plan_Enforcer**: The Convex backend module that validates whether an organization's current action is permitted under its active subscription plan
- **Provider_Registry**: The new CLI module that stores the canonical list of supported LLM providers with their endpoints, default models, and authentication requirements
- **SICARIO_API_KEY**: The project-scoped API key used exclusively to authenticate CLI-to-Convex telemetry HTTP requests; never used for LLM authentication
- **Subscription**: An organization's active billing plan (Free, Pro, Team, or Enterprise) stored in the `subscriptions` Convex table
- **Usage_Summary**: A per-organization, per-billing-period record of findings stored, projects active, and scans submitted, stored in the `usageSummary` Convex table
- **Whop**: The Merchant of Record handling checkout, tax compliance, and global payment routing. Whop owns the checkout UI and payment processing; Sicario's backend only listens for Whop webhook events to update subscription state.

---

## Requirements

### Requirement 1: Subscription Tier Definitions

**User Story:** As a product owner, I want clearly defined subscription tiers with enforced limits, so that Sicario can generate revenue while remaining free for individual developers.

#### Acceptance Criteria

1. THE Billing_Service SHALL support exactly four subscription plans: `free`, `pro`, `team`, and `enterprise`
2. WHILE a subscription is on the `free` plan, THE Plan_Enforcer SHALL permit at most 1 active project per organization
3. WHILE a subscription is on the `free` plan, THE Plan_Enforcer SHALL permit at most 500 findings stored per organization
4. WHILE a subscription is on the `free` plan, THE Plan_Enforcer SHALL enforce a 30-day finding retention window, after which findings are automatically purged
5. WHILE a subscription is on the `pro` plan, THE Plan_Enforcer SHALL permit at most 10 active projects per organization
6. WHILE a subscription is on the `pro` plan, THE Plan_Enforcer SHALL permit at most 5,000 findings stored per organization
7. WHILE a subscription is on the `pro` plan, THE Plan_Enforcer SHALL enforce a 90-day finding retention window
8. WHILE a subscription is on the `team` plan, THE Plan_Enforcer SHALL permit unlimited active projects per organization
9. WHILE a subscription is on the `team` plan, THE Plan_Enforcer SHALL enforce a 365-day finding retention window
10. WHILE a subscription is on the `enterprise` plan, THE Plan_Enforcer SHALL apply retention and project limits as specified in the organization's custom contract, defaulting to unlimited if no contract value is set
11. THE Billing_Service SHALL store the plan name, status, billing cycle, seat count, current period start and end, Whop user ID, Whop subscription ID, and trial end date for each organization's subscription

### Requirement 2: Per-Contributing-Developer Seat Counting

**User Story:** As a billing administrator, I want seat counts based on active contributors rather than registered users, so that organizations pay only for developers who actually use the tool.

#### Acceptance Criteria

1. WHEN the CLI submits a telemetry payload, THE CLI SHALL compute the Contributing_Developer count by inspecting the local Git log for unique author email addresses with at least one commit in the trailing 90-day window
2. THE CLI SHALL include the Contributing_Developer count as a field in the telemetry payload submitted to `POST /api/v1/telemetry/scan`
3. WHEN the Billing_Service receives a telemetry payload, THE Billing_Service SHALL update the `seatCount` field on the organization's subscription to the maximum of the current stored value and the submitted contributor count within the current billing period
4. THE CLI SHALL compute the Contributing_Developer count using only local Git history and SHALL NOT transmit any author names, email addresses, or commit messages to the cloud
5. WHEN a billing period ends, THE Billing_Service SHALL reset the `seatCount` to zero at the start of the new period so the next period's count reflects only recent contributors
6. IF the CLI is run outside a Git repository, THEN THE CLI SHALL submit a contributor count of 1 as a conservative default

### Requirement 3: Whop Checkout & Webhook Integration

**User Story:** As a developer, I want to upgrade my plan through a frictionless checkout flow, so that I can unlock Pro or Team features without contacting sales.

#### Acceptance Criteria

**Frontend**

1. WHEN an organization administrator clicks an "Upgrade" button on the Dashboard, THE Dashboard SHALL redirect the browser to the corresponding Whop product URL (e.g., `https://whop.com/checkout/plan_XXXX`) appending `?custom_req=<orgId>` as a query parameter so Whop can associate the purchase with the correct organization
2. THE Dashboard SHALL NOT create checkout sessions, payment intents, or any other payment objects directly; all checkout UI is owned by Whop
3. THE Dashboard SHALL define one Whop product URL constant per paid plan (`pro`, `team`, `enterprise`) in a single configuration file; changing a plan's Whop URL SHALL require editing only that file
4. WHEN a user returns from the Whop checkout flow to the Dashboard, THE Dashboard SHALL display a "Verifying your subscription…" state and poll the organization's subscription status until it transitions to `active` or a 30-second timeout elapses
5. THE Dashboard SHALL display the current plan name, seat count, billing cycle, and next renewal date to organization administrators

**Backend**

6. THE Billing_Service SHALL expose an HTTP endpoint at `/whop-webhook` that accepts `POST` requests from Whop
7. WHEN the `/whop-webhook` endpoint receives a `membership.went_valid` event, THE Billing_Service SHALL extract the `orgId` from the `metadata.custom_req` field of the webhook payload and activate the corresponding subscription by setting `status: "active"` and updating the plan to the tier associated with the Whop product ID in the payload
8. WHEN the `/whop-webhook` endpoint receives a `membership.went_invalid` event, THE Billing_Service SHALL extract the `orgId` from `metadata.custom_req` and downgrade the organization to the `free` plan with `status: "canceled"`
9. THE Billing_Service SHALL validate all incoming Whop webhook payloads by verifying the `x-whop-signature` header using the Whop webhook signing secret before processing any event
10. IF the `custom_req` field is absent or does not correspond to a known `orgId`, THE Billing_Service SHALL return HTTP 400 and log the malformed event for manual review
11. THE Billing_Service SHALL respond to all valid Whop webhook deliveries with HTTP 200 within 5 seconds to prevent Whop from retrying the delivery

### Requirement 4: Plan Enforcement at Telemetry Ingestion

**User Story:** As a platform operator, I want plan limits enforced at the point of data ingestion, so that organizations cannot exceed their tier's storage limits by submitting more scans.

#### Acceptance Criteria

1. WHEN the telemetry endpoint receives a scan payload, THE Plan_Enforcer SHALL check whether accepting the findings would exceed the organization's plan limit for stored findings
2. IF accepting a payload would cause the organization's stored finding count to exceed the plan limit, THEN THE Plan_Enforcer SHALL reject the payload with HTTP 402 and a response body of `{"error": "Finding storage limit reached. Upgrade your plan at usesicario.xyz/pricing"}`
3. WHEN the telemetry endpoint receives a scan payload for a new project, THE Plan_Enforcer SHALL check whether the organization has reached its plan limit for active projects
4. IF a new project would exceed the organization's plan limit for active projects, THEN THE Plan_Enforcer SHALL reject the payload with HTTP 402 and a response body of `{"error": "Project limit reached. Upgrade your plan at usesicario.xyz/pricing"}`
5. THE Plan_Enforcer SHALL apply limits based on the organization's subscription status at the time of the request; a `past_due` subscription SHALL be treated as `free` for enforcement purposes
6. THE CLI SHALL display the HTTP 402 error message to the user and SHALL NOT treat a 402 response as a scan failure for exit code purposes

### Requirement 5: Usage Tracking

**User Story:** As a billing administrator, I want to see how much of my plan quota I have consumed, so that I can plan upgrades before hitting limits.

#### Acceptance Criteria

1. THE Billing_Service SHALL maintain a `usageSummary` record per organization per billing period tracking: findings stored, active project count, and scans submitted
2. WHEN a telemetry payload is accepted, THE Billing_Service SHALL increment the `scansSubmitted` counter and update `findingsStored` and `projectCount` in the current period's `usageSummary`
3. THE Dashboard SHALL display current-period usage as a progress bar showing consumed vs. plan limit for findings stored and active projects
4. WHEN an organization's `findingsStored` reaches 80% of the plan limit, THE Billing_Service SHALL send a warning notification via the organization's configured webhook
5. THE Billing_Service SHALL retain `usageSummary` records for at least 12 billing periods to support historical usage reporting

### Requirement 6: Free Tier Restrictions

**User Story:** As a product owner, I want the free tier to be genuinely useful for individuals while creating clear upgrade incentives for teams, so that the product drives organic conversion.

#### Acceptance Criteria

1. WHILE a subscription is on the `free` plan, THE Plan_Enforcer SHALL permit unlimited local CLI scans without authentication
2. WHILE a subscription is on the `free` plan, THE Plan_Enforcer SHALL not permit SSO configuration
3. WHILE a subscription is on the `free` plan, THE Plan_Enforcer SHALL not permit webhook configuration
4. WHILE a subscription is on the `free` plan, THE Plan_Enforcer SHALL not permit team management (inviting members, assigning roles)
5. THE CLI SHALL function fully for local scanning, AI remediation, and report generation regardless of subscription plan or authentication state
6. WHEN an unauthenticated user runs `sicario scan . --publish`, THE CLI SHALL display a message explaining that publishing requires a free account and SHALL provide the signup URL

### Requirement 7: Enterprise Plan Features

**User Story:** As an enterprise security team, I want SSO, compliance exports, and a dedicated support channel, so that Sicario meets our procurement and compliance requirements.

#### Acceptance Criteria

1. WHILE a subscription is on the `enterprise` plan, THE Plan_Enforcer SHALL permit SSO configuration using SAML 2.0 or OIDC
2. WHILE a subscription is on the `enterprise` plan, THE Plan_Enforcer SHALL permit compliance data exports in SARIF and OWASP report formats via the Dashboard
3. WHILE a subscription is on the `enterprise` plan, THE Plan_Enforcer SHALL permit custom retention periods as specified in the organization's contract
4. THE Billing_Service SHALL support `enterprise` plan activation via manual provisioning by a Sicario administrator, bypassing the Whop checkout flow
5. WHEN an enterprise organization's subscription is provisioned, THE Billing_Service SHALL record the contract start date, custom retention days, and dedicated CSM identifier in the subscription record

### Requirement 8: Native Anthropic LLM Client

**User Story:** As a developer, I want to use Claude models for AI remediation without a proxy, so that I get the best possible fix quality from Anthropic's native API.

#### Acceptance Criteria

1. THE LLM_Client SHALL implement a native Anthropic client that sends requests to `https://api.anthropic.com/v1/messages` using the Anthropic Messages API format
2. WHEN the configured provider is Anthropic, THE LLM_Client SHALL include the `anthropic-version: 2023-06-01` header and the `x-api-key` header (not `Authorization: Bearer`) in all requests
3. WHEN the configured provider is Anthropic, THE LLM_Client SHALL serialize the request body as `{"model": "<model>", "max_tokens": <n>, "system": "<system_prompt>", "messages": [{"role": "user", "content": "<user_prompt>"}]}`
4. WHEN the configured provider is Anthropic, THE LLM_Client SHALL extract the generated text from `response.content[0].text` in the Anthropic response format
5. IF the Anthropic API returns an error response, THEN THE LLM_Client SHALL extract the error message from `response.error.message` and surface it to the user
6. THE Key_Manager SHALL resolve the Anthropic API key from the `ANTHROPIC_API_KEY` environment variable before falling back to the OS keyring and config file

### Requirement 9: LLM Provider Preset System

**User Story:** As a developer, I want to switch LLM providers with a single command, so that I can use the cheapest or fastest model for my current task without manually setting environment variables.

#### Acceptance Criteria

1. THE CLI SHALL implement a `sicario config set-provider <name>` command that writes the provider's canonical endpoint URL and default model to `~/.sicario/config.toml`
2. WHEN `sicario config set-provider <name>` is executed, THE Provider_Registry SHALL look up the provider by name (case-insensitive) and write its `endpoint` and `default_model` fields to the config file
3. IF the provider name is not found in the Provider_Registry, THEN THE CLI SHALL display an error listing all valid provider names and exit with code 2
4. THE Provider_Registry SHALL contain entries for the following providers: `openai`, `anthropic`, `gemini`, `azure`, `bedrock`, `deepseek`, `groq`, `cerebras`, `together`, `fireworks`, `openrouter`, `mistral`, `ollama`, `lmstudio`, `xai`, `perplexity`, `cohere`, `deepinfra`, `novita`
5. WHEN `sicario config show` is executed, THE CLI SHALL display a table listing all providers in the Provider_Registry with their endpoint URL, default model, and required environment variable name
6. THE Provider_Registry SHALL be defined as a static data structure in the CLI source code and SHALL NOT require a network request to populate

### Requirement 10: Ollama and Local Model Auto-Detection

**User Story:** As a developer running air-gapped or cost-sensitive workloads, I want the CLI to automatically use a local Ollama instance when no cloud API key is configured, so that AI remediation works without any setup.

#### Acceptance Criteria

1. WHEN the Key_Manager resolves the LLM configuration and finds no API key from any source, THE Key_Manager SHALL attempt to connect to `http://localhost:11434` to check for a running Ollama instance
2. WHEN an Ollama instance is detected at `localhost:11434`, THE Key_Manager SHALL set the LLM endpoint to `http://localhost:11434/v1/chat/completions` and the model to the first available model returned by `GET http://localhost:11434/api/tags`
3. IF no Ollama instance is detected and no API key is configured, THEN THE LLM_Client SHALL display the existing "No LLM API key configured" error message with instructions for both cloud providers and local Ollama setup
4. THE Ollama detection check SHALL complete within 500 milliseconds and SHALL NOT block the scan if the connection attempt times out
5. WHEN Ollama auto-detection is used, THE CLI SHALL display a notice: "Using local Ollama model: <model_name>. Set ANTHROPIC_API_KEY or OPENAI_API_KEY to use a cloud provider."
6. THE LM Studio local runtime at `localhost:1234/v1` SHALL be treated as a secondary fallback after Ollama, using the same auto-detection mechanism

### Requirement 11: Extended Key Manager Resolution Order

**User Story:** As a developer, I want the CLI to automatically pick up my provider-specific API key environment variables, so that I don't need to rename them to `SICARIO_LLM_API_KEY`.

#### Acceptance Criteria

1. THE Key_Manager SHALL resolve the LLM API key using the following priority order, stopping at the first match: (1) `SICARIO_LLM_API_KEY` env var, (2) OS keyring entry set via `sicario config set-key`, (3) `OPENAI_API_KEY` env var, (4) `ANTHROPIC_API_KEY` env var, (5) `GROQ_API_KEY` env var, (6) `DEEPSEEK_API_KEY` env var, (7) `CEREBRAS_API_KEY` env var, (8) `~/.sicario/config.toml` LLM key field, (9) Ollama auto-detection
2. WHEN the Key_Manager resolves a key from a provider-specific environment variable (steps 3–7), THE Key_Manager SHALL also set the LLM endpoint to that provider's canonical endpoint if no explicit endpoint override is configured
3. THE Key_Manager SHALL never use `SICARIO_API_KEY` for LLM authentication; `SICARIO_API_KEY` is reserved exclusively for authenticating HTTP requests to the Convex telemetry endpoint
4. WHEN `sicario config show` is executed, THE CLI SHALL display the resolved key source (e.g., "ANTHROPIC_API_KEY env var") without displaying the key value itself
5. FOR ALL valid combinations of environment variable presence and absence, the Key_Manager SHALL always select the highest-priority available credential

### Requirement 12: OpenAI-Compatible Provider Support

**User Story:** As a developer, I want to use any OpenAI-compatible provider (DeepSeek, Groq, Cerebras, Together, Fireworks, OpenRouter, Mistral, xAI, Perplexity, Cohere, DeepInfra, Novita) without custom integration code, so that I can optimize for cost, speed, or capability.

#### Acceptance Criteria

1. THE LLM_Client SHALL send requests to any OpenAI-compatible provider by setting the `endpoint` to the provider's base URL and appending `/chat/completions` if not already present
2. WHEN the endpoint is an OpenAI-compatible provider, THE LLM_Client SHALL authenticate using the `Authorization: Bearer <api_key>` header
3. THE Provider_Registry SHALL record the following endpoint for each OpenAI-compatible provider: DeepSeek at `https://api.deepseek.com/v1`, Groq at `https://api.groq.com/openai/v1`, Cerebras at `https://api.cerebras.ai/v1`, Together AI at `https://api.together.xyz/v1`, Fireworks AI at `https://api.fireworks.ai/inference/v1`, OpenRouter at `https://openrouter.ai/api/v1`, Mistral at `https://api.mistral.ai/v1`, xAI at `https://api.x.ai/v1`, Perplexity at `https://api.perplexity.ai`, Cohere at `https://api.cohere.ai/compatibility/v1`, DeepInfra at `https://api.deepinfra.com/v1/openai`, Novita AI at `https://api.novita.ai/v3/openai`
4. THE Provider_Registry SHALL record the following endpoint for Google Gemini's OpenAI-compatible mode: `https://generativelanguage.googleapis.com/v1beta/openai/`
5. WHEN the configured provider is Azure OpenAI, THE LLM_Client SHALL construct the endpoint as `https://<resource_name>.openai.azure.com/openai/deployments/<deployment_name>/chat/completions?api-version=2024-02-01` using values from the config file or environment variables `AZURE_OPENAI_RESOURCE` and `AZURE_OPENAI_DEPLOYMENT`

### Requirement 13: FSL-1.1-Apache-2.0 License Migration

**User Story:** As the licensor, I want to adopt the Functional Source License (FSL-1.1) so that the non-compete protection is simpler and clearer than BSL, the community trust signal is stronger, and the codebase automatically becomes Apache 2.0 after two years.

#### Acceptance Criteria

1. THE `LICENSE` file SHALL be replaced with the Functional Source License version 1.1 (FSL-1.1) with Apache License 2.0 as the Change License and a Change Date of two years from the first public release of each version
2. THE FSL-1.1 `LICENSE` file SHALL identify the Licensor as Emmanuel Enyi and the Licensed Work as "Sicario CLI and Template Registry"
3. THE FSL-1.1 non-compete clause SHALL prohibit any use of the Licensed Work to offer a competing product or service — specifically, running Sicario as a hosted security scanning service for third parties is prohibited without a commercial agreement
4. THE FSL-1.1 license SHALL explicitly permit: individual developers using Sicario locally, running Sicario in CI/CD pipelines for internal use, open-source projects, and non-profit organizations — all without a commercial agreement
5. THE repository SHALL contain a `COMMERCIAL_LICENSE.md` file that describes the enterprise licensing path, pricing model reference, and contact information for licensing inquiries
6. THE `COMMERCIAL_LICENSE.md` file SHALL include a section explaining the FSL-1.1 choice: simpler non-compete language than BSL, 2-year automatic conversion to Apache 2.0, and alignment with the Fair Source movement
7. ALL references to "BSL 1.1" in `README.md`, `Cargo.toml`, badge URLs, and inline comments SHALL be updated to "FSL-1.1"

### Requirement 14: Contributor License Agreement

**User Story:** As the project maintainer, I want all contributors to sign a CLA, so that I retain the ability to relicense the codebase for commercial purposes and to re-relicense it again when FSL converts to Apache 2.0.

#### Acceptance Criteria

1. THE `CONTRIBUTING.md` file SHALL include a section titled "Contributor License Agreement" that states contributors must agree to the CLA before their pull request can be merged
2. THE `CONTRIBUTING.md` file SHALL include a link to the CLA document or CLA signing service
3. THE `CONTRIBUTING.md` file SHALL replace any reference to "MIT License" with the correct FSL-1.1 and CLA language
4. THE repository SHALL contain a `CLA.md` file that grants the licensor the right to use, modify, sublicense, and relicense contributions under any license, including proprietary licenses and future open-source licenses
5. THE `CLA.md` file SHALL state that contributors retain copyright to their contributions while granting the licensor a perpetual, irrevocable, worldwide, royalty-free license

### Requirement 15: Trademark Guidance

**User Story:** As the brand owner, I want clear trademark guidance in the repository, so that third parties know what uses of the "Sicario" name and logo are permitted.

#### Acceptance Criteria

1. THE `COMMERCIAL_LICENSE.md` file SHALL include a section titled "Trademark Policy" that states "Sicario" and the Sicario logo are trademarks of the licensor
2. THE Trademark Policy section SHALL explicitly permit use of the name "Sicario" in factual descriptions such as "powered by Sicario" or "compatible with Sicario"
3. THE Trademark Policy section SHALL explicitly prohibit use of the name "Sicario" in product names, company names, or domain names without written permission
4. THE Trademark Policy section SHALL explicitly prohibit use of the Sicario logo in any form without written permission

### Requirement 16: GitHub Marketplace Listing

**User Story:** As a developer, I want to find and install the Sicario GitHub Action from the GitHub Marketplace, so that I can add security scanning to my CI pipeline in one click.

#### Acceptance Criteria

1. THE `action.yml` file SHALL include a `branding` section with an `icon` and `color` field as required by GitHub Marketplace
2. THE `action.yml` file SHALL include a `description` field of 125 characters or fewer as required by GitHub Marketplace
3. THE repository SHALL contain a `README.md` section titled "GitHub Marketplace" that describes the action's inputs, outputs, and example workflow
4. THE `action.yml` file SHALL define at least the following inputs: `args` (the sicario command arguments), `version` (the CLI version to install, defaulting to `latest`), and `fail-on` (the severity threshold for exit code 1, defaulting to `High`)
5. WHEN the GitHub Action runs, THE action SHALL install the specified version of the Sicario CLI binary and execute `sicario <args>` with the configured inputs

### Requirement 17: Sicario Rules Open-Source Library

**User Story:** As a security engineer, I want to contribute to and consume a community-maintained rule library, so that Sicario's detection coverage improves through collective effort.

#### Acceptance Criteria

1. THE project documentation SHALL describe a `sicario-rules` repository as a separate open-source repository under the Apache 2.0 license
2. THE `sicario-rules` repository description SHALL specify that it contains only YAML rule files and test fixtures, with no Rust source code
3. THE CLI SHALL support loading rules from a local directory path specified via `--rules-dir` in addition to the built-in rules
4. WHEN `--rules-dir` is specified, THE CLI SHALL merge rules from the specified directory with the built-in rules, with user-provided rules taking precedence on ID conflicts
5. THE `CONTRIBUTING.md` file SHALL include a section describing how to contribute new rules to the `sicario-rules` repository

### Requirement 18: Continuous Watch Mode

**User Story:** As a developer, I want the CLI to automatically re-scan files as I edit them, so that I get immediate security feedback without running a manual scan.

#### Acceptance Criteria

1. THE CLI SHALL implement a `sicario scan --watch` flag that keeps the process running and monitors the target directory for file changes
2. WHEN a file is modified, created, or deleted in the watched directory, THE CLI SHALL re-scan only the affected file within 500 milliseconds of the change event
3. WHILE in watch mode, THE CLI SHALL display a live-updating summary of the current finding count by severity
4. WHEN a new finding is introduced by a file change, THE CLI SHALL display the finding immediately using the standard diagnostic output format
5. WHEN a finding is resolved by a file change, THE CLI SHALL display a "resolved" notification for that finding
6. WHILE in watch mode, THE CLI SHALL respect `.gitignore` and `.sicarioignore` exclusion patterns
7. WHEN the user presses `Ctrl+C` while in watch mode, THE CLI SHALL exit cleanly with exit code 0

### Requirement 19: SOC 2 Type II Audit Logging Readiness

**User Story:** As a compliance officer, I want all security-relevant actions logged in a structured, tamper-evident format, so that Sicario can pass a SOC 2 Type II audit.

#### Acceptance Criteria

1. THE Billing_Service SHALL log all subscription state transitions (created, upgraded, downgraded, canceled, past_due) with timestamp, orgId, previous plan, new plan, and the triggering event source (Whop webhook event ID or admin action)
2. THE Billing_Service SHALL log all plan enforcement rejections with timestamp, orgId, endpoint, rejection reason, and the limit that was exceeded
3. THE Dashboard SHALL log all administrative actions (project deletion, telemetry purge, API key rotation, SSO configuration changes) with timestamp, userId, orgId, and action type
4. THE audit log entries SHALL be stored in a dedicated Convex table with no delete or update mutations exposed — entries are append-only
5. WHEN an enterprise organization requests a compliance export, THE Dashboard SHALL generate a JSON export of all audit log entries for the organization within the requested date range

### Requirement 20: Parser and Serializer Correctness for Billing Payloads

**User Story:** As a platform engineer, I want billing and usage data to survive serialization round-trips without data loss, so that Stripe webhook processing and telemetry ingestion are reliable.

#### Acceptance Criteria

1. THE Billing_Service SHALL serialize subscription records to JSON for Whop webhook processing and SHALL deserialize them back to equivalent records without data loss
2. FOR ALL valid subscription records, serializing to JSON and then deserializing SHALL produce a record equal to the original (round-trip property)
3. THE CLI SHALL serialize the Contributing_Developer count and include it in the telemetry payload JSON
4. FOR ALL valid telemetry payloads containing a contributor count, serializing to JSON and deserializing SHALL preserve the contributor count exactly
5. THE Billing_Service SHALL validate that all required subscription fields are present before persisting a record, and SHALL return a descriptive error identifying missing fields if validation fails

### Requirement 21: Zero-Exfiltration Billing Constraint

**User Story:** As a privacy-conscious developer, I want to be certain that the billing system never receives my source code or LLM keys, so that I can trust Sicario with sensitive codebases.

#### Acceptance Criteria

1. THE Billing_Service SHALL never store, log, or transmit LLM API keys of any kind
2. THE telemetry payload schema SHALL not include any field for LLM API keys, and THE Billing_Service SHALL reject any payload that contains a field named `llmApiKey`, `openaiKey`, `anthropicKey`, or any variant thereof
3. THE Contributing_Developer count submitted in the telemetry payload SHALL be a single integer and SHALL NOT include author names, email addresses, commit messages, or any other personally identifiable information
4. THE Dashboard SHALL display the Contributing_Developer count as a number only, with no ability to enumerate individual contributor identities
5. THE `SICARIO_API_KEY` environment variable documentation SHALL explicitly state that this key is for telemetry authentication only and is never used for LLM requests

### Requirement 22: Subscription Schema Additions

**User Story:** As a backend engineer, I want the Convex schema to include the necessary tables for subscription and usage tracking, so that billing state is persisted reliably.

#### Acceptance Criteria

1. THE Convex schema SHALL include a `subscriptions` table with the following fields: `orgId` (string), `plan` (string: `free` | `pro` | `team` | `enterprise`), `status` (string: `active` | `trialing` | `past_due` | `canceled` | `paused`), `billingCycle` (string: `monthly` | `annual` | `manual`), `seatCount` (number), `currentPeriodStart` (string ISO-8601), `currentPeriodEnd` (string ISO-8601), `whopUserId` (optional string), `whopSubscriptionId` (optional string), `trialEndsAt` (optional string ISO-8601), `customRetentionDays` (optional number), `csmIdentifier` (optional string), `contractStartDate` (optional string)
2. THE Convex schema SHALL include a `usageSummary` table with the following fields: `orgId` (string), `periodStart` (string ISO-8601), `periodEnd` (string ISO-8601), `findingsStored` (number), `projectCount` (number), `scansSubmitted` (number)
3. THE `subscriptions` table SHALL have an index on `orgId` for O(1) lookup by organization
4. THE `usageSummary` table SHALL have a compound index on `orgId` and `periodStart` for efficient period-range queries
5. WHEN an organization is created, THE Billing_Service SHALL automatically create a `subscriptions` record with `plan: "free"`, `status: "active"`, and `billingCycle: "manual"`
6. THE `subscriptions` and `usageSummary` tables SHALL be included in the audit log scope for SOC 2 compliance

### Requirement 23: Pro and Team Plan Feature Gates

**User Story:** As a Pro or Team subscriber, I want access to the features I'm paying for, so that my subscription delivers the promised value.

#### Acceptance Criteria

1. WHILE a subscription is on the `pro` or `team` plan, THE Plan_Enforcer SHALL permit PR check integration (creating and updating `prChecks` records via the telemetry endpoint)
2. WHILE a subscription is on the `pro` or `team` plan, THE Plan_Enforcer SHALL permit Slack and Microsoft Teams webhook configuration
3. WHILE a subscription is on the `pro` or `team` plan, THE Plan_Enforcer SHALL permit SARIF and OWASP report generation and download from the Dashboard
4. WHILE a subscription is on the `team` plan, THE Plan_Enforcer SHALL permit team management: inviting members, assigning roles (admin, manager, developer), and removing members
5. WHILE a subscription is on the `team` plan, THE Plan_Enforcer SHALL permit custom YAML rule uploads via the Dashboard
6. WHILE a subscription is on the `team` plan, THE Plan_Enforcer SHALL permit baseline management operations (save, compare, trend) via the Dashboard
7. WHILE a subscription is on the `team` plan, THE Plan_Enforcer SHALL permit access to the execution audit trail for all findings in the organization
8. IF an organization on the `free` plan attempts to use a `pro`-or-above feature, THEN THE Plan_Enforcer SHALL return HTTP 402 with a message identifying the required plan and a link to the pricing page

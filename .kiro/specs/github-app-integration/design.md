# Design Document: GitHub App Integration

## Overview

This design replaces all mocked GitHub App data in the V2 onboarding flow with real Sicario Security GitHub App integration, removes the legacy V1 onboarding entirely, and consolidates to a single onboarding experience. The implementation spans two codebases: the Convex backend (`convex/convex/`) and the React frontend (`sicario-frontend/`).

The core changes are:

1. A new Convex HTTP action that generates RS256-signed JWTs using `crypto.subtle`, exchanges them for GitHub installation tokens, and fetches repositories for a given installation.
2. Frontend updates to `OnboardingV2Page.tsx` that redirect to the real GitHub App installation URL, handle the `installation_id` callback, and call the new backend endpoint.
3. Passing the real `installation_id` through to the `createV2` mutation instead of the `ghapp_placeholder` string.
4. Deletion of the V1 onboarding files (`OnboardingPage.tsx`, `OnboardingWizard.tsx`, `useOnboarding.ts`) and removal of the `/dashboard/onboarding` route from `App.tsx`.
5. CORS preflight support for the new `/api/v1/github/repos` endpoint.

## Architecture

```mermaid
sequenceDiagram
    participant User
    participant Browser as OnboardingV2Page
    participant GitHub as GitHub.com
    participant Convex as Convex HTTP Actions

    User->>Browser: Click "Install GitHub App"
    Browser->>GitHub: Redirect to /apps/sicario-security/installations/new
    GitHub->>Browser: Redirect back with ?installation_id=123&setup_action=install
    Browser->>Browser: Extract installation_id from URL params
    Browser->>Convex: GET /api/v1/github/repos?installation_id=123 (Bearer token)
    Convex->>Convex: Read GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY from env
    Convex->>Convex: Generate RS256 JWT (iss=APP_ID, iat=now-60s, exp=now+10m)
    Convex->>GitHub: POST /app/installations/123/access_tokens (Bearer JWT)
    GitHub-->>Convex: { token: "ghs_xxx" }
    Convex->>GitHub: GET /installation/repositories (Bearer ghs_xxx)
    GitHub-->>Convex: { repositories: [...] }
    Convex-->>Browser: JSON array of { name, full_name, html_url }
    Browser->>Browser: Display real repos, user selects one
    User->>Browser: Click "Confirm & Continue"
    Browser->>Convex: createV2 mutation (installation_id=123, repo info)
    Convex->>Convex: Store project with real githubAppInstallationId
```

The architecture keeps all GitHub API communication server-side in Convex HTTP actions. The private key never leaves the backend. The frontend only passes the `installation_id` (a non-secret numeric identifier provided by GitHub in the redirect URL) and receives repository metadata.

### Key Design Decisions

1. **JWT signing in Convex HTTP actions**: Convex HTTP actions have access to `crypto.subtle.importKey` with `RSASSA-PKCS1-v1_5`, which is sufficient for RS256 JWT signing. No external JWT library is needed — we construct the JWT manually (base64url-encode header + payload, sign with `crypto.subtle.sign`).

2. **No token caching**: Installation tokens are short-lived (1 hour) but we only need them during onboarding. The cost of generating a fresh token per request is negligible for this use case. Caching can be added later if needed for high-frequency operations.

3. **Authentication via existing `resolveIdentity`**: The `/api/v1/github/repos` endpoint reuses the existing `resolveIdentity` helper from `http.ts` to authenticate the caller, maintaining consistency with all other API endpoints.

4. **Frontend redirect flow (not popup)**: The GitHub App installation uses a full-page redirect to `github.com/apps/sicario-security/installations/new`. GitHub redirects back to the onboarding page with query parameters. This is the standard GitHub App installation flow and avoids popup-blocker issues.

## Components and Interfaces

### Backend Components (convex/convex/)

#### 1. `githubApp.ts` — GitHub App utility module (new file)

Pure functions for JWT generation and GitHub API interaction, used by HTTP actions.

```typescript
// Generates an RS256-signed JWT for GitHub App authentication
async function generateAppJwt(appId: string, privateKeyPem: string): Promise<string>

// Acquires an installation token from GitHub
async function getInstallationToken(jwt: string, installationId: string): Promise<string>

// Fetches repositories accessible to an installation
async function listInstallationRepos(token: string): Promise<Array<{ name: string; full_name: string; html_url: string }>>
```

#### 2. `http.ts` — New route additions

```typescript
// GET /api/v1/github/repos?installation_id=<id>
// - Authenticates caller via resolveIdentity
// - Calls generateAppJwt → getInstallationToken → listInstallationRepos
// - Returns JSON array of repos

// OPTIONS /api/v1/github/repos
// - Returns 204 with CORS headers
```

#### 3. Environment variable validation

A helper function that reads and validates all required GitHub App env vars, returning a typed object or throwing with a descriptive message:

```typescript
function requireGitHubAppEnv(): {
  appId: string;
  privateKey: string;
  clientId: string;
  clientSecret: string;
}
```

### Frontend Components (sicario-frontend/)

#### 1. `OnboardingV2Page.tsx` — Modified

- Remove `MOCK_REPOS` constant
- Remove `handleGitHubAppInstall` mock behavior
- Add `installationId` state (extracted from URL params)
- Add `repos` state (fetched from backend)
- Add `repoLoading` and `repoError` states
- Redirect to `https://github.com/apps/sicario-security/installations/new` on button click
- On mount, check `URLSearchParams` for `installation_id` and `setup_action`
- Call `/api/v1/github/repos?installation_id=<id>` when installation_id is present
- Pass real `installationId` to `createV2` mutation

#### 2. Files to delete

- `sicario-frontend/src/pages/dashboard/OnboardingPage.tsx`
- `sicario-frontend/src/components/dashboard/OnboardingWizard.tsx`
- `sicario-frontend/src/hooks/useOnboarding.ts`

#### 3. `App.tsx` — Modified

- Remove `OnboardingPage` lazy import
- Remove `/dashboard/onboarding` route
- Keep `/dashboard/onboarding/v2` route

## Data Models

### Existing Schema (no changes required)

The `projects` table already has the `githubAppInstallationId` field as an optional string. The `createV2` mutation already accepts this field. No schema migration is needed — we simply pass a real value instead of `"ghapp_placeholder"`.

```typescript
// From schema.ts — projects table (relevant fields)
{
  githubAppInstallationId: v.optional(v.string()),  // Will now store real installation IDs like "12345678"
}
```

### Environment Variables

| Variable | Purpose | Example |
|---|---|---|
| `GITHUB_APP_ID` | App ID for JWT `iss` claim | `3493217` |
| `GITHUB_APP_PRIVATE_KEY` | PEM-encoded RSA private key for RS256 signing | `-----BEGIN RSA PRIVATE KEY-----\n...` |
| `GITHUB_APP_CLIENT_ID` | OAuth client ID (for future OAuth flows) | `Iv23liklwqKCnrHPSmeM` |
| `GITHUB_APP_CLIENT_SECRET` | OAuth client secret (for future OAuth flows) | `ghsec_...` |
| `GITHUB_WEBHOOK_SECRET` | HMAC secret for webhook signature validation | `whsec_...` |

### API Contract

#### `GET /api/v1/github/repos?installation_id=<id>`

**Request:**
- Method: `GET`
- Query parameter: `installation_id` (required, numeric string)
- Header: `Authorization: Bearer <convex-auth-token>`

**Success Response (200):**
```json
[
  { "name": "my-app", "full_name": "org/my-app", "html_url": "https://github.com/org/my-app" },
  { "name": "api-server", "full_name": "org/api-server", "html_url": "https://github.com/org/api-server" }
]
```

**Error Responses:**
- `401`: Unauthorized (missing or invalid auth token)
- `500`: Missing GitHub App configuration
- `502`: GitHub API error (token acquisition or repo fetch failed)


## Correctness Properties

*A property is a characteristic or behavior that should hold true across all valid executions of a system — essentially, a formal statement about what the system should do. Properties serve as the bridge between human-readable specifications and machine-verifiable correctness guarantees.*

### Property 1: Missing environment variable detection

*For any* subset of the 4 required GitHub App environment variables (`GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_CLIENT_SECRET`) where at least one variable is absent, the `requireGitHubAppEnv` function SHALL throw an error whose message contains the name of every missing variable.

**Validates: Requirements 1.5**

### Property 2: JWT generation round-trip

*For any* valid RSA key pair and any valid GitHub App ID string, generating a JWT via `generateAppJwt` and then decoding the resulting token (splitting on `.`, base64url-decoding header and payload) SHALL produce a header with `alg` equal to `"RS256"` and `typ` equal to `"JWT"`, and a payload where `iss` equals the App ID, `iat` is within 1 second of `(referenceTime - 60)`, and `exp` is within 1 second of `(referenceTime + 600)`. Furthermore, verifying the signature against the corresponding public key using `RSASSA-PKCS1-v1_5` with SHA-256 SHALL succeed.

**Validates: Requirements 2.1, 2.2**

### Property 3: Repository extraction preserves required fields

*For any* array of GitHub API repository objects (each containing at least `name`, `full_name`, `html_url`, and arbitrary additional fields), the `listInstallationRepos` extraction logic SHALL return an array of the same length where each element contains exactly the `name`, `full_name`, and `html_url` fields matching the corresponding input object, with no additional fields.

**Validates: Requirements 3.3**

### Property 4: Webhook HMAC-SHA256 validation round-trip

*For any* non-empty payload string and any non-empty secret string, computing the HMAC-SHA256 of the payload with the secret, formatting it as `sha256=<hex>`, and then calling `validateWebhookSignature(payload, formattedSignature, secret)` SHALL return `true`. Additionally, calling `validateWebhookSignature(payload + "tampered", formattedSignature, secret)` SHALL return `false`.

**Validates: Requirements 8.2**

### Property 5: CORS headers present on all endpoint responses

*For any* request to `/api/v1/github/repos` (regardless of HTTP method, authentication state, or query parameters), the response SHALL include `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, and `Access-Control-Allow-Headers` headers.

**Validates: Requirements 9.2**

## Error Handling

### Backend Error Handling

| Scenario | HTTP Status | Response Body | Requirement |
|---|---|---|---|
| Missing GitHub App env var | 500 | `{ "error": "Missing configuration: GITHUB_APP_PRIVATE_KEY" }` | 1.5 |
| Caller not authenticated | 401 | `{ "error": "Unauthorized" }` | 3.4 |
| GitHub API returns error during token acquisition | 502 | `{ "error": "GitHub API error: <status> <message>" }` | 2.5, 3.5 |
| GitHub API returns error during repo fetch | 502 | `{ "error": "Failed to fetch repositories: <message>" }` | 3.5 |
| Missing `installation_id` query param | 400 | `{ "error": "installation_id query parameter is required" }` | — |
| Webhook secret not configured | 500 | `{ "error": "Webhook secret not configured" }` | 8.3 |
| Invalid webhook signature | 401 | `{ "error": "Invalid webhook signature" }` | 8.2 |

### Frontend Error Handling

| Scenario | Behavior | Requirement |
|---|---|---|
| Repo fetch fails (network/502) | Display error banner with message + "Retry" button | 5.5 |
| Project creation fails | Display error banner with "Failed to create project. Please try again." | Existing |
| No `installation_id` in URL on load | Show the "Install GitHub App" button (initial state) | 5.1 |

### PEM Key Parsing

The `GITHUB_APP_PRIVATE_KEY` environment variable may contain literal `\n` escape sequences (common in environment variable storage). The `generateAppJwt` function must normalize these to actual newline characters before passing to `crypto.subtle.importKey`. If the key fails to parse, the function throws with a descriptive error message.

## Testing Strategy

### Property-Based Tests (Vitest + fast-check)

Property-based tests will use `fast-check` with Vitest. Each property test runs a minimum of 100 iterations.

| Property | Test File | What Varies |
|---|---|---|
| Property 1: Missing env var detection | `convex/convex/__tests__/githubApp.property.test.ts` | Which subset of env vars is present/absent |
| Property 2: JWT generation round-trip | `convex/convex/__tests__/githubApp.property.test.ts` | App ID strings, reference timestamps |
| Property 3: Repo extraction | `convex/convex/__tests__/githubApp.property.test.ts` | Number of repos, field names, extra fields |
| Property 4: Webhook HMAC round-trip | `convex/convex/__tests__/webhookValidation.property.test.ts` | Payload strings, secret strings |
| Property 5: CORS headers invariant | `convex/convex/__tests__/githubReposEndpoint.property.test.ts` | Request method, auth state, query params |

Tag format: `Feature: github-app-integration, Property N: <title>`

### Unit Tests (Vitest)

| Test | What's Verified |
|---|---|
| `requireGitHubAppEnv` with all vars set | Returns typed object with correct values |
| `generateAppJwt` produces 3-part dot-separated string | JWT structure |
| Repo endpoint returns 401 without auth | Auth guard |
| Repo endpoint returns 400 without installation_id | Input validation |
| Repo endpoint returns 502 when GitHub API fails | Error propagation |
| Webhook handler returns 500 when secret missing | Env var check |
| CORS preflight returns 204 | OPTIONS handler |

### Integration Tests

| Test | What's Verified |
|---|---|
| Full onboarding flow with mocked GitHub API | End-to-end: redirect → callback → repo fetch → project creation |
| Webhook signature validation with real HMAC | Existing handler works with env var |

### Smoke Tests (Post-deployment)

| Test | What's Verified |
|---|---|
| All 5 GitHub App env vars are set in Convex deployment | Configuration |
| V1 onboarding files are deleted | File removal |
| `/dashboard/onboarding` route is removed from App.tsx | Route cleanup |
| `/dashboard/onboarding/v2` route exists | Route presence |

### Testing Notes

- **RS256 key generation for tests**: Property tests for JWT signing will generate RSA key pairs using `crypto.subtle.generateKey` with `RSASSA-PKCS1-v1_5` algorithm and 2048-bit modulus length. This avoids needing a real GitHub App private key in tests.
- **No real GitHub API calls in unit/property tests**: All GitHub API interactions are tested via mocks. Integration tests against the real GitHub API are out of scope for this feature.
- **Convex HTTP action testing**: Since Convex HTTP actions can't be directly unit-tested in isolation, the pure logic (JWT generation, repo extraction, env var validation, HMAC validation) is extracted into `githubApp.ts` as standalone async functions that can be tested independently.

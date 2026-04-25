# Implementation Plan: GitHub App Integration

## Overview

Replace all mocked GitHub App data in the V2 onboarding flow with real Sicario Security GitHub App integration, remove the legacy V1 onboarding, and consolidate to a single onboarding experience. Implementation spans the Convex backend (`convex/convex/`) and the React frontend (`sicario-frontend/`). Pure utility functions are extracted into a testable `githubApp.ts` module, tested with Vitest + fast-check property tests, and wired into HTTP actions and the frontend.

## Tasks

- [x] 1. Set up test infrastructure in the Convex project
  - Add `vitest` and `fast-check` as dev dependencies in `convex/package.json`
  - Add a `"test"` script (`vitest --run`) to `convex/package.json`
  - Create `convex/vitest.config.ts` with appropriate TypeScript and path configuration
  - Create the `convex/convex/__tests__/` directory
  - _Requirements: Testing Strategy (Design)_

- [x] 2. Implement `githubApp.ts` utility module
  - [x] 2.1 Create `convex/convex/githubApp.ts` with `requireGitHubAppEnv` function
    - Read `GITHUB_APP_ID`, `GITHUB_APP_PRIVATE_KEY`, `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_CLIENT_SECRET` from `process.env`
    - Throw an error whose message contains the name of every missing variable
    - Return a typed object `{ appId, privateKey, clientId, clientSecret }`
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5_

  - [ ]* 2.2 Write property test for `requireGitHubAppEnv`
    - **Property 1: Missing environment variable detection**
    - For any subset of the 4 required env vars where at least one is absent, the function SHALL throw an error whose message contains the name of every missing variable
    - Test file: `convex/convex/__tests__/githubApp.property.test.ts`
    - **Validates: Requirements 1.5**

  - [x] 2.3 Implement `generateAppJwt` function in `convex/convex/githubApp.ts`
    - Construct JWT header (`alg: RS256`, `typ: JWT`) and payload (`iss: appId`, `iat: now - 60`, `exp: now + 600`)
    - Base64url-encode header and payload
    - Normalize PEM key (replace literal `\n` with real newlines), strip PEM headers, decode base64 to ArrayBuffer
    - Import key via `crypto.subtle.importKey` with `RSASSA-PKCS1-v1_5` algorithm
    - Sign with `crypto.subtle.sign`, base64url-encode signature, return `header.payload.signature`
    - _Requirements: 2.1, 2.2_

  - [ ]* 2.4 Write property test for `generateAppJwt`
    - **Property 2: JWT generation round-trip**
    - For any valid RSA key pair and App ID, the generated JWT SHALL decode to correct header/payload and verify against the public key
    - Test file: `convex/convex/__tests__/githubApp.property.test.ts`
    - **Validates: Requirements 2.1, 2.2**

  - [x] 2.5 Implement `getInstallationToken` function in `convex/convex/githubApp.ts`
    - POST to `https://api.github.com/app/installations/{installationId}/access_tokens` with Bearer JWT
    - Include `Accept: application/vnd.github+json` and `User-Agent: sicario-security-app` headers
    - Extract and return the `token` field from the response
    - Throw with descriptive error including GitHub status code and message on failure
    - _Requirements: 2.3, 2.4, 2.5_

  - [x] 2.6 Implement `listInstallationRepos` function in `convex/convex/githubApp.ts`
    - GET `https://api.github.com/installation/repositories` with Bearer installation token
    - Include `Accept: application/vnd.github+json` and `User-Agent: sicario-security-app` headers
    - Extract `repositories` array from response, map each to `{ name, full_name, html_url }`
    - Throw with descriptive error on failure
    - _Requirements: 3.2, 3.3_

  - [ ]* 2.7 Write property test for repository extraction logic
    - **Property 3: Repository extraction preserves required fields**
    - For any array of GitHub API repo objects with arbitrary extra fields, the extraction SHALL return same-length array with exactly `name`, `full_name`, `html_url` matching input
    - Test file: `convex/convex/__tests__/githubApp.property.test.ts`
    - **Validates: Requirements 3.3**

- [ ] 3. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Add `/api/v1/github/repos` HTTP route and CORS preflight
  - [x] 4.1 Add GET `/api/v1/github/repos` route to `convex/convex/http.ts`
    - Authenticate caller via existing `resolveIdentity` helper
    - Return 401 if unauthenticated
    - Extract `installation_id` from URL query params; return 400 if missing
    - Call `requireGitHubAppEnv` (returns 500 on missing config)
    - Call `generateAppJwt` → `getInstallationToken` → `listInstallationRepos`
    - Return JSON array of repos with 200 status
    - Return 502 on GitHub API errors
    - Include CORS headers on all responses
    - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 9.2_

  - [x] 4.2 Add OPTIONS `/api/v1/github/repos` preflight route to `convex/convex/http.ts`
    - Return 204 with CORS headers (`Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, `Access-Control-Allow-Headers`)
    - _Requirements: 9.1_

  - [ ]* 4.3 Write property test for webhook HMAC-SHA256 validation
    - **Property 4: Webhook HMAC-SHA256 validation round-trip**
    - For any non-empty payload and secret, computing HMAC-SHA256 and validating SHALL return true; tampered payload SHALL return false
    - Test file: `convex/convex/__tests__/webhookValidation.property.test.ts`
    - **Validates: Requirements 8.2**

  - [ ]* 4.4 Write property test for CORS headers on `/api/v1/github/repos`
    - **Property 5: CORS headers present on all endpoint responses**
    - For any request to the endpoint (regardless of method, auth state, query params), the response SHALL include all 3 CORS headers
    - Test file: `convex/convex/__tests__/githubReposEndpoint.property.test.ts`
    - **Validates: Requirements 9.2**

  - [ ]* 4.5 Write unit tests for the repos endpoint
    - Test 401 without auth, 400 without `installation_id`, 502 on GitHub API failure
    - Test file: `convex/convex/__tests__/githubReposEndpoint.test.ts`
    - _Requirements: 3.4, 3.5_

- [ ] 5. Checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Update frontend `OnboardingV2Page.tsx` for real GitHub App flow
  - [x] 6.1 Replace mock data with real GitHub App redirect and callback handling
    - Remove `MOCK_REPOS` constant
    - Add `installationId` state, initialized from `URLSearchParams` `installation_id` on mount
    - Add `repos`, `repoLoading`, `repoError` state variables
    - Change "Install GitHub App" button to redirect to `https://github.com/apps/sicario-security/installations/new`
    - Remove the mock `handleGitHubAppInstall` that sets `githubAuthed` to true directly
    - On mount, if `installation_id` param is present, set `githubAuthed` to true and store the ID
    - _Requirements: 4.1, 4.2, 5.1, 5.2_

  - [x] 6.2 Fetch real repositories from backend
    - When `installationId` is set, call `GET /api/v1/github/repos?installation_id=<id>` with the user's auth token
    - Use the Convex deployment URL (`https://flexible-terrier-680.convex.site`) as the base
    - Set `repos` state from the response; display them in the repo selection list
    - Handle loading state with `repoLoading`
    - On error, set `repoError` and display error banner with "Retry" button
    - _Requirements: 5.3, 5.4, 5.5_

  - [x] 6.3 Pass real `installationId` to `createV2` mutation
    - Replace `githubAppInstallationId: 'ghapp_placeholder'` with `githubAppInstallationId: installationId`
    - Ensure `installationId` is the string value from the GitHub callback
    - _Requirements: 6.1, 6.2_

- [x] 7. Remove legacy V1 onboarding
  - [x] 7.1 Delete V1 onboarding files
    - Delete `sicario-frontend/src/pages/dashboard/OnboardingPage.tsx`
    - Delete `sicario-frontend/src/components/dashboard/OnboardingWizard.tsx`
    - Delete `sicario-frontend/src/hooks/useOnboarding.ts`
    - _Requirements: 7.1, 7.2, 7.3_

  - [x] 7.2 Update `sicario-frontend/src/App.tsx` routing
    - Remove the `OnboardingPage` lazy import
    - Remove the `/dashboard/onboarding` route
    - Keep the `/dashboard/onboarding/v2` route pointing to `OnboardingV2Page`
    - _Requirements: 7.4, 7.5, 7.6_

- [x] 8. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.
  - Verify V1 onboarding files are deleted
  - Verify `/dashboard/onboarding` route is removed from App.tsx
  - Verify `/dashboard/onboarding/v2` route still exists

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation
- Property tests validate universal correctness properties from the design document using fast-check + Vitest
- Unit tests validate specific examples and edge cases
- All GitHub API communication stays server-side in Convex HTTP actions — the private key never leaves the backend
- The `githubApp.ts` module exports pure async functions that can be tested independently without Convex runtime

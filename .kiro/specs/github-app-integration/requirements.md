# Requirements Document

## Introduction

This feature replaces all mocked GitHub App data in the V2 onboarding flow with real GitHub App (Sicario Security) integration, removes the legacy V1 onboarding flow entirely, and consolidates to a single onboarding experience. The Sicario Security GitHub App (owned by @sicario-labs) enables users to install the app on their GitHub account/org, select repositories, and create projects backed by real installation IDs and repository data fetched from the GitHub API.

## Glossary

- **Onboarding_V2_Page**: The React page component at `sicario-frontend/src/pages/dashboard/OnboardingV2Page.tsx` that guides new users through GitHub App installation, repository selection, and project creation.
- **GitHub_App**: The registered GitHub App named "Sicario Security" (slug: `sicario-security`, App ID: 3493217) owned by the @sicario-labs organization.
- **Installation_Token**: A short-lived token obtained from the GitHub API by signing a JWT with the GitHub App private key and exchanging it for a token scoped to a specific installation.
- **Installation_ID**: A numeric identifier assigned by GitHub when a user or organization installs the GitHub App, passed back as a query parameter after the installation flow.
- **Convex_Backend**: The Convex deployment at `https://flexible-terrier-680.convex.site` that hosts HTTP endpoints, mutations, and queries for the Sicario cloud platform.
- **JWT**: A JSON Web Token signed with the GitHub App private key (RS256) used to authenticate as the GitHub App when requesting installation tokens.
- **PostLoginRouter**: The React component that determines whether an authenticated user is new (redirect to onboarding) or returning (show dashboard).
- **V1_Onboarding**: The legacy onboarding flow consisting of `OnboardingPage.tsx`, `OnboardingWizard` component, and `useOnboarding` hook, routed at `/dashboard/onboarding`.
- **Project_Record**: A row in the Convex `projects` table that stores project metadata including `githubAppInstallationId`.

## Requirements

### Requirement 1: GitHub App Credential Storage

**User Story:** As a platform operator, I want GitHub App credentials stored as Convex environment variables, so that the backend can authenticate with the GitHub API securely without hardcoded secrets.

#### Acceptance Criteria

1. THE Convex_Backend SHALL read the GitHub App private key from the `GITHUB_APP_PRIVATE_KEY` environment variable.
2. THE Convex_Backend SHALL read the GitHub App ID from the `GITHUB_APP_ID` environment variable.
3. THE Convex_Backend SHALL read the GitHub App client secret from the `GITHUB_APP_CLIENT_SECRET` environment variable.
4. THE Convex_Backend SHALL read the GitHub App client ID from the `GITHUB_APP_CLIENT_ID` environment variable.
5. IF any required GitHub App environment variable is missing, THEN THE Convex_Backend SHALL return an HTTP 500 response with a descriptive error message indicating the missing configuration.

### Requirement 2: JWT Generation and Installation Token Acquisition

**User Story:** As the backend system, I want to generate a JWT signed with the GitHub App private key and exchange it for an installation token, so that I can make authenticated API calls to GitHub on behalf of an installation.

#### Acceptance Criteria

1. WHEN the Convex_Backend needs to call the GitHub API for a specific installation, THE Convex_Backend SHALL generate a JWT with the `iss` claim set to the GitHub App ID, the `iat` claim set to the current time minus 60 seconds, and the `exp` claim set to 10 minutes from the current time.
2. THE Convex_Backend SHALL sign the JWT using the RS256 algorithm with the private key from the `GITHUB_APP_PRIVATE_KEY` environment variable.
3. WHEN a valid JWT is generated, THE Convex_Backend SHALL send a POST request to `https://api.github.com/app/installations/{installation_id}/access_tokens` with the JWT as a Bearer token.
4. WHEN the GitHub API returns a successful response, THE Convex_Backend SHALL extract the `token` field from the response body for use in subsequent API calls.
5. IF the GitHub API returns an error response, THEN THE Convex_Backend SHALL return an HTTP error response with the status code and error message from GitHub.

### Requirement 3: Repository Listing Endpoint

**User Story:** As a frontend developer, I want a Convex HTTP endpoint that fetches repositories for a given GitHub App installation, so that the onboarding page can display real repositories instead of mock data.

#### Acceptance Criteria

1. WHEN the Onboarding_V2_Page sends a GET request to `/api/v1/github/repos` with an `installation_id` query parameter, THE Convex_Backend SHALL acquire an Installation_Token for that installation.
2. WHEN a valid Installation_Token is obtained, THE Convex_Backend SHALL send a GET request to `https://api.github.com/installation/repositories` with the Installation_Token as a Bearer token.
3. THE Convex_Backend SHALL return a JSON array of repository objects, each containing `name`, `full_name`, and `html_url` fields extracted from the GitHub API response.
4. IF the caller is not authenticated, THEN THE Convex_Backend SHALL return an HTTP 401 response.
5. IF the Installation_Token acquisition fails, THEN THE Convex_Backend SHALL return an HTTP 502 response with a descriptive error message.

### Requirement 4: GitHub App Installation Redirect

**User Story:** As a new user, I want the "Install GitHub App" button to redirect me to the real GitHub App installation page, so that I can grant Sicario access to my repositories.

#### Acceptance Criteria

1. WHEN the user clicks the "Install GitHub App" button on the Onboarding_V2_Page, THE Onboarding_V2_Page SHALL redirect the browser to `https://github.com/apps/sicario-security/installations/new`.
2. THE Onboarding_V2_Page SHALL NOT set `githubAuthed` to true without a real GitHub App installation callback.

### Requirement 5: GitHub App Installation Callback Handling

**User Story:** As a new user returning from the GitHub App installation flow, I want the onboarding page to detect my installation and load my repositories, so that I can select a repository to protect.

#### Acceptance Criteria

1. WHEN the browser navigates to the Onboarding_V2_Page with `installation_id` and `setup_action` query parameters, THE Onboarding_V2_Page SHALL extract the `installation_id` value from the URL.
2. WHEN a valid `installation_id` is extracted, THE Onboarding_V2_Page SHALL store the installation ID in component state and set the GitHub-authenticated state to true.
3. WHEN the GitHub-authenticated state becomes true, THE Onboarding_V2_Page SHALL call the `/api/v1/github/repos` endpoint with the stored installation ID.
4. WHEN the repository list is successfully fetched, THE Onboarding_V2_Page SHALL display the real repositories in place of the previously hardcoded mock repository list.
5. IF the repository fetch fails, THEN THE Onboarding_V2_Page SHALL display an error message and provide a retry button.

### Requirement 6: Real Installation ID on Project Creation

**User Story:** As a new user, I want the project record to store my real GitHub App installation ID, so that future operations (webhooks, PR checks, auto-fix) can authenticate with GitHub on behalf of my installation.

#### Acceptance Criteria

1. WHEN the user confirms project creation on the Onboarding_V2_Page, THE Onboarding_V2_Page SHALL pass the real `installation_id` (from the GitHub callback) to the `createV2` mutation instead of the placeholder value `ghapp_placeholder`.
2. THE Project_Record SHALL store the real GitHub App installation ID in the `githubAppInstallationId` field.

### Requirement 7: Legacy V1 Onboarding Removal

**User Story:** As a developer, I want the legacy V1 onboarding flow removed, so that there is a single onboarding path and no dead code in the codebase.

#### Acceptance Criteria

1. THE codebase SHALL NOT contain the file `sicario-frontend/src/pages/dashboard/OnboardingPage.tsx`.
2. THE codebase SHALL NOT contain the file `sicario-frontend/src/components/dashboard/OnboardingWizard.tsx`.
3. THE codebase SHALL NOT contain the file `sicario-frontend/src/hooks/useOnboarding.ts`.
4. THE `sicario-frontend/src/App.tsx` route configuration SHALL NOT include a route for `/dashboard/onboarding`.
5. THE `sicario-frontend/src/App.tsx` route configuration SHALL include a route for `/dashboard/onboarding/v2` pointing to the Onboarding_V2_Page.
6. THE `sicario-frontend/src/App.tsx` SHALL NOT import the `OnboardingPage` component.

### Requirement 8: Webhook Secret Environment Variable

**User Story:** As a platform operator, I want the GitHub webhook handler to use the `GITHUB_WEBHOOK_SECRET` environment variable for signature validation, so that webhook payloads are verified against the real secret.

#### Acceptance Criteria

1. WHEN a webhook request arrives at `/api/v1/github/webhook`, THE Convex_Backend SHALL read the webhook secret from the `GITHUB_WEBHOOK_SECRET` environment variable.
2. THE Convex_Backend SHALL validate the `X-Hub-Signature-256` header against the payload using the secret from the environment variable.
3. IF the `GITHUB_WEBHOOK_SECRET` environment variable is not set, THEN THE Convex_Backend SHALL return an HTTP 500 response with the message "Webhook secret not configured".

### Requirement 9: CORS and Preflight for New Endpoints

**User Story:** As a frontend developer, I want the new GitHub API endpoints to support CORS preflight requests, so that the browser can call them from the Sicario frontend domain.

#### Acceptance Criteria

1. WHEN an OPTIONS request is sent to `/api/v1/github/repos`, THE Convex_Backend SHALL return a 204 response with appropriate CORS headers.
2. THE Convex_Backend SHALL include `Access-Control-Allow-Origin`, `Access-Control-Allow-Methods`, and `Access-Control-Allow-Headers` headers on all responses from `/api/v1/github/repos`.

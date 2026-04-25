# Implementation Plan: Email-Based Member Invite

## Overview

Replace the User ID-based member addition flow with an email-based invite system. Implementation proceeds bottom-up: schema changes first, then backend mutations/queries, then the auth callback, then frontend components. Both `convex/convex/` and `sicario-frontend/convex/` directories must be updated in parallel since they share the same schema and function definitions.

## Tasks

- [x] 1. Add `pendingInvitations` table and update `userProfiles` schema
  - [x] 1.1 Update `convex/convex/schema.ts` to add the `pendingInvitations` table with fields: `invitationId`, `email`, `orgId`, `role`, `teamIds`, `inviterUserId`, `createdAt`; add indexes `by_orgId`, `by_email`, `by_orgId_email`; add optional `lastNotificationDismissedAt` field to `userProfiles` table
    - _Requirements: 6.1, 6.2, 6.3, 8.3_
  - [x] 1.2 Mirror the same schema changes in `sicario-frontend/convex/schema.ts`
    - _Requirements: 6.1, 6.2, 6.3, 8.3_

- [x] 2. Implement `invitations.ts` backend functions
  - [x] 2.1 Create `convex/convex/invitations.ts` with the `create` mutation: accept `callerUserId, orgId, email, role, teamIds?`; normalize email to lowercase; enforce admin RBAC via `requireRole`; check for duplicate membership; check for duplicate pending invitation; look up Auth `users` table by email; if user found create membership immediately and return `{ status: "added", email }`; if not found create `pendingInvitations` record and return `{ status: "invited", email }`
    - _Requirements: 1.1, 1.2, 1.3, 1.5, 1.6, 5.1, 6.4_
  - [x] 2.2 Add the `listPending` query to `convex/convex/invitations.ts`: accept `orgId, callerUserId`; enforce admin RBAC; query `pendingInvitations` by `by_orgId` index; return all records with email, role, teamIds, createdAt
    - _Requirements: 4.1, 4.2, 5.1_
  - [x] 2.3 Add the `revoke` mutation to `convex/convex/invitations.ts`: accept `callerUserId, orgId, invitationId`; enforce admin RBAC; find and delete the pending invitation record
    - _Requirements: 4.3, 5.2, 5.3_
  - [x] 2.4 Add the `getNewMemberships` query to `convex/convex/invitations.ts`: accept `userId`; look up `userProfiles` for `lastNotificationDismissedAt`; query memberships for the user; filter to those created after the dismissal timestamp; join with `organizations` table to include org name; return array of `{ orgName, role, createdAt }`
    - _Requirements: 8.1, 8.2, 8.4_
  - [x] 2.5 Add the `dismissNotifications` mutation to `convex/convex/invitations.ts`: accept `userId`; upsert `lastNotificationDismissedAt` on the user's `userProfiles` record to current ISO timestamp
    - _Requirements: 8.3_
  - [x] 2.6 Mirror `convex/convex/invitations.ts` to `sicario-frontend/convex/invitations.ts`
    - _Requirements: 1.1, 1.2, 1.3, 1.5, 1.6, 4.1, 4.2, 4.3, 5.1, 5.2, 5.3, 8.1, 8.2, 8.3, 8.4_

- [x] 3. Checkpoint — Verify backend functions
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Add `afterUserCreatedOrUpdated` callback in auth.ts
  - [x] 4.1 Modify `convex/convex/auth.ts` to add an `afterUserCreatedOrUpdated` callback to the `convexAuth` config: query `pendingInvitations` by the user's email (normalized to lowercase); for each matching invitation, create a membership record with the invitation's role and teamIds, then delete the pending invitation; wrap each invitation processing in try/catch so a single failure doesn't block others; log errors and retain failed invitation records
    - _Requirements: 3.1, 3.2, 3.3, 3.4_
  - [x] 4.2 Mirror the same `auth.ts` changes to `sicario-frontend/convex/auth.ts`
    - _Requirements: 3.1, 3.2, 3.3, 3.4_

- [x] 5. Checkpoint — Verify auth callback integration
  - Ensure all tests pass, ask the user if questions arise.

- [x] 6. Update frontend `AddMemberModal` and `MembersTab`
  - [x] 6.1 Modify `AddMemberModal` in `sicario-frontend/src/pages/dashboard/SettingsPage.tsx`: replace `userId: string` form field with `email: string`; add email format validation (regex for `local-part@domain` after trimming whitespace); change mutation call from `api.memberships.create` to `api.invitations.create`; differentiate success toast: "Member added" when status is `"added"`, "Invitation sent" when status is `"invited"`; show loading state on submit button and disable inputs during submission
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 2.1, 2.2, 2.3, 1.4_
  - [x] 6.2 Modify the `MembersTab` in `sicario-frontend/src/pages/dashboard/SettingsPage.tsx`: add a `useQuery` call for `api.invitations.listPending`; render pending invitations in the members table with a "Pending" `Badge` component; add a "Revoke" action button on each pending row that calls `api.invitations.revoke`
    - _Requirements: 4.4, 4.3_

- [x] 7. Create `NewMembershipBanner` component
  - [x] 7.1 Create `sicario-frontend/src/components/dashboard/NewMembershipBanner.tsx`: query `api.invitations.getNewMemberships`; if results are non-empty, render a banner at the top of the content area listing org name(s) and role(s); include a dismiss button that calls `api.invitations.dismissNotifications`; style consistently with the existing design system
    - _Requirements: 8.1, 8.2, 8.4, 8.5_
  - [x] 7.2 Integrate `NewMembershipBanner` into `sicario-frontend/src/pages/dashboard/DashboardLayout.tsx`: render the banner inside `<main>` above the `<ErrorBoundary>` so it appears at the top of the dashboard content area
    - _Requirements: 8.5_

- [x] 8. Checkpoint — Verify frontend integration
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 9. Write property-based tests for invitation logic
  - [ ]* 9.1 Write property test for email lookup normalization in `convex/convex/__tests__/email-invite-properties.test.ts`
    - **Property 1: Email lookup finds correct user by normalized email**
    - **Validates: Requirements 1.1**
  - [ ]* 9.2 Write property test for email validation
    - **Property 2: Email validation accepts valid emails and rejects invalid ones**
    - **Validates: Requirements 2.1, 2.3**
  - [ ]* 9.3 Write property test for immediate membership field preservation
    - **Property 3: Immediate membership creation preserves invite fields**
    - **Validates: Requirements 1.2**
  - [ ]* 9.4 Write property test for pending invitation field completeness
    - **Property 4: Pending invitation stores all required fields**
    - **Validates: Requirements 1.3, 6.1**
  - [ ]* 9.5 Write property test for duplicate membership rejection
    - **Property 5: Duplicate membership rejection**
    - **Validates: Requirements 1.5**
  - [ ]* 9.6 Write property test for duplicate pending invitation rejection
    - **Property 6: Duplicate pending invitation rejection**
    - **Validates: Requirements 1.6, 6.4**
  - [ ]* 9.7 Write property test for pending invitation to membership round-trip
    - **Property 7: Pending invitation to membership round-trip**
    - **Validates: Requirements 3.1, 3.2, 3.3**
  - [ ]* 9.8 Write property test for RBAC enforcement
    - **Property 8: RBAC enforcement for invitation operations**
    - **Validates: Requirements 5.1, 5.2, 5.3**
  - [ ]* 9.9 Write property test for pending invitation listing completeness
    - **Property 9: Pending invitation listing returns complete records**
    - **Validates: Requirements 4.1, 4.2**
  - [ ]* 9.10 Write property test for revocation deletion
    - **Property 10: Pending invitation revocation deletes the record**
    - **Validates: Requirements 4.3**
  - [ ]* 9.11 Write property test for new membership notification query
    - **Property 11: New membership notification returns all recent memberships**
    - **Validates: Requirements 8.1, 8.2, 8.4**
  - [ ]* 9.12 Write property test for notification dismissal round-trip
    - **Property 12: Notification dismissal prevents re-showing**
    - **Validates: Requirements 8.3**

- [x] 10. Final checkpoint — Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise.

## Notes

- Tasks marked with `*` are optional and can be skipped for faster MVP
- Both `convex/convex/` and `sicario-frontend/convex/` must be kept in sync (tasks 1.2, 2.6, 4.2)
- Property tests use `fast-check` v4.1.1 + `vitest` in `convex/convex/__tests__/`
- Each task references specific requirements for traceability
- Checkpoints ensure incremental validation after each layer (backend → auth → frontend)

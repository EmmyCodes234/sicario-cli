# Requirements Document

## Introduction

The current "Add Member" flow in the Sicario dashboard requires admins to enter raw internal user IDs (Convex document IDs) to add members to an organization. This is a poor developer experience because admins rarely know these opaque identifiers. This feature replaces the User ID input with an email-based invite flow, allowing admins to invite team members by email address. If the email matches an existing Convex Auth user, the member is added immediately. If no matching user exists, a pending invitation record is created so the invitee can join upon signing up.

## Glossary

- **Invite_System**: The backend subsystem responsible for resolving email addresses to users, creating pending invitations, and accepting invitations upon user signup.
- **Admin**: A user with the "admin" role in an organization's membership, authorized to invite new members.
- **Invitee**: The person being invited to join an organization, identified by email address.
- **Pending_Invitation**: A record representing an invitation to a user who does not yet have an account in the system.
- **AddMember_Modal**: The frontend dialog component used by admins to invite members to an organization.
- **Auth_Users_Table**: The Convex Auth `users` table containing user records with optional `name` and `email` fields.
- **Memberships_Table**: The Convex `memberships` table storing user-to-organization role assignments.

## Requirements

### Requirement 1: Invite Member by Email Address

**User Story:** As an admin, I want to invite a member by entering their email address, so that I do not need to know their internal user ID.

#### Acceptance Criteria

1. WHEN an admin submits an email address in the AddMember_Modal, THE Invite_System SHALL look up the Auth_Users_Table for a user record matching that email address.
2. WHEN a matching user is found in the Auth_Users_Table, THE Invite_System SHALL create a membership record in the Memberships_Table linking that user to the organization with the specified role.
3. WHEN no matching user is found in the Auth_Users_Table, THE Invite_System SHALL create a Pending_Invitation record containing the email address, organization ID, assigned role, and team assignments.
4. WHEN the invitation is processed successfully, THE AddMember_Modal SHALL display a success notification indicating whether the member was added immediately or a pending invitation was created.
5. IF the email address is already associated with an existing membership in the organization, THEN THE Invite_System SHALL return an error indicating the user is already a member.
6. IF the email address matches an existing Pending_Invitation for the same organization, THEN THE Invite_System SHALL return an error indicating an invitation is already pending for that email.

### Requirement 2: Email Input Validation

**User Story:** As an admin, I want the email input to be validated before submission, so that I do not accidentally send invitations to malformed addresses.

#### Acceptance Criteria

1. WHEN an admin enters text into the email field, THE AddMember_Modal SHALL validate the input against a standard email format (local-part@domain).
2. IF the email input does not conform to a valid email format, THEN THE AddMember_Modal SHALL display an inline validation error and prevent form submission.
3. THE AddMember_Modal SHALL trim leading and trailing whitespace from the email input before validation and submission.

### Requirement 3: Pending Invitation Acceptance on Signup

**User Story:** As an invitee, I want to be automatically added to the organization when I sign up with the invited email address, so that I do not need a separate step to join.

#### Acceptance Criteria

1. WHEN a new user completes signup via Convex Auth (GitHub OAuth or Password provider), THE Invite_System SHALL query the Pending_Invitation records for any invitations matching the new user's email address.
2. WHEN one or more matching Pending_Invitation records are found, THE Invite_System SHALL create a membership record in the Memberships_Table for each matching invitation with the role and team assignments specified in the invitation.
3. WHEN a Pending_Invitation is successfully converted to a membership, THE Invite_System SHALL delete the Pending_Invitation record.
4. IF the membership creation fails during invitation acceptance, THEN THE Invite_System SHALL retain the Pending_Invitation record and log the error.

### Requirement 4: Pending Invitation Management

**User Story:** As an admin, I want to view and manage pending invitations, so that I can track who has been invited and revoke invitations if needed.

#### Acceptance Criteria

1. THE Invite_System SHALL provide a query that returns all Pending_Invitation records for a given organization, accessible only to admins.
2. WHEN an admin requests the list of pending invitations, THE Invite_System SHALL return each invitation's email address, assigned role, team assignments, and creation timestamp.
3. WHEN an admin revokes a Pending_Invitation, THE Invite_System SHALL delete the Pending_Invitation record from the database.
4. THE AddMember_Modal SHALL display pending invitations alongside existing members in the organization's settings page, visually distinguished with a "Pending" status indicator.

### Requirement 5: RBAC Enforcement for Invitations

**User Story:** As a system operator, I want invitation operations to enforce the same role-based access control as membership operations, so that only authorized admins can invite members.

#### Acceptance Criteria

1. THE Invite_System SHALL require the calling user to have the "admin" role in the target organization before creating an invitation.
2. THE Invite_System SHALL require the calling user to have the "admin" role in the target organization before revoking a Pending_Invitation.
3. IF a non-admin user attempts to create or revoke an invitation, THEN THE Invite_System SHALL return an "Access denied" error.

### Requirement 6: Invitation Data Model

**User Story:** As a developer, I want a well-defined schema for pending invitations, so that the data is consistent and queryable.

#### Acceptance Criteria

1. THE Invite_System SHALL store each Pending_Invitation with the following fields: invitation ID (unique string), email address, organization ID, role, team IDs (array), inviter user ID, and creation timestamp.
2. THE Invite_System SHALL index Pending_Invitation records by organization ID for efficient listing.
3. THE Invite_System SHALL index Pending_Invitation records by email address for efficient lookup during signup.
4. THE Invite_System SHALL enforce uniqueness of the (email, organization ID) pair across Pending_Invitation records.

### Requirement 7: Frontend Modal Replacement

**User Story:** As an admin, I want the Add Member modal to use an email field instead of a User ID field, so that the invite experience is intuitive.

#### Acceptance Criteria

1. THE AddMember_Modal SHALL replace the "User ID" text input with an "Email Address" text input.
2. THE AddMember_Modal SHALL retain the existing "Role" dropdown with options: admin, manager, developer.
3. THE AddMember_Modal SHALL retain the existing optional "Teams" multi-select dropdown.
4. WHEN the form is submitted, THE AddMember_Modal SHALL call the new invite mutation instead of the existing `memberships.create` mutation.
5. WHILE the invite mutation is in progress, THE AddMember_Modal SHALL display a loading state on the submit button and disable form inputs.

### Requirement 8: New Membership Notification Banner

**User Story:** As a user who has been added to an organization, I want to see a notification on the dashboard so that I know I've been added to a new org.

#### Acceptance Criteria

1. WHEN a user logs into the dashboard and has been added to one or more organizations since their last login (or since they last dismissed the notification), THE dashboard SHALL display a notification banner indicating the new org membership(s).
2. THE notification banner SHALL include the organization name and the role the user was assigned.
3. WHEN the user dismisses the notification banner, THE dashboard SHALL record the dismissal so the same notification is not shown again.
4. IF the user was added to multiple organizations, THE notification banner SHALL list all new memberships.
5. THE notification banner SHALL be displayed prominently at the top of the dashboard content area, styled consistently with the existing dashboard design system.

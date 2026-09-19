# ADR-0001: Establish rtp-bff as the server-side trust boundary

- Status: Accepted
- Review: Sascha Block
- Date: 2026-09-19

## Context

Rock the Prototype requires a web-based onboarding experience that will
integrate with Keycloak for authentication and identity capabilities.

The browser will eventually initiate authentication, registration,
email verification and onboarding interactions.

A browser-based architecture could expose OAuth/OIDC tokens directly to
frontend code and make the browser responsible for security-sensitive
session and token handling.

RTP also requires application-specific state that does not belong in
Keycloak, including onboarding state, qualification and persona-related
information.

## Decision

RTP will introduce `rtp-bff` as a Backend-for-Frontend and server-side
trust boundary between the browser and security-sensitive backend
capabilities.

The BFF will become the OAuth/OIDC client from the application's
perspective.

The intended authentication architecture is based on Authorization Code
Flow with PKCE.

OAuth access tokens and refresh tokens will remain server-side.

The browser will interact with RTP through a hardened application
session rather than becoming the long-lived holder of OAuth tokens.

Keycloak remains responsible for IAM capabilities.

RTP-specific onboarding and persona state remains in the RTP application
domain.

## Rationale

### Reduce token exposure

Keeping OAuth tokens server-side reduces the number of environments in
which these credentials exist.

Browser JavaScript must not require direct access to refresh tokens or
backend credentials.

### Establish a clear trust boundary

The BFF provides one controlled point at which authentication state,
session state and future authorization decisions can be enforced.

### Separate IAM from application domain

Authentication state and onboarding state represent different concerns.

For example:

    email_verified = true

is identity-related evidence.

Whereas:

    onboarding_state = qualification_pending

is an RTP domain state.

Representing all application state as Keycloak roles, groups or claims
would unnecessarily couple RTP business logic to the IAM product.

### Support a frontend-specific API

The BFF can provide APIs shaped around the RTP user experience without
exposing internal service interfaces directly to the browser.

### Improve auditability

The server-side boundary makes future authentication transitions,
session creation and authorization decisions observable and testable at
one controlled component.

## Consequences

### Positive

- reduced browser exposure to OAuth tokens;
- stronger separation of concerns;
- centralized session management;
- frontend-specific API boundary;
- independently testable authentication behaviour;
- easier future integration of onboarding services.

### Costs

- an additional server-side component must be developed and operated;
- session state must be managed;
- the BFF becomes security-relevant infrastructure;
- availability of the frontend experience depends on the BFF.

These costs are accepted because the BFF is deliberately part of the RTP
security architecture rather than merely a convenience proxy.

## Security constraints

The BFF must not:

- embed secrets in source code;
- expose OAuth refresh tokens to browser JavaScript;
- expose administrative Keycloak interfaces;
- unnecessarily disclose infrastructure information;
- use the browser as the canonical authorization authority.

## Follow-up decisions

Separate ADRs will define at least:

- OIDC Authorization Code + PKCE implementation;
- server-side session management;
- secure cookie policy;
- Keycloak client configuration;
- onboarding state persistence;
- deployment and runtime isolation.
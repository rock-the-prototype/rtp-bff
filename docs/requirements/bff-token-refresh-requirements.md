# BFF Token Refresh Requirements

- **Status:** Proposed
- **Date:** 2026-09-26
- **Component:** `rtp-bff`
- **Related decision:** ADR-0005 — Server-side OAuth Token Refresh Lifecycle

## Purpose

This document defines the normative requirements for resolving a usable OAuth access token from an authenticated BFF session.

The refresh lifecycle is entirely server-side. The browser remains bound only to the opaque BFF session cookie and never participates in OAuth token refresh.

## Terminology

- **BFF session:** The authenticated server-side session stored in the private Redis session store.
- **Access token (AT):** OAuth access token used by the BFF when calling an allowed resource server.
- **Refresh token (RT):** OAuth refresh token stored only inside the BFF trust boundary.
- **Refresh ownership:** Temporary exclusive right to perform a refresh-token exchange for one BFF session.
- **Refresh window:** Bounded interval before AT expiry during which the BFF may proactively refresh.
- **Authorization Server (AS):** The OAuth/OIDC Authorization Server used by `rtp-bff`; currently Keycloak in the RTP architecture.

## Normative requirements

### REQ-BFF-REFRESH-001 — Server-side refresh only

OAuth token refresh MUST be performed exclusively by `rtp-bff` on the server side.

The browser MUST NOT perform a refresh-token grant.

### REQ-BFF-REFRESH-002 — OAuth token secrecy

Access tokens and refresh tokens MUST NOT be exposed to the browser.

Access tokens, refresh tokens, client secrets, Authorization headers, and refresh request bodies MUST NOT be emitted in application logs, tracing fields, panic output, or browser-visible error responses.

### REQ-BFF-REFRESH-003 — Reuse sufficiently valid access token

If the current access token is outside the configured refresh window, the BFF MUST reuse it and MUST NOT contact the Authorization Server token endpoint.

### REQ-BFF-REFRESH-004 — Confidential refresh-token grant

If refresh is required and a refresh token is available, the BFF MUST call the configured Authorization Server token endpoint using the OAuth refresh-token grant.

The BFF MUST authenticate to the token endpoint as the configured confidential OAuth client.

### REQ-BFF-REFRESH-005 — Refresh-token rotation

If the Authorization Server returns a new refresh token, the BFF MUST replace the previously stored refresh token with the new value.

If the Authorization Server does not return a new refresh token, the BFF MUST retain the existing refresh token.

### REQ-BFF-REFRESH-006 — Persist before use

A refreshed access token MUST be persisted to the authenticated BFF session before it is considered usable by downstream application logic.

The persisted state MUST include:

- the refreshed access token;
- the refreshed access-token expiry;
- the rotated refresh token when one is returned.

The update MUST preserve the previous refresh token when no rotated refresh token is returned.

### REQ-BFF-REFRESH-007 — Serialize concurrent refresh

Concurrent refresh attempts for the same BFF session MUST be serialized.

At most one concurrent request for the same BFF session may perform a refresh-token exchange.

A request that does not own the refresh operation MUST NOT independently use the same refresh token against the Authorization Server.

### REQ-BFF-REFRESH-008 — Ownership-safe refresh lock

Refresh ownership MUST use a bounded lease and a unique owner value.

Lock release MUST verify ownership atomically.

A stale owner MUST NOT be able to delete a refresh lock that has expired and has been acquired by another request.

### REQ-BFF-REFRESH-009 — Reauthentication on unusable refresh grant

If refresh is required but no refresh token is available, the BFF MUST treat the session as requiring reauthentication.

If the Authorization Server rejects the refresh grant as invalid or unusable, including `invalid_grant`, the authenticated BFF session MUST be invalidated and MUST no longer authorize application requests.

### REQ-BFF-REFRESH-010 — Temporary upstream failure

Authorization Server network failures, timeouts, and temporary server failures MUST fail closed for the current request.

A temporary upstream failure MUST NOT expose stale or refreshed OAuth token material to the browser.

A temporary upstream failure does not by itself require invalidation of an otherwise valid BFF session.

### REQ-BFF-REFRESH-011 — Redis failure

A Redis failure during refresh ownership, session lookup, refresh persistence, or required invalidation MUST fail closed.

If refreshed token state cannot be safely persisted, the refreshed access token MUST NOT be returned to downstream application logic as a successfully resolved token.

### REQ-BFF-REFRESH-012 — Authenticated-session TTL is not sliding

Token refresh MUST NOT extend or reset the authenticated BFF session TTL.

The remaining session lifetime after refresh MUST be less than or equal to the remaining session lifetime before the refresh persistence step, subject only to elapsed time.

### REQ-BFF-REFRESH-013 — Do not recreate expired session

A refresh persistence operation MUST update only an authenticated-session key that still exists.

If the authenticated BFF session expires while a refresh is in progress, the BFF MUST NOT recreate the session when the Authorization Server response arrives.

The result MUST require reauthentication or otherwise fail closed.

### REQ-BFF-REFRESH-014 — No browser-facing refresh endpoint

`rtp-bff` MUST NOT expose a browser-facing endpoint whose purpose is to submit or retrieve OAuth refresh tokens or explicitly trigger a browser-controlled refresh-token grant.

In particular, this slice SHALL NOT introduce `/auth/refresh`.

### REQ-BFF-REFRESH-015 — Bounded refresh window

The BFF MAY refresh an access token before absolute expiry.

Any refresh skew MUST be bounded and centrally configured or defined.

The refresh window MUST NOT affect the authenticated BFF session TTL.

### REQ-BFF-REFRESH-016 — Separation from proxy responsibilities

The token-refresh component MUST expose an internal result that lets later proxy code distinguish at least:

- a usable access token;
- reauthentication required;
- temporary unavailability.

The proxy layer MUST NOT need to perform refresh-token grant logic itself.

## Non-functional constraints

### NFR-BFF-REFRESH-001 — Horizontal scaling readiness

Refresh coordination MUST remain correct when more than one BFF replica operates against the same Redis session store.

### NFR-BFF-REFRESH-002 — Bounded waiting

A request waiting for another request to complete refresh MUST use bounded waiting/backoff.

The BFF MUST NOT wait indefinitely for refresh ownership.

### NFR-BFF-REFRESH-003 — Testability

The Authorization Server interaction MUST be testable against a controllable local/mock token endpoint.

Redis-specific concurrency, persistence, and TTL semantics MUST be covered by Redis-backed integration tests.

## Out of scope

The following are not part of this requirement set:

- resource-server proxying;
- bearer injection;
- destination allowlisting;
- proxy header sanitization;
- CSRF protection for authenticated application calls;
- logout;
- IAM, federation, WebAuthn, EUDI, BundID, credential issuance, identity linking, or application-profile logic.

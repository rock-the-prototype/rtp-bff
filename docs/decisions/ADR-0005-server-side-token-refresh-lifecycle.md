# ADR-0005 — Server-side OAuth Token Refresh Lifecycle

- **Status:** Proposed
- **Date:** 2026-09-26
- **Review:** Sascha Block
- **Scope:** `rtp-bff` authenticated-session and OAuth token lifecycle

## Context

`rtp-bff` establishes a browser-facing BFF session after a successful OIDC Authorization Code Flow with PKCE.

The browser receives only an opaque BFF session cookie. OAuth access tokens and refresh tokens remain inside the BFF trust boundary and are stored in the private Redis-backed authenticated-session store.

The authenticated-session slice already provides:

- server-side storage of access and refresh tokens;
- an opaque browser session identifier;
- Redis-backed session resolution;
- explicit `401`, `204`, and `503` session-status outcomes;
- `Cache-Control: no-store` on authentication-state responses;
- non-sliding authenticated-session TTL semantics;
- Redis-backed evidence that session reads do not extend the session TTL.

The next required capability is access-token renewal without exposing OAuth token material to the browser and without turning token refresh into a second browser-visible authentication protocol.

A refresh operation also introduces concurrency risk. Multiple application requests may arrive after the same access token has expired or entered its refresh window. If all requests independently use the same refresh token, refresh-token rotation at the Authorization Server can cause one request to invalidate the token state used by another request.

## Decision

OAuth access-token renewal is exclusively a server-side BFF operation.

The browser MUST NOT receive, store, submit, or explicitly refresh OAuth access tokens or refresh tokens.

`rtp-bff` MUST NOT expose a browser-facing `/auth/refresh` endpoint.

The BFF resolves the authenticated session from Redis and determines whether the current access token is still sufficiently valid. If so, the existing access token is reused without contacting the Authorization Server.

If refresh is required and a refresh token is available, the BFF performs the OAuth refresh-token grant server-to-server against the configured Authorization Server token endpoint and authenticates as the confidential OAuth client.

A successful refresh updates the server-side authenticated session before the refreshed access token is considered usable.

If the Authorization Server returns a rotated refresh token, the new refresh token replaces the previous refresh token. If no new refresh token is returned, the existing refresh token is retained.

Refresh processing MUST NOT extend the authenticated BFF session lifetime.

A refresh update MUST NOT recreate a BFF session that expired while the refresh was in progress.

## Concurrency control

Concurrent refresh attempts for the same authenticated BFF session MUST be serialized.

Refresh ownership is coordinated through Redis so the rule remains valid when `rtp-bff` later runs with more than one replica.

The coordination key is logically separate from the authenticated-session key, for example:

```text
rtp:bff:refresh-lock:<session-id>
```

A refresh contender acquires ownership using a short, bounded Redis lease with a cryptographically random owner value.

Conceptually:

```text
SET rtp:bff:refresh-lock:<session-id> <owner-id> NX PX <bounded-lease>
```

Only the owner may perform the refresh-token exchange.

A request that does not acquire refresh ownership MUST NOT independently call the Authorization Server token endpoint. It must re-read the authenticated session after a bounded wait/backoff and use the refreshed access token if another request has already completed the refresh.

Lock release MUST verify ownership atomically. A stale owner MUST NOT be able to delete a lease that has expired and has subsequently been acquired by another request.

The implementation may use an atomic Redis script or an equivalent Redis primitive for compare-and-delete semantics.

## Session update semantics

The refresh result is persisted only into an existing authenticated-session record.

The update MUST:

- replace the access token;
- update the access-token expiry;
- replace the refresh token only when the Authorization Server returns a new refresh token;
- retain the existing refresh token when no replacement is returned;
- preserve the remaining authenticated-session TTL;
- fail if the authenticated-session key no longer exists.

The session update MUST NOT reset the Redis TTL to the configured full session lifetime.

## Failure semantics

### Refresh token unavailable

If refresh is required but the authenticated session contains no refresh token, the result is reauthentication-required.

### Authorization Server rejects the refresh token

An OAuth refresh rejection that represents an invalid or unusable refresh grant, including `invalid_grant`, transitions the BFF session to an unauthenticated state.

The invalid authenticated session MUST no longer be usable for application requests.

### Temporary Authorization Server failure

Network failures, timeouts, and temporary Authorization Server failures do not become browser-visible OAuth errors.

The BFF fails closed for the current application request and reports a temporary server-side failure through its internal error mapping.

A temporary upstream failure does not by itself require destruction of an otherwise valid BFF session.

### Redis failure

If refresh ownership, session re-read, session persistence, or required session invalidation cannot be completed because Redis is unavailable, the BFF fails closed.

A refreshed access token that cannot be safely persisted MUST NOT be returned to downstream application logic as a successfully resolved token.

## Token secrecy

Access tokens, refresh tokens, client secrets, authorization headers, and refresh-token request bodies are security material.

They MUST NOT:

- be returned to the browser;
- appear in application logs;
- appear in error responses;
- appear in tracing fields;
- be included in panic or debug output.

Token-carrying types SHOULD avoid derived debug representations unless their debug output is explicitly redacted.

## Internal result model

The refresh lifecycle should expose a small internal outcome model to later BFF proxy code.

The intended semantic outcomes are:

```text
Ready
ReauthenticationRequired
TemporarilyUnavailable
```

The exact Rust type is an implementation decision, but proxy code must not need to understand refresh-token handling.

## Refresh window

The BFF may refresh an access token shortly before its absolute expiry to avoid sending a token that will expire during downstream processing.

The refresh skew MUST be bounded and configurable or centrally defined. It MUST NOT change the authenticated BFF session lifetime.

No concrete skew duration is mandated by this ADR.

## Security properties

This decision preserves the following properties:

1. OAuth tokens remain outside the browser.
2. The browser interacts only through the opaque BFF session.
3. Refresh-token rotation cannot be raced by concurrent requests for the same BFF session.
4. Redis remains the authoritative private store for BFF token state.
5. Refresh does not turn the authenticated session into a sliding session.
6. An expired BFF session cannot be recreated by a late refresh write.
7. Authorization Server and Redis failures fail closed.
8. The later resource proxy can request a usable access token without handling refresh-token protocol details.

## Consequences

### Positive

- Browser attack surface remains independent of OAuth token renewal.
- Refresh-token rotation is compatible with concurrent application traffic.
- The design remains suitable for horizontal BFF scaling.
- Token lifecycle logic remains separated from browser handlers and later proxy code.
- Session lifetime remains explicit and auditable.

### Costs

- Redis coordination is required around refresh operations.
- Concurrency and failure handling require dedicated tests.
- Refresh persistence must preserve TTL atomically and must detect expired sessions.
- Integration tests require a real Redis instance and a controllable mock Authorization Server.

## Out of scope

This ADR does not introduce:

- resource-server proxying;
- bearer-token injection into downstream requests;
- proxy destination allowlisting;
- request/response header sanitization;
- CSRF protection for authenticated application requests;
- logout;
- migration of authorization-transaction state to Redis;
- EUDI, BundID, federation, identity linking, credential issuance, or IAM logic.

Those concerns remain separate slices.

## Related decisions

- ADR-0001 — BFF trust boundary
- ADR-0002 — Browser-bound OIDC Authorization Transactions
- ADR-0003 — OIDC security profile and deployment boundary
- ADR-0004 — Redis-backed BFF session boundary

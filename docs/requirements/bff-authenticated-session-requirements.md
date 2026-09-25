# Authenticated BFF Session Requirements

Status: Draft
Component: `rtp-bff`
Related ADR: `ADR-0004-redis-backed-bff-session-boundary`

## Security Objective

After a successful OIDC Authorization Code flow, the browser MUST receive only
an opaque BFF session identifier. OAuth access tokens, refresh tokens, client
credentials, and other server-side security material MUST remain outside the
browser and inside the BFF trust boundary.

## Requirements

### REQ-BFF-SESSION-001 — Session creation after validated authentication

An authenticated BFF session MUST only be created after successful authorization
code exchange and successful ID-token validation.

### REQ-BFF-SESSION-002 — Opaque unpredictable session identifier

Each authenticated BFF session MUST use a newly generated cryptographically
random session identifier. The identifier MUST NOT encode the access token,
refresh token, Keycloak user identifier, or other application-domain data.

### REQ-BFF-SESSION-003 — Server-side token association

The access token and any issued refresh token MUST be associated with the BFF
session in the server-side Redis session store.

The browser MUST NOT receive those tokens.

### REQ-BFF-SESSION-004 — Minimal stored state

The initial authenticated-session record MUST contain only the state required for
OAuth token mediation:

- access token;
- optional refresh token;
- optional access-token expiry timestamp.

Generic Keycloak session metadata MUST NOT be duplicated without a demonstrated
BFF requirement.

### REQ-BFF-SESSION-005 — Cookie security

For production HTTPS deployments, the authenticated session cookie MUST be
`Secure` and `HttpOnly`, SHOULD use `SameSite=Strict`, SHOULD use `Path=/`,
SHOULD NOT set a `Domain` attribute, and SHOULD use the `__Host-Http-` prefix.

### REQ-BFF-SESSION-006 — Bounded lifetime

Each Redis authenticated-session record MUST have a bounded TTL. The browser
cookie lifetime MUST not outlive the configured server-side BFF session TTL.

### REQ-BFF-SESSION-007 — Fail closed on session-store failure

If the BFF cannot persist the authenticated session after successful token
exchange, it MUST NOT issue an authenticated browser-session cookie.

### REQ-BFF-SESSION-008 — Store isolation

The Redis BFF session store MUST remain a private dependency of `rtp-bff`.
Neither browser clients nor Keycloak require direct access to this store for the
BFF session mechanism.

### REQ-BFF-SESSION-009 — Authenticated session resolution

The BFF MUST provide a check-session endpoint that resolves the presented
opaque BFF session identifier against the private server-side session store.

The endpoint MUST return:

- `204 No Content` when an active authenticated session exists;
- `401 Unauthorized` when no authenticated BFF session exists;
- `503 Service Unavailable` when the session store cannot be queried.

The endpoint MUST NOT expose access tokens, refresh tokens, client credentials,
or other server-side OAuth security material to the browser.

Session lookup MUST NOT extend the configured server-side session TTL.

### REQ-BFF-SESSION-010 — Authentication-state responses are not cacheable

Every response from the check-session endpoint MUST include:

`Cache-Control: no-store`

Authentication-state responses MUST NOT be reusable from browser or
intermediary caches.

## Acceptance Criteria

| ID | Requirement | Scenario | Expected observation |
|---|---|---|---|
| AC-BFF-SESSION-001 | REQ-001/002/003 | Successful OIDC callback | New opaque session ID is created and tokens are associated server-side |
| AC-BFF-SESSION-002 | REQ-003 | Inspect browser-visible callback response | Access and refresh tokens are absent |
| AC-BFF-SESSION-003 | REQ-004 | Inspect stored test session | Only access token, optional refresh token and optional AT expiry are modeled |
| AC-BFF-SESSION-004 | REQ-005 | Build production session cookie | `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, no `Domain`, `__Host-Http-` prefix |
| AC-BFF-SESSION-005 | REQ-006 | Persist session | Session has bounded store TTL and cookie max-age does not exceed it |
| AC-BFF-SESSION-006 | REQ-007 | Session-store write fails | Callback fails and no authenticated session cookie is issued |
| AC-BFF-SESSION-007 | REQ-BFF-SESSION-009 | Check session without cookie | `401 Unauthorized` |
| AC-BFF-SESSION-008 | REQ-BFF-SESSION-009 | Check active stored session | `204 No Content` |
| AC-BFF-SESSION-009 | REQ-BFF-SESSION-009 | Check unknown/stale session | `401 Unauthorized` |
| AC-BFF-SESSION-010 | REQ-BFF-SESSION-009 | Session-store read fails | `503 Service Unavailable` |
| AC-BFF-SESSION-011 | REQ-BFF-SESSION-010 | Inspect all check-session responses | `Cache-Control: no-store` is present |

## Evidence Mapping

Each acceptance criterion MUST ultimately link to an automated procedure/test,
its observation, validation result, source commit, CI execution, and released
artifact digest.

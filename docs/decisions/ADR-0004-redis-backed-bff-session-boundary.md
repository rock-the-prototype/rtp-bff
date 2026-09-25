# ADR-0004: Redis-backed authenticated BFF session boundary

- Status: Proposed
- Date: 2026-09-24
- Review: Sascha Block
- Scope: `rtp-bff`
- Related: ADR-0001, ADR-0002, ADR-0003, RFC 10017 §6.1

## Context

`rtp-bff` already acts as the confidential OAuth/OIDC client and performs the
Authorization Code flow with PKCE. After a successful code exchange, Keycloak
returns the OAuth access token and, when issued, the refresh token to the BFF.

RFC 10017 requires a BFF to associate those tokens with a cookie-based user
session while preventing direct token exposure to the browser.

Keycloak maintains its own authorization-server user and client sessions. Those
sessions are not the BFF's application session and do not remove the OAuth
client's need to hold the tokens issued to it.

RTP deliberately keeps the application BFF outside the Keycloak runtime to
reduce blast radius and avoid coupling application proxy traffic and BFF state
to the IAM process.

## Decision

The authenticated RTP browser session is owned by `rtp-bff`.

The BFF will use a dedicated Redis instance as the server-side authenticated
session store.

The browser receives only a cryptographically random opaque session identifier.
OAuth access tokens and refresh tokens are stored only in the BFF-side session
store and are never returned to browser JavaScript.

The production authenticated-session cookie MUST use:

- `Secure`;
- `HttpOnly`;
- `SameSite=Strict`;
- `Path=/`;
- no `Domain` attribute;
- the `__Host-Http-` cookie-name prefix.

A loopback HTTP development profile MAY use a different cookie name without
`Secure`; that exception MUST NOT be used for production deployment.

The Redis record contains only BFF OAuth-client state currently required for
subsequent API mediation:

- access token;
- refresh token, when one was issued;
- access-token expiry information, when provided by the token endpoint.

The BFF MUST NOT duplicate Keycloak user-session metadata such as generic user
session creation timestamps or last-activity timestamps solely because Keycloak
already maintains such IAM session state.

The Redis session key MUST have a bounded TTL. The configured BFF session
lifetime is a deployment security policy and should not exceed the usable
lifetime of the associated refresh-token context.

If the authenticated session cannot be written to Redis, authentication MUST
fail closed: the BFF MUST NOT issue an authenticated browser-session cookie.

Authenticated-session lookup is performed by the BFF against the private Redis
session store. Lookup MUST NOT refresh the Redis TTL.

The browser-facing check-session response MUST use `Cache-Control: no-store`
for every outcome so that authentication state cannot be reused from browser
or intermediary caches.

## Isolation boundary

Redis is a private dependency of `rtp-bff`, not a Keycloak datastore.

The intended trust relationships are:

```text
Browser ----> rtp-bff ----> Keycloak
                 |
                 +--------> Redis
```

and not:

```text
Browser ----> Redis
Keycloak ---> Redis
Redis ------> Keycloak
```

Deployment controls MUST ensure that the browser cannot reach Redis directly.
Keycloak does not require Redis credentials for this BFF session store. Redis
does not receive Keycloak administrative credentials.

Whether Redis persistence, replication, TLS, Unix sockets, or another transport
profile is used is a separate deployment decision. Any persistence of the Redis
session data must treat the stored OAuth tokens as sensitive bearer credentials.

## Rationale

This separation deliberately creates an additional security boundary. A failure
or compromise of the BFF session store must not automatically become a failure
of Keycloak's persistent IAM database or Keycloak runtime, and application API
proxy traffic does not execute inside the IAM process.

A dedicated server-side session store also keeps the OAuth tokens out of the
browser while allowing explicit session invalidation and later horizontal BFF
scaling.

## Consequences

Positive:

- OAuth tokens remain outside the browser;
- Keycloak and BFF session state remain separate security domains;
- no BFF proxy implementation is loaded into the Keycloak process;
- session invalidation can be controlled by the BFF;
- Redis TTL provides bounded session retention;
- BFF replicas can later share authenticated-session state.

Costs:

- Redis becomes security-relevant infrastructure;
- Redis availability affects authenticated application sessions;
- Redis must be isolated and monitored;
- token refresh must later update the Redis record atomically;
- pending authorization transactions remain process-local until separately
  migrated to shared storage.

## Non-goals

This ADR does not define:

- the refresh-token lifecycle implementation;
- the resource-server proxy;
- CSRF protection for authenticated API calls;
- logout;
- Redis high availability or persistence policy;
- EUDI, BundID, credential issuance, identity federation, profile, skill,
  qualification, contribution, reputation, or matching state.

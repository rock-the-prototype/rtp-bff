# ADR-0003: OIDC Security Profile and Deployment Boundary

## Status

Accepted

## Date

2026-09-23

## Context

The current RTP BFF implementation provides the browser-bound OIDC
authorization-transaction slice of the target Backend-for-Frontend
architecture.

The implementation separates normative protocol requirements from the
currently selected RTP deployment and security profile.

RFC 10017 requires the BFF to act as a confidential OAuth client. The
standard does not require one specific confidential-client authentication
mechanism for every deployment.

OpenID Connect requires validation of ID-token signatures and relevant token
claims. The protocol requirement itself does not make the RTP deployment
profile synonymous with one particular signing algorithm.

The current authorization-transaction store is process-local. Atomic
browser-binding verification and one-time transaction consumption are
therefore guaranteed within one BFF process, but pending transactions are
not shared across processes or preserved across process restarts.

These distinctions must be explicit so that implementation choices are not
mistaken for universal RFC or OIDC requirements and so that future scaling or
security-profile changes do not silently weaken the existing guarantees.

## Decision

### Authorization-transaction deployment boundary

The current authorization-transaction store remains process-local.

The current deployment therefore MUST run exactly one RTP BFF application
replica.

An authorization request and its callback MUST be handled by the same BFF
process.

A BFF process restart intentionally invalidates all pending authorization
transactions. A browser whose transaction was pending during a restart MUST
start a new authorization flow.

Horizontal scaling MUST NOT be enabled while authorization transactions are
stored process-locally.

Before multiple BFF replicas are permitted, the process-local transaction
store MUST be replaced by shared storage providing:

- atomic browser-bound lookup-and-take semantics;
- one-time consumption under concurrent callbacks;
- TTL enforcement equivalent to the authorization-transaction TTL;
- consistent visibility across BFF replicas.

### Confidential-client authentication profile

The RTP BFF MUST act as a confidential OAuth client.

The current RTP deployment profile uses `client_secret_basic` for token
endpoint client authentication.

The client secret MUST remain inside the BFF trust boundary and MUST NOT be
exposed to the browser.

The current profile MUST send the client secret using HTTP Basic client
authentication and MUST NOT place the client secret in the token-request
form body.

`client_secret_basic` is an RTP deployment-profile decision, not a universal
RFC 10017 requirement.

A future change to another suitable confidential-client authentication
mechanism requires an explicit architecture/configuration decision but does
not change the generic requirement that the BFF acts as a confidential
client.

### ID-token signing profile

The BFF MUST validate the ID-token signature and the required issuer,
audience, nonce and temporal properties before accepting authentication.

The current RTP security profile accepts ES256
(`ECDSA using P-256 and SHA-256`) for ID-token signatures.

The configured OpenID Provider, currently Keycloak, MUST use a signing
configuration compatible with this profile.

ES256 is an RTP security-profile decision. It MUST NOT be represented as a
generic requirement of RFC 10017 or OpenID Connect.

A future change of the accepted signing profile requires an explicit
architecture/configuration decision and corresponding validation evidence.

## Rationale

The process-local authorization-transaction store is sufficient for the
current single-replica implementation slice and already provides atomic
one-time consumption and bounded transaction lifetime.

Introducing distributed storage solely in anticipation of future horizontal
scaling would add operational and failure-mode complexity without being
required by the current deployment.

Constraining the current deployment to one BFF replica makes the existing
guarantees explicit while preserving a clear prerequisite for future
horizontal scaling.

Separating confidential-client authentication from the current
`client_secret_basic` profile prevents an implementation-specific choice from
becoming an accidental protocol requirement.

Separating ID-token signature validation from the current ES256 profile
serves the same purpose and keeps future cryptographic agility possible.

## Consequences

The current RTP BFF deployment is limited to exactly one application replica
while authorization transactions are process-local.

A process restart invalidates pending authorization transactions. This is a
fail-closed behavior; affected browsers must start a new login transaction.

Horizontal scaling requires shared authorization-transaction storage with
atomic take and TTL semantics before additional BFF replicas may be enabled.

The Keycloak signing configuration MUST remain compatible with the current
ES256 security profile.

The configured token-endpoint client-authentication mechanism MUST remain
compatible with the current `client_secret_basic` profile.

Changes to the client-authentication or ID-token-signing profile require
updated configuration, tests and architectural evidence.

OAuth access tokens, refresh tokens, client credentials and other
server-side security material MUST remain inside the BFF trust boundary.

This ADR does not introduce the final authenticated browser session,
server-side access/refresh-token association, resource-server proxy, token
refresh lifecycle or logout behavior. Those capabilities belong to later
RFC-10017 implementation slices.

## Validation

The current implementation is validated by automated tests covering:

- confidential-client token exchange using `client_secret_basic`;
- rejection of client secrets placed in the token-request form body;
- browser-bound authorization transactions;
- atomic one-time transaction consumption;
- transaction expiration;
- callback replay rejection;
- PKCE validation;
- OIDC nonce validation;
- ID-token signature validation;
- ES256 signing-policy enforcement;
- JWKS refresh and signing-key rotation;
- absence of OAuth tokens and client credentials from browser-visible
  responses.

The project quality gate additionally requires formatting, compilation,
Clippy with warnings denied, automated tests, build completion and
`git diff --check` to succeed.

## Scope

This ADR governs the current OIDC authorization-transaction implementation
slice.

It does not claim that the complete RFC-10017 Backend-for-Frontend target
architecture is already implemented.

Authenticated browser sessions, session cookies, token/session association,
resource-server proxying, refresh-token lifecycle and logout remain explicit
future architecture increments.
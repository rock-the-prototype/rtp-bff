# ADR-0002: Browser-bound OIDC Authorization Transactions

- Status: Proposed
- Date: 2026-09-21
- Review: Sascha Block
- Scope: rtp-bff
- Related: ADR-0001 BFF Trust Boundary

## Context

The RTP BFF implements the OpenID Connect Authorization Code Flow with PKCE.

For each authorization request, the BFF currently maintains server-side pending state containing:

- OAuth/OIDC `state`
- PKCE verifier
- OIDC nonce
- transaction creation time
- client IP used for abuse protection

The `state` value identifies an authorization transaction, but possession of `state` alone does not prove that the callback is being presented by the browser that initiated the authorization request.

This becomes security-critical once the BFF establishes an authenticated browser session after a successful callback.

Without browser binding, an authorization response initiated in one browser could be presented from another browser. When combined with subsequent session creation, this can result in login CSRF / session swapping.

Client IP addresses are not suitable as browser identity because they may be shared or change due to NAT, reverse proxies, mobile networks, or IPv6 address changes.

## Decision

Each OIDC authorization transaction MUST be bound to the browser that initiated it.

The BFF MUST create an independent cryptographically random browser-binding secret when `/auth/login` is initiated.

The browser-binding secret MUST be transported in a short-lived pre-authentication cookie.

The server MUST associate the authorization transaction with a representation of that browser-binding secret.

The callback MUST verify the browser binding before:

1. consuming the authorization transaction;
2. exchanging the authorization code;
3. creating any authenticated browser session.

The OAuth/OIDC `state` parameter and browser-binding secret MUST be independent values.

## Authorization Transaction

The application-domain security object is named:

`AuthorizationTransaction`

It contains at least:

- transaction identifier / OAuth `state`
- PKCE verifier
- OIDC nonce
- browser-binding representation
- creation time
- expiration information
- client IP for abuse protection

The client IP is explicitly not part of the browser identity proof.

## Browser Binding

The browser receives a short-lived pre-authentication cookie containing an independently generated random secret.

Conceptually:

Browser:

`rtp-preauth = B`

Server:

`state S -> AuthorizationTransaction(binding = H(B), ...)`

On callback:

1. resolve transaction using `state`;
2. obtain the pre-authentication cookie;
3. verify that the cookie corresponds to the transaction binding;
4. atomically consume the transaction;
5. continue with authorization-code exchange and token validation.

A callback with a missing or incorrect browser binding MUST NOT consume the transaction.

## Cookie Policy

For production, the pre-authentication cookie MUST be:

- `HttpOnly`
- `Secure`
- short-lived
- scoped as narrowly as practical
- without a `Domain` attribute

`SameSite=Lax` is selected for the pre-authentication cookie because the OIDC authorization response returns through a top-level navigation from an external Identity Provider.

The final authenticated BFF session cookie is a separate security object and may use a stricter cookie policy.

Local loopback development MAY omit `Secure` only while an explicitly permitted HTTP loopback redirect URI is used.

## Transaction Lifecycle

The lifecycle is:

`pending -> consumed`

or:

`pending -> expired`

A consumed or expired transaction MUST never become pending again.

Successful callbacks, legitimate OIDC error callbacks, and expiration all terminate the transaction.

A callback with an invalid browser binding does not terminate a valid transaction.

## Atomicity

Browser-binding verification and transaction consumption MUST be performed atomically with respect to competing callback requests.

For two concurrent callbacks referencing the same authorization transaction, at most one callback may proceed to authorization-code exchange.

## Alternatives Considered

### OAuth/OIDC state only

Rejected.

`state` identifies the transaction but is itself presented in the callback request and does not independently prove browser continuity.

### Client IP binding

Rejected.

Client IP addresses are neither stable nor unique browser identifiers.

They remain useful for rate limiting and abuse detection only.

### User-Agent binding

Rejected.

User-Agent values are not secret, are easily reproducible, and do not provide meaningful browser possession proof.

### Server-side browser binding using an HttpOnly cookie

Accepted.

It provides an independent browser-held secret that can be associated with the server-side authorization transaction without exposing the value to application JavaScript.

## Consequences

Positive:

- authorization responses become bound to the initiating browser;
- future BFF session creation is protected against login CSRF / session swapping;
- transaction identity and abuse detection remain separate concerns;
- browser binding becomes independently testable;
- the behavior can produce explicit machine-readable security evidence.

Costs:

- an additional short-lived cookie is required;
- authorization transaction state becomes slightly richer;
- callback processing must distinguish invalid binding from transaction completion;
- local loopback HTTP requires a deliberate development exception.

## Evidence

The decision MUST be demonstrated through automated acceptance tests covering at least:

- valid browser binding;
- missing browser binding;
- incorrect browser binding;
- callback replay;
- concurrent callback attempts;
- OIDC error callback;
- transaction expiration.

The resulting CI observations MUST be usable as evidence for the corresponding requirements and acceptance criteria.
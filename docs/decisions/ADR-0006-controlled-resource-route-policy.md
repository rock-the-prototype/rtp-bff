# ADR-0006 — Controlled Resource Route Policy

- **Status:** Proposed
- **Date:** 2026-09-28
- **Component:** `rtp-bff`
- **Primary source:** RFC 10017
- **Related:** ADR-0007
- **Requirements:** `docs/requirements/bff-resource-proxy-requirements.md`

## Context

`rtp-bff` is the OAuth client for the browser application and keeps OAuth access and refresh tokens outside the browser.

RFC 10017 requires the BFF to proxy resource requests in a way that does not turn the BFF into an open proxy and does not allow an attacker to influence the destination to which a user's access token is sent.

A destination may change operationally through scaling, load balancing, failover, or service discovery. The security decision should therefore target a stable logical resource identity rather than one instance IP.

The authenticated session store is not the authority for outbound routing.

## Decision

`rtp-bff` will use a dedicated **Resource Route Policy Registry**.

A browser-visible application route maps to a logical route identifier. The identifier resolves against one immutable, validated policy snapshot to:

- approved `https` scheme;
- approved logical host;
- approved port;
- approved path template;
- explicit HTTP methods;
- explicit path-parameter constraints;
- explicit query-parameter allowlist;
- explicit request/response header policy.

Example:

```text
GET /api/projects/{id}
          |
          v
    projects.read
          |
          v
scheme        = https
host          = projects-api.example.invalid
port          = 443
path_template = /v1/projects/{id}
methods       = GET, HEAD
id            = UUID
```

The example host is fictitious documentation data.

## Meaning of "fixed"

"Fixed" means fixed by the currently active trusted route-policy snapshot.

It does **not** mean permanently hard-coded in source, tied to one physical node, tied to one ephemeral IP address, configurable by the browser, or configurable by authenticated user session state.

A later trusted control plane may replace the snapshot if replacement is authenticated, authorized, completely validated, auditable, atomic, and fail-closed.

## Outbound TLS decision

Production Resource Server routes use HTTPS.

Before an access token is sent, the BFF MUST have:

1. resolved an approved route;
2. validated method/path/query constraints;
3. constructed the target from trusted components;
4. selected the approved logical host and port.

The outbound HTTP client MUST verify the Resource Server certificate and hostname according to the configured trust anchors and MUST NOT follow redirects automatically.

The BFF MUST NOT weaken certificate verification to make an upstream route work.

## Security invariants

1. Unknown route => deny.
2. Browser/session input cannot select scheme, host, port, or absolute URL.
3. Production scheme is HTTPS.
4. HTTP methods are explicitly allowed.
5. Dynamic path values are explicitly validated.
6. Query parameters are denied unless allowed.
7. URLs are built from parsed trusted components, not raw string concatenation.
8. Browser `Authorization` is never authoritative for upstream authorization.
9. BFF session cookies are never forwarded to Resource Servers.
10. Access-token injection occurs only after destination authorization.
11. Resource-server TLS certificate and hostname verification remain enabled.
12. Upstream redirects are not automatically followed.
13. Upstream `Set-Cookie` is not returned unchanged to the browser.
14. Route-policy update is authenticated, validated, atomic, and fail-closed.
15. Resource Server authorization remains independent and authoritative.
16. Tokens, credentials, private routing data, and secrets are not logged.

## Scaling decision

The allowlist identifies a stable logical service endpoint such as a trusted DNS/service-discovery name or an internal load balancer.

Horizontal scale changes nodes behind that logical identity. It does not grant the browser new routing authority and normally does not change the BFF route contract.

## Consequences

### Positive

- prevents open-proxy behavior;
- prevents browser-controlled token exfiltration;
- separates session state from routing authority;
- supports horizontal scaling;
- preserves a stable browser API;
- enables deterministic policy tests before network I/O exists.

### Costs

- every proxied application operation needs explicit policy;
- policy distribution is security-sensitive;
- service discovery and network enforcement remain separate operational controls.

## Deferred

- dynamic control-plane technology;
- mTLS/DPoP sender-constrained access tokens;
- mutation methods and their CSRF boundary;
- service mesh / workload identity.

## References

- RFC 10017: <https://www.rfc-editor.org/rfc/rfc10017.html>

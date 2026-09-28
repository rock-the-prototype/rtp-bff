# BFF Controlled Resource Proxy Requirements

- **Status:** Proposed
- **Date:** 2026-09-28
- **Component:** `rtp-bff`
- **Decision:** ADR-0006
- **Related ingress decision:** ADR-0007

## Security objective

The BFF proxies authenticated requests only to explicitly approved Resource Servers and prevents browser/session-controlled values from selecting where a server-side OAuth access token is sent.

## Requirements

### REQ-BFF-PROXY-001 — Default-deny route resolution
Every proxied request MUST match an active Resource Route Policy entry before an upstream request is created.

### REQ-BFF-PROXY-002 — No browser-selected upstream URL
Browser input MUST NOT supply or override upstream scheme, host, port, or absolute URL.

### REQ-BFF-PROXY-003 — Session store is not routing authority
Authenticated session state MUST NOT define or override upstream routing.

### REQ-BFF-PROXY-004 — Explicit logical destination allowlist
Every route MUST identify an approved logical Resource Server host and port.

### REQ-BFF-PROXY-005 — HTTPS-only production route
Production Resource Server routes MUST use HTTPS.

### REQ-BFF-PROXY-006 — Verified upstream TLS
The outbound client MUST verify the Resource Server certificate chain and hostname using configured trust anchors. Verification MUST NOT be disabled as a routing workaround.

### REQ-BFF-PROXY-007 — Stable logical service identity
Policy SHOULD target controlled DNS/service discovery/load-balancer identity, not an ephemeral instance IP.

### REQ-BFF-PROXY-008 — Explicit method allowlist
Every route MUST define allowed methods. The initial slice permits only GET and HEAD.

### REQ-BFF-PROXY-009 — Constrained path templates
Dynamic path segments MUST be server-defined and explicitly validated. Traversal, encoded separators, URI schemes, authority delimiters, and invalid values MUST be rejected.

### REQ-BFF-PROXY-010 — Query allowlist
Query parameters are denied by default and allowed only explicitly.

### REQ-BFF-PROXY-011 — Safe URL construction
The outbound URL MUST be built from parsed trusted components and validated dynamic values, never raw browser-controlled URL concatenation.

### REQ-BFF-PROXY-012 — Route authorization before token resolution
Destination/method/path/query authorization MUST complete before the BFF resolves or injects an OAuth access token for the upstream request.

### REQ-BFF-PROXY-013 — Existing token lifecycle is authoritative
`AccessTokenResolution::Ready` permits proxy execution. `ReauthenticationRequired` and `TemporarilyUnavailable` prevent upstream contact.

### REQ-BFF-PROXY-014 — Browser Authorization is not upstream authority
Inbound browser `Authorization` MUST NOT be forwarded and MUST NOT influence the server-side access token.

### REQ-BFF-PROXY-015 — Server-side Bearer injection
For bearer tokens, outbound `Authorization: Bearer` MUST be created solely from the server-side token-resolution result after route authorization.

### REQ-BFF-PROXY-016 — Session cookie confinement
The BFF authenticated-session cookie MUST NOT be forwarded to Resource Servers.

### REQ-BFF-PROXY-017 — Request-header filtering
At minimum the BFF MUST control/remove `Authorization`, `Cookie`, `Connection`, `Proxy-Authorization`, `Proxy-Authenticate`, `TE`, `Trailer`, `Transfer-Encoding`, and `Upgrade`.

### REQ-BFF-PROXY-018 — Redirects are not followed
The outbound client MUST NOT automatically follow Resource Server redirects.

### REQ-BFF-PROXY-019 — Response-header filtering
Upstream `Set-Cookie` and hop-by-hop response headers MUST NOT be forwarded unchanged to the browser.

### REQ-BFF-PROXY-020 — No secret leakage
OAuth tokens, client credentials, session identifiers, private route policy, and upstream authorization material MUST NOT appear in browser-visible responses or routine logs/telemetry.

### REQ-BFF-PROXY-021 — Policy snapshot validation
Candidate snapshots MUST be completely validated before activation.

### REQ-BFF-PROXY-022 — Atomic policy activation
Requests MUST observe one complete old or new snapshot, never a partial update.

### REQ-BFF-PROXY-023 — Fail closed on policy update failure
Failed retrieval/authentication/parsing/validation/activation MUST NOT activate partial policy.

### REQ-BFF-PROXY-024 — Trusted policy administration
Only an authenticated/authorized administrative mechanism may replace policy. Browser/user sessions MUST NOT possess that capability.

### REQ-BFF-PROXY-025 — Policy auditability
Active policy MUST have a stable non-secret version/digest.

### REQ-BFF-PROXY-026 — Resource Server authorization remains authoritative
Successful BFF routing MUST NOT replace Resource Server token validation or authorization.

### REQ-BFF-PROXY-027 — Read-only first slice
Until mutation/CSRF requirements exist, unlisted/state-changing methods MUST be rejected.

# Inbound Reverse Proxy Requirements

- **Status:** Proposed
- **Date:** 2026-09-28
- **Decision:** ADR-0007
- **Components:** reverse proxy, Keycloak, `rtp-bff`

## Security objective

Public traffic reaches Keycloak and `rtp-bff` only through a controlled ingress that preserves TLS confidentiality/integrity on every network hop and owns the proxy-derived HTTP metadata trusted by backend services.

## Requirements

### REQ-INGRESS-001 — TLS re-encrypt production profile
The production profile MUST terminate public TLS at the trusted reverse proxy and establish a separate TLS connection to the backend.

### REQ-INGRESS-002 — No plaintext backend hop
Edge termination with plaintext HTTP from the public proxy to Keycloak or `rtp-bff` MUST NOT be used in the RTP production profile.

### REQ-INGRESS-003 — Backend certificate verification
The reverse proxy MUST verify backend certificate chain and hostname using configured trust anchors. Verification MUST NOT be disabled.

### REQ-INGRESS-004 — Direct backend bypass prevention
Public clients MUST NOT be able to directly reach Keycloak backend or BFF backend listeners.

### REQ-INGRESS-005 — One explicit proxy-header family
Keycloak MUST parse only the configured trusted proxy-header family. The current profile uses `xforwarded`.

### REQ-INGRESS-006 — Forwarded headers are overwritten
The reverse proxy MUST overwrite trusted `X-Forwarded-*` values from connection facts. Browser-supplied values MUST NOT be appended/trusted.

### REQ-INGRESS-007 — Trusted proxy addresses
Keycloak SHOULD restrict accepted proxy headers to deployment-private trusted proxy IPs/CIDRs using `proxy-trusted-addresses`, in addition to network isolation.

### REQ-INGRESS-008 — Identity-affecting header filtering
The proxy MUST strip or own headers that could influence identity resolution, access control, proxy routing, or trusted client metadata. At minimum this includes external values for `X-Original-Forwarded-For`, `X-Real-IP`, `X-Original-URL`, `X-Original-Method`, and `X-Forwarded-Access-Token`.

### REQ-INGRESS-009 — Untrusted tracing context filtering
External distributed tracing/baggage headers MUST be stripped unless an explicit trusted tracing propagation policy is defined.

### REQ-INGRESS-010 — Explicit Keycloak public path policy
The proxy MUST expose only explicitly required Keycloak public paths.

### REQ-INGRESS-011 — Administrative Keycloak paths stay private
`/admin/` and the administrative realm protocol path (normally `/realms/master/`) MUST NOT be exposed on the public listener.

### REQ-INGRESS-012 — Keycloak management port stays private
Keycloak management port `9000`, including health/metrics, MUST NOT be proxied to the public network.

### REQ-INGRESS-013 — Explicit BFF public path policy
Only explicitly intended browser/application BFF routes may be exposed publicly. Operational endpoints such as `/health` remain private unless separately designed.

### REQ-INGRESS-014 — Backend applications remain independently defensive
Neither Keycloak nor BFF security MUST rely solely on ingress filtering. Backend validation remains mandatory.

### REQ-INGRESS-015 — Passthrough configuration is prohibited in re-encrypt profile
`proxy-protocol-enabled` MUST NOT be enabled as a substitute for the selected re-encrypt header model. `proxy-headers` and PROXY-protocol profiles MUST not be mixed.

### REQ-INGRESS-016 — X.509 requirement triggers ADR review
Native client X.509 authentication directly at Keycloak MUST trigger review of ADR-0007 before proxy-header certificate forwarding is introduced.

### REQ-INGRESS-017 — No public production topology/secrets in repository
Production backend names, private addresses/CIDRs, certificates/private keys, trusted proxy addresses, and real route policy instances MUST remain deployment-private.

### REQ-INGRESS-018 — TLS/route failures fail closed
If backend TLS verification, route matching, or trusted-header construction fails, the reverse proxy MUST NOT fall back to a less secure route/profile.

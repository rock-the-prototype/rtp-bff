# Inbound Reverse Proxy Acceptance Criteria

- **Status:** Proposed
- **Date:** 2026-09-28
- **Decision:** ADR-0007

| ID | Requirement | Scenario | Expected observation |
|---|---|---|---|
| AC-INGRESS-001 | REQ-001/002 | Public request to Keycloak | TLS exists client→proxy and proxy→Keycloak |
| AC-INGRESS-002 | REQ-001/002 | Public request to BFF | TLS exists client→proxy and proxy→BFF |
| AC-INGRESS-003 | REQ-003 | Backend certificate invalid/untrusted | Proxy fails closed |
| AC-INGRESS-004 | REQ-003 | Backend hostname mismatch | Proxy fails closed |
| AC-INGRESS-005 | REQ-004 | Attempt direct public Keycloak backend connection | Network path is unavailable |
| AC-INGRESS-006 | REQ-004 | Attempt direct public BFF backend connection | Network path is unavailable |
| AC-INGRESS-007 | REQ-005/006 | Client injects X-Forwarded-For/Proto/Host/Port | Backend observes proxy-generated values, not client values |
| AC-INGRESS-008 | REQ-007 | Proxy headers arrive from non-trusted source | Keycloak does not trust them |
| AC-INGRESS-009 | REQ-008 | Client sends identity-affecting proxy headers | They are stripped/overwritten before backend |
| AC-INGRESS-010 | REQ-009 | Client sends traceparent/baggage/B3/Jaeger headers | They are stripped unless explicit trusted policy exists |
| AC-INGRESS-011 | REQ-010 | Request required OIDC/discovery/static public path | Allowed according to explicit proxy route |
| AC-INGRESS-012 | REQ-011 | Public request `/admin/` | Not routed to public Keycloak admin surface |
| AC-INGRESS-013 | REQ-011 | Public request `/realms/master/` | Not routed to administrative realm |
| AC-INGRESS-014 | REQ-012 | Public request to Keycloak port 9000/health/metrics | Not publicly routable |
| AC-INGRESS-015 | REQ-013 | Public request to BFF `/health` | Not publicly routable in default profile |
| AC-INGRESS-016 | REQ-014 | Ingress omits a defense-in-depth filter in backend unit test | Backend still enforces its own security invariant |
| AC-INGRESS-017 | REQ-015 | Re-encrypt configuration inspected | `xforwarded`/trusted-address profile is used; no PROXY-protocol mix |
| AC-INGRESS-018 | REQ-016 | X.509 direct-client-auth requirement introduced | ADR-0007 is reopened before implementation |
| AC-INGRESS-019 | REQ-017 | Scan public repository examples | No production host/IP/secret/trusted-address values |
| AC-INGRESS-020 | REQ-018 | Backend TLS or route config fails | No plaintext/fallback backend route is attempted |

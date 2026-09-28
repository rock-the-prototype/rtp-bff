# ADR-0007 — Inbound Reverse Proxy TLS Trust Boundary

- **Status:** Proposed
- **Date:** 2026-09-28
- **Components:** Keycloak, `rtp-bff`, inbound reverse proxy
- **Primary source:** Keycloak — Configuring a reverse proxy
- **Related:** ADR-0006
- **Requirements:** `docs/requirements/inbound-reverse-proxy-requirements.md`

## Context

RTP exposes Keycloak and `rtp-bff` through an infrastructure reverse proxy.

Keycloak documents three common TLS modes:

1. **TLS re-encrypt** — proxy terminates client TLS and establishes a separate TLS connection to Keycloak;
2. **edge termination** — proxy terminates TLS and uses plaintext HTTP to Keycloak;
3. **TLS passthrough** — proxy forwards the raw TLS connection so the TLS handshake occurs directly between the client and Keycloak.

The architecture needs encryption on every network hop, HTTP-layer path filtering, trustworthy forwarding headers, the ability to keep Keycloak administrative/management surfaces private, and a clean path to future horizontal scaling. There is currently no requirement for native browser/client X.509 certificate authentication directly at Keycloak.

## Decision

The RTP production target uses **TLS re-encrypt** at the inbound reverse-proxy boundary.

```text
Client --TLS A--> trusted reverse proxy --TLS B--> Keycloak
                                     \
                                      --TLS C--> rtp-bff
```

The proxy and backend services use independently validated certificates.

Edge termination with a plaintext backend hop is not the target architecture.

TLS passthrough is not selected for the current requirements because it removes the proxy's ability to inspect HTTP, overwrite forwarding headers, and filter public URL paths.

## Why re-encrypt

Keycloak identifies re-encrypt as the common production choice because it preserves TLS on both sides of the proxy, allows the proxy to set/overwrite forwarding headers, allows public-path filtering, permits HTTP-layer policy/routing, and allows separate public and backend certificates.

Those properties are directly required by the RTP ingress boundary.

## Forwarded-header trust

For the Keycloak re-encrypt profile:

- Keycloak parses exactly one selected proxy-header family;
- the current RTP profile uses `xforwarded`;
- the reverse proxy MUST overwrite `X-Forwarded-*` values with values derived from the actual proxy connection;
- browser-supplied forwarding headers MUST NOT be appended or trusted;
- Keycloak SHOULD use `proxy-trusted-addresses` for the actual trusted proxy addresses/CIDRs as defense in depth;
- network controls MUST prevent arbitrary clients from bypassing the proxy and connecting directly to Keycloak.

`proxy-trusted-addresses` is not a substitute for network isolation.

## Header filtering

The proxy MUST prevent external clients from controlling headers that affect identity resolution, access control, or observability.

For the Keycloak ingress this includes, at minimum:

- overwrite `Forwarded` / `X-Forwarded-*` according to the selected family;
- strip `X-Original-Forwarded-For`;
- strip `X-Real-IP` unless a backend explicitly requires a proxy-generated value and that exception is documented;
- strip `X-Original-URL`;
- strip `X-Original-Method`;
- strip `X-Forwarded-Access-Token`;
- strip external distributed-tracing/baggage headers unless an explicit trusted tracing boundary is designed.

## Keycloak path exposure

The public proxy MUST use an explicit path policy.

Publicly required Keycloak paths include the protocol/discovery/static-resource surfaces needed by the deployment, such as:

- `/realms/` except the administrative realm;
- `/resources/`;
- `/.well-known/`.

The following are not public in the RTP profile:

- `/admin/`;
- `/realms/master/` (assuming the administrative realm retains the default name);
- Keycloak management port `9000`;
- management `/health` and `/metrics`.

The Keycloak guide recommends not proxying port `9000`.

## Direct-backend bypass

Network policy MUST ensure that the public network cannot directly reach the Keycloak backend port or the BFF backend listener.

This is required because a direct client could otherwise bypass path/header controls and could attempt to forge proxy-derived headers.

## BFF ingress

The same re-encrypt principle applies to `rtp-bff`:

```text
Browser --TLS--> reverse proxy --TLS--> rtp-bff
```

The public proxy exposes only explicit BFF browser/application routes. Operational endpoints such as `/health` remain private unless a separate controlled health path is intentionally designed.

The BFF MUST still enforce its own application security controls even when the reverse proxy filters requests. Proxy filtering is defense in depth, not an authorization substitute.

## X.509 client certificate trigger

If RTP later requires native X.509 client-certificate authentication at Keycloak, this ADR MUST be revisited.

Keycloak recommends TLS passthrough for that case because the client certificate reaches Keycloak directly, avoiding security-sensitive certificate forwarding in an HTTP header.

If passthrough is selected in a future ADR:

- `--proxy-headers` MUST NOT be configured;
- PROXY protocol may be used for original client IP;
- `--proxy-protocol-enabled` and `--proxy-headers` are mutually exclusive;
- network access must still be restricted to the proxy;
- graceful-shutdown timing must account for TCP/TLS keepalive draining;
- Keycloak certificate SAN requirements must be re-evaluated.

## Scaling

The reverse proxy/load balancer may distribute traffic across multiple Keycloak nodes.

Keycloak documents sticky sessions as an optional performance optimization for clustered deployments. They are not mandatory for correctness and are not the security basis of this ADR.

For dynamic reverse-proxy addresses, the deployment MUST NOT solve the problem by trusting an overly broad network range. Use a stable trusted proxy layer, appropriate network segmentation, or another deployment-specific trusted identity/control and revisit the trusted-address configuration.

## Consequences

### Positive

- public and backend hops are both encrypted;
- the proxy can enforce public path restrictions;
- forwarded-header provenance is controlled;
- backend services can be hidden from direct public access;
- public/backend certificates can be managed independently;
- the design remains compatible with horizontal scaling.

### Costs

- backend TLS certificates and trust anchors must be operated;
- TLS verification failures become deployment failures, as intended;
- proxy header and path policy require explicit tests;
- native X.509 client authentication would require an ADR review.

## References

- Keycloak, Configuring a reverse proxy: <https://www.keycloak.org/server/reverseproxy>

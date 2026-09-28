# Proxy Trust Boundaries

**Status:** Proposed  
**Date:** 2026-09-28

## Purpose

RTP uses the word "proxy" for two technically different components. This document makes their trust boundaries explicit.

```text
                           PUBLIC NETWORK
                                |
                             HTTPS
                                |
                                v
                   +-------------------------+
                   | Inbound Reverse Proxy   |
                   | NGINX / LB              |
                   | TLS termination +       |
                   | TLS re-encryption       |
                   +------------+------------+
                                |
                     HTTPS      |      HTTPS
                    +-----------+-----------+
                    |                       |
                    v                       v
               +---------+              +---------+
               | Keycloak|              | rtp-bff |
               | IAM / AS |              | BFF     |
               +---------+              +----+----+
                                            |
                                            | HTTPS
                                            | Authorization: Bearer <AT>
                                            v
                                     +---------------+
                                     | Resource API  |
                                     +---------------+

                                      +-------------+
                                      | Redis       |
                                      | BFF-private |
                                      +-------------+
                                            ^
                                            |
                                         rtp-bff
```

Redis is a private dependency of the BFF and is not an inbound reverse-proxy target.

## Boundary A — inbound infrastructure reverse proxy

The inbound proxy protects public entry to Keycloak and `rtp-bff`.

Responsibilities include:

- terminate public TLS;
- establish a new verified TLS connection to the backend (**TLS re-encrypt**);
- route only explicitly public paths;
- overwrite trusted forwarding headers instead of accepting browser-supplied values;
- strip identity-, tracing-, or proxy-related headers that external clients must not control;
- prevent direct public bypass to backend service ports;
- keep Keycloak management port `9000`, management health/metrics, administrative paths, and the administrative realm off the public path;
- keep BFF operational/health endpoints off the public path unless a separate controlled operational path is deliberately designed.

This boundary is governed by ADR-0007.

## Boundary B — `rtp-bff` application-layer resource proxy

The BFF does not proxy arbitrary browser-supplied URLs. It maps one browser-visible application operation to a trusted Resource Route Policy entry.

Responsibilities include:

- default-deny unknown routes;
- approve destination scheme, logical host, port, path template, method, query parameters, and forwarded headers before token resolution;
- resolve/refresh the user's access token only after route authorization;
- never accept browser `Authorization` as the upstream authorization source;
- never forward the BFF session cookie to a Resource Server;
- inject the server-side OAuth access token only for the approved destination;
- use verified HTTPS for the Resource Server;
- never follow upstream redirects automatically;
- remove upstream `Set-Cookie` and hop-by-hop response headers;
- fail closed on policy, session-store, token-resolution, TLS, or upstream routing failures.

This boundary is governed by ADR-0006.

## Why route policy is not stored in the session store

The session store answers:

> Which authenticated BFF session and server-side OAuth material belong to this opaque browser session identifier?

The route policy answers:

> Which logical backend operation may this browser request cause?

Those are different authorities. Storing route authority in per-user session state would couple identity/session data to infrastructure policy and would make session manipulation capable of changing token destinations.

The BFF therefore uses a separate trusted Resource Route Policy Registry.

## Scaling

### Horizontal scaling

Horizontal scaling adds/removes service instances. The route policy points to a stable **logical service identity**, not to one ephemeral instance IP.

```text
projects-api.example.invalid
              |
              +--> 192.0.2.21
              +--> 192.0.2.22
              +--> 192.0.2.23
```

The addresses are reserved documentation data. A real deployment uses its private service-discovery/load-balancer mechanism outside the public repository.

### Keycloak clustering

Keycloak documents sticky sessions as optional, not mandatory, for clustered deployments. Affinity can improve performance because authentication/user session data may be locally owned in the distributed cache. This is an operational optimization rather than the security basis of the architecture.

## TLS termination modes at the Keycloak boundary

### Re-encrypt — selected target architecture

```text
Browser --TLS A--> Reverse Proxy --TLS B--> Keycloak
```

The proxy can inspect HTTP and can therefore overwrite `Forwarded` / `X-Forwarded-*`, filter URL paths, and enforce HTTP-layer policy. Both network hops remain encrypted.

### Edge termination — not selected

```text
Browser --TLS--> Reverse Proxy --HTTP--> Keycloak
```

The backend hop is plaintext. Keycloak's current reverse-proxy guide treats this as less secure than re-encrypt. It is not the RTP target architecture.

### TLS passthrough — explicitly deferred alternative

```text
Browser ----------------TLS----------------> Keycloak
                  via TCP proxy
```

The proxy cannot inspect or modify HTTP. Keycloak therefore MUST NOT use `--proxy-headers` in this mode. If the original client IP is required, Keycloak documents the PROXY protocol instead.

Passthrough is particularly relevant if native X.509 client-certificate authentication at Keycloak becomes a requirement because the client certificate reaches Keycloak directly instead of being asserted in an HTTP header.

Introducing that requirement MUST reopen ADR-0007.

## Layered Zero Trust interpretation

```text
Inbound route policy:
  May this public request reach this backend surface?

TLS:
  Is the network channel authenticated and confidential?

BFF Resource Route Policy:
  May this application operation target this logical resource service?

OAuth access token:
  What delegated authority is presented?

Resource Server:
  Is this token valid for this audience/scope and is this operation authorized?
```

No layer substitutes for another.

# Public Repository Publication Boundary

## Principle

Security does not depend on hiding architecture principles, threat mitigations, requirements, acceptance criteria, or test names.

## Safe to publish

- trust-boundary architecture;
- Redis as BFF session-store technology;
- server-side OAuth token handling principle;
- TLS re-encrypt vs passthrough decision rationale;
- selected proxy-header family (`xforwarded`) as an architectural profile;
- route-policy model and validation rules;
- Keycloak public/private path categories;
- acceptance criteria and test names;
- fictitious examples using reserved documentation values.

## Deployment-private

Do not publish:

- production/non-public hostnames;
- real internal IPs, CIDRs, service-discovery records, or topology;
- actual `proxy-trusted-addresses`;
- real production route-policy instances;
- Redis URLs/credentials;
- OAuth client secrets;
- access/refresh tokens or authenticated captures;
- TLS private keys or private signing keys;
- passwords/API keys/recovery secrets;
- private trust-store contents where disclosure is not intended;
- firewall/ACL data that exposes private topology;
- non-public administrative/control-plane endpoints;
- sensitive operational logs.

## Documentation values

Use:

- `example.invalid` for fictitious domains;
- `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` for IPv4 examples;
- `2001:db8::/32` for IPv6 examples.

## Integrity boundary

Production ingress policy and BFF route policy determine where trusted requests and access tokens may flow. Their modification requires authentication, authorization, validation, auditable versioning, and fail-closed activation.

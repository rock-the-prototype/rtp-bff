Decision

- current authorization transaction store is process-local
- current deployment therefore supports exactly one BFF replica
- process restart invalidates pending authorization transactions
- horizontal scaling requires shared atomic take + TTL storage

- RFC requirement is confidential-client authentication
- current RTP profile uses client_secret_basic

- RFC/OIDC requirement is signature validation
- current RTP crypto profile accepts ES256
- Keycloak configuration must conform to that profile
# OIDC Authorization Transaction Requirements

Status: Draft
Component: `rtp-bff`
Related ADR: `ADR-0002-browser-bound-oidc-authorization-transactions`

## Security Objective

An OIDC authorization response MUST only be accepted by the RTP BFF when it belongs to a valid, unexpired, single-use authorization transaction and is presented by the browser that initiated that transaction.

---

## Requirements

### REQ-OIDC-TXN-001 — Unique transaction material

Each authorization request MUST create new cryptographically random transaction material.

At minimum, each transaction MUST have independently generated:

- OAuth/OIDC `state`
- OIDC nonce
- PKCE verifier
- browser-binding secret

Transaction material MUST NOT be reused between authorization attempts.

---

### REQ-OIDC-TXN-002 — Browser binding

Each authorization transaction MUST be bound to the browser that initiated `/auth/login`.

Knowledge of `state` alone MUST NOT be sufficient to complete an authorization transaction.

---

### REQ-OIDC-TXN-003 — Browser-binding confidentiality

The browser-binding secret MUST NOT be readable by application JavaScript.

The production pre-authentication cookie MUST use:

- `HttpOnly`
- `Secure`
- no `Domain` attribute
- a limited lifetime

The cookie MUST use a path no broader than required by the authentication flow.

---

### REQ-OIDC-TXN-004 — Independent state and browser binding

OAuth/OIDC `state` and the browser-binding secret MUST be independent cryptographically random values.

The browser-binding secret MUST NOT be derived from `state`, nonce, or PKCE material.

---

### REQ-OIDC-TXN-005 — One-time use

An authorization transaction MUST be usable at most once.

After successful consumption, any replay using the same transaction identifier MUST be rejected.

---

### REQ-OIDC-TXN-006 — Atomic consumption

Browser-binding verification and transaction consumption MUST prevent multiple concurrent callbacks from successfully using the same transaction.

At most one callback MUST reach authorization-code exchange.

---

### REQ-OIDC-TXN-007 — Expiration

Authorization transactions MUST expire after a bounded period.

The current transaction lifetime is:

`300 seconds`

An expired transaction MUST NOT reach authorization-code exchange.

---

### REQ-OIDC-TXN-008 — OIDC error completion

A legitimate OIDC error callback with a valid transaction and correct browser binding MUST terminate the transaction.

Example:

`error=access_denied`

The completed transaction MUST no longer occupy a pending-login slot.

---

### REQ-OIDC-TXN-009 — Binding verification before consumption

A callback with a valid `state` but missing or incorrect browser binding MUST be rejected before transaction consumption.

The valid pending transaction MUST remain available to the correct initiating browser until it is consumed or expires.

---

### REQ-OIDC-TXN-010 — PKCE transaction binding

The authorization code MUST only be exchanged using the PKCE verifier belonging to the same authorization transaction.

---

### REQ-OIDC-TXN-011 — Nonce transaction binding

The ID Token MUST only be accepted when its nonce corresponds to the nonce stored for the same authorization transaction.

---

### REQ-OIDC-TXN-012 — Token validation

The BFF MUST validate security-relevant ID Token properties including at least:

- signature
- issuer
- audience / client
- nonce
- temporal validity
- signing key

A signing-key lookup failure caused by `NoMatchingKey` MAY trigger exactly one metadata/JWKS refresh and one subsequent verification attempt.

No unbounded verification retry MUST occur.

---

### REQ-OIDC-TXN-013 — Token confidentiality

OAuth access tokens, refresh tokens, and the OIDC client secret MUST remain server-side.

They MUST NOT be returned to the browser.

---

### REQ-OIDC-TXN-014 — IP independence

Client IP information MUST NOT be used as proof of browser identity.

Client IP MAY be used for:

- rate limiting
- abuse detection
- observability

---

## Acceptance Criteria

| ID | Requirement | Scenario | Expected observation |
|---|---|---|---|
| AC-OIDC-TXN-001 | REQ-001 | Start two login transactions | `state`, nonce, PKCE verifier, and browser binding differ |
| AC-OIDC-TXN-002 | REQ-002 | Correct browser presents callback | Callback proceeds |
| AC-OIDC-TXN-003 | REQ-002/003 | Callback contains no pre-auth cookie | Callback rejected; no token exchange |
| AC-OIDC-TXN-004 | REQ-002/009 | Browser B presents Browser A's callback | Callback rejected; transaction remains pending |
| AC-OIDC-TXN-005 | REQ-005 | Successful callback is replayed | Replay rejected |
| AC-OIDC-TXN-006 | REQ-006 | Two callbacks race for the same transaction | At most one reaches token exchange |
| AC-OIDC-TXN-007 | REQ-007 | Callback uses expired transaction | Callback rejected; no token exchange |
| AC-OIDC-TXN-008 | REQ-008 | `access_denied` with correct binding | HTTP error returned and transaction removed |
| AC-OIDC-TXN-009 | REQ-009 | Wrong binding supplied | Transaction is not consumed |
| AC-OIDC-TXN-010 | REQ-010 | Incorrect PKCE verifier | Token exchange fails |
| AC-OIDC-TXN-011 | REQ-011 | ID Token contains wrong nonce | Token rejected |
| AC-OIDC-TXN-012 | REQ-012 | ID Token signature invalid | Token rejected |
| AC-OIDC-TXN-013 | REQ-012 | Signing key is initially unknown | Metadata/JWKS refreshed exactly once |
| AC-OIDC-TXN-014 | REQ-012 | Rotated key exists after refresh | Token accepted after second verification |
| AC-OIDC-TXN-015 | REQ-012 | Key still unknown after refresh | Token rejected; no further refresh |
| AC-OIDC-TXN-016 | REQ-005 | Transaction already consumed | Callback rejected |
| AC-OIDC-TXN-017 | REQ-003 | Successful authentication completes | Pre-authentication cookie invalidated |
| AC-OIDC-TXN-018 | REQ-002 | Browser A starts login; Browser B presents code/state | Browser B cannot complete transaction |
| AC-OIDC-TXN-019 | REQ-013 | Inspect browser-visible response | No OAuth access token, refresh token, or client secret present |

---

## Evidence Mapping

Each acceptance criterion MUST ultimately be linked to:

1. an automated procedure/test;
2. its observation;
3. the resulting validation status;
4. the source commit;
5. the CI execution;
6. later, the released artifact digest.

Target evidence chain:

`Requirement -> Acceptance Criterion -> Procedure -> Observation -> Validation Result -> Evidence`

This mapping is intended to become compatible with the RTP/AIF artifact graph.
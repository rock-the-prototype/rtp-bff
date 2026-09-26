# BFF Token Refresh Acceptance Criteria

- **Status:** Proposed
- **Date:** 2026-09-26
- **Requirements:** `bff-token-refresh-acceptance-criteria.md`
- **Decision:** `docs/decisions/ADR-0005-server-side-oauth-token-refresh-lifecycle.md`

## Acceptance criteria

| ID | Requirement(s) | Scenario | Expected result |
|---|---|---|---|
| AC-BFF-REFRESH-001 | REQ-BFF-REFRESH-003 | Authenticated session contains an access token outside the refresh window | Existing access token is returned internally; token endpoint is not called |
| AC-BFF-REFRESH-002 | REQ-BFF-REFRESH-004, 006 | Access token requires refresh and a refresh token exists | BFF performs exactly one confidential refresh-token exchange and persists the refreshed access token before use |
| AC-BFF-REFRESH-003 | REQ-BFF-REFRESH-005 | Authorization Server returns a rotated refresh token | Redis session contains the new refresh token and no longer contains the previous refresh token |
| AC-BFF-REFRESH-004 | REQ-BFF-REFRESH-005 | Authorization Server omits a refresh token in the refresh response | Existing refresh token remains stored |
| AC-BFF-REFRESH-005 | REQ-BFF-REFRESH-006 | Refresh succeeds with an access-token lifetime | New access-token expiry is stored consistently with the refresh response |
| AC-BFF-REFRESH-006 | REQ-BFF-REFRESH-007, 008; NFR-BFF-REFRESH-001 | Two or more requests for the same session require refresh concurrently | Token endpoint observes at most one concurrent refresh exchange for that session |
| AC-BFF-REFRESH-007 | REQ-BFF-REFRESH-007; NFR-BFF-REFRESH-002 | Second request cannot acquire refresh ownership | Second request does not call token endpoint; it re-reads session state after bounded wait/backoff |
| AC-BFF-REFRESH-008 | REQ-BFF-REFRESH-008 | Refresh lock expires and another owner acquires it | Original/stale owner cannot delete the new owner's lock |
| AC-BFF-REFRESH-009 | REQ-BFF-REFRESH-009 | Refresh is required but session has no refresh token | Internal result is reauthentication-required; no token endpoint call occurs |
| AC-BFF-REFRESH-010 | REQ-BFF-REFRESH-009 | Token endpoint returns `invalid_grant` | Authenticated BFF session is invalidated and cannot authorize later requests |
| AC-BFF-REFRESH-011 | REQ-BFF-REFRESH-010 | Token endpoint times out or returns a temporary server failure | Current request fails closed as temporary failure; no OAuth token material is returned to browser |
| AC-BFF-REFRESH-012 | REQ-BFF-REFRESH-011 | Refresh succeeds at AS but Redis persistence fails | Refreshed token is not returned as successfully resolved; request fails closed |
| AC-BFF-REFRESH-013 | REQ-BFF-REFRESH-012 | Redis session has a shortened TTL before refresh | Successful refresh does not increase or reset the remaining BFF session TTL |
| AC-BFF-REFRESH-014 | REQ-BFF-REFRESH-013 | BFF session expires after refresh starts but before persistence | Refresh persistence does not recreate the session key |
| AC-BFF-REFRESH-015 | REQ-BFF-REFRESH-002 | Refresh succeeds or fails | Browser response, logs, traces, and errors contain no AT, RT, client secret, or Authorization header value |
| AC-BFF-REFRESH-016 | REQ-BFF-REFRESH-014 | Router is inspected after implementation | No browser-facing `/auth/refresh` route exists |
| AC-BFF-REFRESH-017 | REQ-BFF-REFRESH-015 | Access token enters configured refresh window | Refresh occurs according to the configured/central refresh skew without changing BFF session TTL |
| AC-BFF-REFRESH-018 | REQ-BFF-REFRESH-016 | Later caller requests a usable token | Internal API distinguishes usable-token, reauthentication-required, and temporary-failure outcomes without exposing refresh-token mechanics |

## Required automated evidence

### Unit/component tests

At minimum, automated tests SHOULD include equivalents of:

```text
valid_access_token_is_reused_without_refresh
expiring_access_token_is_refreshed
rotated_refresh_token_replaces_previous_value
missing_rotated_refresh_token_preserves_previous_value
missing_refresh_token_requires_reauthentication
invalid_grant_invalidates_authenticated_session
temporary_token_endpoint_failure_fails_closed
refresh_persistence_failure_fails_closed
no_browser_refresh_route_exists
```

### Concurrency tests

At minimum:

```text
concurrent_refresh_requests_reach_token_endpoint_at_most_once
refresh_waiter_reuses_token_written_by_owner
stale_refresh_owner_cannot_release_new_owner_lock
```

### Redis-backed integration tests

At minimum:

```text
refresh_update_preserves_remaining_session_ttl
refresh_update_does_not_recreate_expired_session
refresh_lock_is_exclusive
refresh_lock_release_requires_owner
```

These tests MUST exercise the Redis-backed production adapter or the same Redis primitives used by production.

### Authorization Server test double

Refresh tests MUST use a controllable local/mock token endpoint capable of producing at least:

- successful refresh with rotated refresh token;
- successful refresh without rotated refresh token;
- `invalid_grant`;
- temporary 5xx response;
- delayed response for concurrency tests.

The test double SHOULD record token-endpoint call count so AC-BFF-REFRESH-001 and AC-BFF-REFRESH-006 can be proven deterministically.

## Evidence mapping

| Evidence | Demonstrates |
|---|---|
| Rust unit/component tests | refresh decision logic, response classification, RT rotation semantics, no browser refresh route |
| Mock-AS tests | confidential refresh exchange, failure classification, call count |
| Redis integration tests | lock ownership, lock release, session update, non-sliding TTL, no expired-session recreation |
| Concurrency test | at-most-one refresh exchange per BFF session |
| `cargo clippy --all-targets --all-features -- -D warnings` | warning-free Rust implementation |
| `cargo test --locked` | deterministic repository test suite |
| `cargo build --locked` | reproducible dependency-locked build |
| GitHub Actions | repeatable PR evidence in CI |

## Merge gate for this slice

The slice is complete only when:

1. ADR-0005 is accepted and implementation matches the decision.
2. REQ-BFF-REFRESH-001 through REQ-BFF-REFRESH-016 are implemented or explicitly deferred with rationale.
3. AC-BFF-REFRESH-001 through AC-BFF-REFRESH-018 have automated evidence where technically applicable.
4. Redis-backed TTL and refresh-lock behavior are exercised in CI.
5. Concurrency evidence proves at most one refresh exchange per BFF session.
6. No OAuth token material is exposed to the browser.
7. No browser-facing `/auth/refresh` endpoint exists.
8. Existing OIDC, authenticated-session, and Redis integration tests remain green.
9. Formatting, Clippy, tests, and build quality gates pass.
10. Architecture and requirement documentation reflects the implemented behavior.

## Explicitly deferred to later slices

Passing this acceptance set does not require:

- resource-server proxy implementation;
- downstream Bearer injection;
- destination allowlist;
- proxy request/response header filtering;
- CSRF enforcement for authenticated application API calls;
- logout;
- authorization-transaction migration to Redis.

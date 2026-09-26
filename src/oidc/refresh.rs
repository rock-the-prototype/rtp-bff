use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openidconnect::{
    AuthType, ClientId, OAuth2TokenResponse, RefreshToken, RequestTokenError,
    core::{CoreClient, CoreErrorResponseType, CoreProviderMetadata},
};

use crate::session::{AuthenticatedSession, RefreshOwnedMutation, new_refresh_owner_id};

use super::{
    OidcState,
    provider::{OIDC_REQUEST_TIMEOUT, provider_metadata},
};

const ACCESS_TOKEN_REFRESH_SKEW: Duration = Duration::from_secs(30);

// Provider discovery is deliberately performed before refresh ownership is
// acquired. Therefore the refresh lease protects only the post-lock critical
// section: session re-read, token exchange, and atomic Redis mutation.
const REFRESH_OWNER_OPERATION_MARGIN_SECONDS: u64 = 10;
pub(super) const REFRESH_OWNER_OPERATION_TIMEOUT: Duration =
    Duration::from_secs(OIDC_REQUEST_TIMEOUT.as_secs() + REFRESH_OWNER_OPERATION_MARGIN_SECONDS);

// The owner operation is explicitly deadline-bounded below. The Redis lease
// must outlive that deadline so a second owner cannot legitimately acquire the
// same refresh token while the first owner's bounded critical section is still
// running.
const REFRESH_LOCK_MARGIN_SECONDS: u64 = 10;
pub(super) const REFRESH_LOCK_LEASE: Duration =
    Duration::from_secs(REFRESH_OWNER_OPERATION_TIMEOUT.as_secs() + REFRESH_LOCK_MARGIN_SECONDS);

// A waiter must tolerate the complete lease and a small observation margin.
// This avoids premature temporary failures while another healthy request owns
// the refresh operation.
const REFRESH_WAIT_MARGIN_SECONDS: u64 = 5;
pub(super) const REFRESH_WAIT_TIMEOUT: Duration =
    Duration::from_secs(REFRESH_LOCK_LEASE.as_secs() + REFRESH_WAIT_MARGIN_SECONDS);

const REFRESH_WAIT_INITIAL_DELAY: Duration = Duration::from_millis(25);
const REFRESH_WAIT_MAX_DELAY: Duration = Duration::from_millis(500);

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Ready payload is consumed by the controlled resource-proxy slice that follows token refresh"
    )
)]
pub(super) enum AccessTokenResolution {
    Ready(String),
    ReauthenticationRequired,
    TemporarilyUnavailable,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "consumed by the controlled resource-proxy slice that follows token refresh"
    )
)]
pub(super) async fn resolve_access_token(
    state: &OidcState,
    session_id: &str,
) -> AccessTokenResolution {
    let now = match unix_time_seconds() {
        Some(now) => now,
        None => return AccessTokenResolution::TemporarilyUnavailable,
    };

    resolve_access_token_at(state, session_id, now).await
}

pub(super) async fn resolve_access_token_at(
    state: &OidcState,
    session_id: &str,
    now: u64,
) -> AccessTokenResolution {
    // The monotonic origin is captured immediately at function entry. Every
    // later effective wall-clock value is derived from this single origin, so
    // session reads, provider discovery, lock acquisition, waiting and the
    // token request are all included in elapsed-time accounting.
    let operation_started_at = tokio::time::Instant::now();

    let initial = match state.session_store.get(session_id).await {
        Ok(Some(session)) => session,
        Ok(None) => return AccessTokenResolution::ReauthenticationRequired,
        Err(()) => return AccessTokenResolution::TemporarilyUnavailable,
    };

    if access_token_is_sufficiently_valid(&initial, effective_now(now, &operation_started_at)) {
        return AccessTokenResolution::Ready(initial.access_token);
    }

    if initial.refresh_token.is_none() {
        return AccessTokenResolution::ReauthenticationRequired;
    }

    // IMPORTANT: Provider discovery may itself wait behind another discovery
    // because provider_metadata() serializes cache population with a mutex.
    // Resolve metadata before refresh ownership is acquired so that such
    // contention can never consume the refresh lease.
    let metadata = match provider_metadata(state).await {
        Ok(metadata) => metadata,
        Err(_) => return AccessTokenResolution::TemporarilyUnavailable,
    };

    let owner_id = new_refresh_owner_id();
    let wait_started_at = tokio::time::Instant::now();
    let wait_deadline = wait_started_at + REFRESH_WAIT_TIMEOUT;
    let mut wait_delay = REFRESH_WAIT_INITIAL_DELAY;

    loop {
        let instant = tokio::time::Instant::now();

        if instant >= wait_deadline {
            return AccessTokenResolution::TemporarilyUnavailable;
        }

        // Start the owner budget before asking Redis for the lease. Redis begins
        // the lease when SET NX PX executes, while the client may observe the
        // successful response later. Starting our absolute deadline before the
        // acquisition attempt is conservative: any Redis/network/task delay
        // consumes owner budget instead of creating work time after lease expiry.
        let acquisition_attempt_started_at = tokio::time::Instant::now();
        let owner_deadline = refresh_owner_deadline(acquisition_attempt_started_at);

        match state
            .session_store
            .try_acquire_refresh_lock(session_id, &owner_id, REFRESH_LOCK_LEASE)
            .await
        {
            Ok(true) => {
                return refresh_with_ownership(
                    state,
                    session_id,
                    &owner_id,
                    &metadata,
                    now,
                    &operation_started_at,
                    owner_deadline,
                )
                .await;
            }
            Ok(false) => {
                let remaining =
                    wait_deadline.saturating_duration_since(tokio::time::Instant::now());

                if remaining.is_zero() {
                    return AccessTokenResolution::TemporarilyUnavailable;
                }

                tokio::time::sleep(std::cmp::min(wait_delay, remaining)).await;

                let current = match state.session_store.get(session_id).await {
                    Ok(Some(session)) => session,
                    Ok(None) => return AccessTokenResolution::ReauthenticationRequired,
                    Err(()) => return AccessTokenResolution::TemporarilyUnavailable,
                };

                if access_token_is_sufficiently_valid(
                    &current,
                    effective_now(now, &operation_started_at),
                ) {
                    return AccessTokenResolution::Ready(current.access_token);
                }

                if current.refresh_token.is_none() {
                    return AccessTokenResolution::ReauthenticationRequired;
                }

                wait_delay = std::cmp::min(
                    wait_delay.saturating_add(wait_delay),
                    REFRESH_WAIT_MAX_DELAY,
                );
            }
            Err(()) => return AccessTokenResolution::TemporarilyUnavailable,
        }
    }
}

async fn refresh_with_ownership(
    state: &OidcState,
    session_id: &str,
    owner_id: &str,
    metadata: &CoreProviderMetadata,
    base_now: u64,
    operation_started_at: &tokio::time::Instant,
    owner_deadline: tokio::time::Instant,
) -> AccessTokenResolution {
    // The absolute deadline was created before the Redis acquisition attempt.
    // If the successful lock response was delayed until after that deadline,
    // do not start owner work at all. Release what is still ours and fail closed.
    if owner_deadline_has_elapsed(owner_deadline, tokio::time::Instant::now()) {
        return release_refresh_lock(
            state,
            session_id,
            owner_id,
            AccessTokenResolution::TemporarilyUnavailable,
        )
        .await;
    }

    // Bound the complete post-acquisition critical section by the absolute
    // deadline that already includes Redis acquisition/response delay.
    let result = match tokio::time::timeout_at(
        owner_deadline,
        refresh_with_ownership_inner(
            state,
            session_id,
            owner_id,
            metadata,
            base_now,
            operation_started_at,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => AccessTokenResolution::TemporarilyUnavailable,
    };

    // Because the owner deadline started before lease acquisition and is
    // strictly shorter than REFRESH_LOCK_LEASE, the configured lease margin is
    // reserved for cancellation/cleanup and ownership-safe release.
    release_refresh_lock(state, session_id, owner_id, result).await
}

async fn release_refresh_lock(
    state: &OidcState,
    session_id: &str,
    owner_id: &str,
    result: AccessTokenResolution,
) -> AccessTokenResolution {
    match state
        .session_store
        .release_refresh_lock(session_id, owner_id)
        .await
    {
        Ok(true) => result,
        Ok(false) | Err(()) => AccessTokenResolution::TemporarilyUnavailable,
    }
}

async fn refresh_with_ownership_inner(
    state: &OidcState,
    session_id: &str,
    owner_id: &str,
    metadata: &CoreProviderMetadata,
    base_now: u64,
    operation_started_at: &tokio::time::Instant,
) -> AccessTokenResolution {
    let current = match state.session_store.get(session_id).await {
        Ok(Some(session)) => session,
        Ok(None) => return AccessTokenResolution::ReauthenticationRequired,
        Err(()) => return AccessTokenResolution::TemporarilyUnavailable,
    };

    // Re-read after acquiring the lock. Another request may have completed a
    // refresh between our initial read and lock acquisition.
    if access_token_is_sufficiently_valid(&current, effective_now(base_now, operation_started_at)) {
        return AccessTokenResolution::Ready(current.access_token);
    }

    let Some(refresh_token_value) = current.refresh_token.as_ref() else {
        return AccessTokenResolution::ReauthenticationRequired;
    };

    let client = CoreClient::from_provider_metadata(
        metadata.clone(),
        ClientId::new(state.config.client_id.clone()),
        Some(state.config.client_secret.clone()),
    )
    .set_auth_type(AuthType::BasicAuth);

    let refresh_token = RefreshToken::new(refresh_token_value.clone());
    let request = match client.exchange_refresh_token(&refresh_token) {
        Ok(request) => request,
        Err(_) => return AccessTokenResolution::TemporarilyUnavailable,
    };

    let token_response = match request.request_async(&state.http_client).await {
        Ok(response) => response,
        Err(RequestTokenError::ServerResponse(error))
            if matches!(error.error(), CoreErrorResponseType::InvalidGrant) =>
        {
            return invalidate_rejected_refresh(state, session_id, owner_id).await;
        }
        Err(_) => return AccessTokenResolution::TemporarilyUnavailable,
    };

    let access_token = token_response.access_token().secret().to_owned();
    let refresh_token = token_response
        .refresh_token()
        .map(|token| token.secret().to_owned())
        .or_else(|| current.refresh_token.clone());

    // Derive expiry from the same monotonic origin captured at
    // resolve_access_token_at() entry. This includes every measurable interval
    // since the supplied base timestamp: initial session read, provider
    // discovery, lock acquisition/waiting, post-lock read and token exchange.
    let response_now = effective_now(base_now, operation_started_at);
    let access_token_expires_at =
        refreshed_access_token_expiry(response_now, token_response.expires_in());

    let refreshed = AuthenticatedSession {
        access_token: access_token.clone(),
        refresh_token,
        access_token_expires_at,
    };

    match state
        .session_store
        .update_after_refresh(session_id, owner_id, &refreshed)
        .await
    {
        Ok(RefreshOwnedMutation::Applied) => AccessTokenResolution::Ready(access_token),
        Ok(RefreshOwnedMutation::SessionMissing) => AccessTokenResolution::ReauthenticationRequired,
        Ok(RefreshOwnedMutation::OwnershipLost) | Err(()) => {
            AccessTokenResolution::TemporarilyUnavailable
        }
    }
}

async fn invalidate_rejected_refresh(
    state: &OidcState,
    session_id: &str,
    owner_id: &str,
) -> AccessTokenResolution {
    match state
        .session_store
        .invalidate_for_refresh(session_id, owner_id)
        .await
    {
        Ok(RefreshOwnedMutation::Applied | RefreshOwnedMutation::SessionMissing) => {
            AccessTokenResolution::ReauthenticationRequired
        }
        Ok(RefreshOwnedMutation::OwnershipLost) | Err(()) => {
            AccessTokenResolution::TemporarilyUnavailable
        }
    }
}

fn access_token_is_sufficiently_valid(session: &AuthenticatedSession, now: u64) -> bool {
    let Some(expires_at) = session.access_token_expires_at else {
        // Without an expiry hint there is no safe threshold to calculate. Keep
        // the current token rather than refreshing on every application request.
        return true;
    };

    expires_at > now.saturating_add(ACCESS_TOKEN_REFRESH_SKEW.as_secs())
}

fn refreshed_access_token_expiry(now: u64, expires_in: Option<Duration>) -> Option<u64> {
    now.checked_add(expires_in?.as_secs())
}

fn refresh_owner_deadline(
    acquisition_attempt_started_at: tokio::time::Instant,
) -> tokio::time::Instant {
    acquisition_attempt_started_at + REFRESH_OWNER_OPERATION_TIMEOUT
}

fn owner_deadline_has_elapsed(
    owner_deadline: tokio::time::Instant,
    now: tokio::time::Instant,
) -> bool {
    now >= owner_deadline
}

fn effective_now(base_now: u64, operation_started_at: &tokio::time::Instant) -> u64 {
    effective_now_from_elapsed(base_now, operation_started_at.elapsed())
}

fn effective_now_from_elapsed(base_now: u64, elapsed: Duration) -> u64 {
    base_now.saturating_add(elapsed.as_secs())
}

fn unix_time_seconds() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

#[cfg(test)]
mod timing_tests {
    use super::*;

    #[test]
    fn owner_operation_deadline_is_shorter_than_refresh_lease() {
        assert!(
            REFRESH_OWNER_OPERATION_TIMEOUT < REFRESH_LOCK_LEASE,
            "the bounded owner critical section must complete before the Redis lease can expire"
        );
    }

    #[test]
    fn waiter_timeout_outlives_refresh_lease() {
        assert!(
            REFRESH_WAIT_TIMEOUT > REFRESH_LOCK_LEASE,
            "a healthy waiter must tolerate the complete refresh-owner lease"
        );
    }

    #[test]
    fn delay_after_acquisition_attempt_consumes_owner_budget() {
        let acquisition_attempt_started_at = tokio::time::Instant::now();
        let owner_deadline = refresh_owner_deadline(acquisition_attempt_started_at);

        let owner_work_before_deadline = acquisition_attempt_started_at
            + REFRESH_OWNER_OPERATION_TIMEOUT
            - Duration::from_millis(1);
        let owner_work_after_deadline = acquisition_attempt_started_at
            + REFRESH_OWNER_OPERATION_TIMEOUT
            + Duration::from_millis(1);

        assert!(
            !owner_deadline_has_elapsed(owner_deadline, owner_work_before_deadline),
            "owner work may proceed while the pre-acquisition deadline is still live"
        );
        assert!(
            owner_deadline_has_elapsed(owner_deadline, owner_work_after_deadline),
            "delay between the acquisition attempt and owner work must consume the owner budget"
        );
    }

    #[test]
    fn effective_now_accounts_for_measurable_elapsed_time() {
        assert_eq!(
            effective_now_from_elapsed(1_800_000_000, Duration::from_secs(7)),
            1_800_000_007
        );
    }
}

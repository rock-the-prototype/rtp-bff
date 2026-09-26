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
) -> AccessTokenResolution {
    // Hard end-to-end deadline for the complete critical section protected by
    // the Redis lease. This is strictly shorter than REFRESH_LOCK_LEASE.
    let result = match tokio::time::timeout(
        REFRESH_OWNER_OPERATION_TIMEOUT,
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

    // Lock release happens outside the owner-operation timeout, while the lease
    // still has REFRESH_LOCK_MARGIN_SECONDS of headroom.
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
    fn effective_now_accounts_for_measurable_elapsed_time() {
        assert_eq!(
            effective_now_from_elapsed(1_800_000_000, Duration::from_secs(7)),
            1_800_000_007
        );
    }
}

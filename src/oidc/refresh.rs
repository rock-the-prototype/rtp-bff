use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openidconnect::{
    AuthType, ClientId, OAuth2TokenResponse, RefreshToken, RequestTokenError,
    core::{CoreClient, CoreErrorResponseType},
};

use crate::session::{AuthenticatedSession, RefreshOwnedMutation, new_refresh_owner_id};

use super::{
    OidcState,
    provider::{OIDC_REQUEST_TIMEOUT, provider_metadata},
};

const ACCESS_TOKEN_REFRESH_SKEW: Duration = Duration::from_secs(30);

// Cold provider discovery performs two HTTP requests:
// 1. OpenID Provider Configuration
// 2. JWKS
//
// The refresh-token exchange adds one more HTTP request.
const COLD_PROVIDER_DISCOVERY_HTTP_REQUESTS: u64 = 2;
const TOKEN_REFRESH_HTTP_REQUESTS: u64 = 1;
const MAX_REFRESH_HTTP_REQUESTS: u64 =
    COLD_PROVIDER_DISCOVERY_HTTP_REQUESTS + TOKEN_REFRESH_HTTP_REQUESTS;

// The reqwest client applies OIDC_REQUEST_TIMEOUT to each HTTP request.
// Add explicit coordination headroom for Redis operations, scheduling and
// normal runtime jitter.
const REFRESH_COORDINATION_MARGIN_SECONDS: u64 = 10;
pub(super) const REFRESH_OPERATION_BOUND_SECONDS: u64 = OIDC_REQUEST_TIMEOUT.as_secs()
    * MAX_REFRESH_HTTP_REQUESTS
    + REFRESH_COORDINATION_MARGIN_SECONDS;

// The lease must outlive the complete bounded refresh operation.
const REFRESH_LOCK_MARGIN_SECONDS: u64 = 5;
pub(super) const REFRESH_LOCK_LEASE: Duration =
    Duration::from_secs(REFRESH_OPERATION_BOUND_SECONDS + REFRESH_LOCK_MARGIN_SECONDS);

// A waiter must tolerate the complete owner lease before declaring temporary
// unavailability. The extra margin lets it observe a just-completed owner
// update or acquire the expired lease itself.
const REFRESH_WAIT_MARGIN_SECONDS: u64 = 5;
pub(super) const REFRESH_WAIT_TIMEOUT: Duration = Duration::from_secs(
    REFRESH_OPERATION_BOUND_SECONDS + REFRESH_LOCK_MARGIN_SECONDS + REFRESH_WAIT_MARGIN_SECONDS,
);

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
    let initial = match state.session_store.get(session_id).await {
        Ok(Some(session)) => session,
        Ok(None) => return AccessTokenResolution::ReauthenticationRequired,
        Err(()) => return AccessTokenResolution::TemporarilyUnavailable,
    };

    if access_token_is_sufficiently_valid(&initial, now) {
        return AccessTokenResolution::Ready(initial.access_token);
    }

    if initial.refresh_token.is_none() {
        return AccessTokenResolution::ReauthenticationRequired;
    }

    let owner_id = new_refresh_owner_id();
    let wait_started_at = tokio::time::Instant::now();
    let wait_deadline = wait_started_at + REFRESH_WAIT_TIMEOUT;
    let mut wait_delay = REFRESH_WAIT_INITIAL_DELAY;

    loop {
        let instant = tokio::time::Instant::now();

        if instant >= wait_deadline {
            return AccessTokenResolution::TemporarilyUnavailable;
        }

        let effective_now = now.saturating_add(wait_started_at.elapsed().as_secs());

        match state
            .session_store
            .try_acquire_refresh_lock(session_id, &owner_id, REFRESH_LOCK_LEASE)
            .await
        {
            Ok(true) => {
                return refresh_with_ownership(state, session_id, &owner_id, effective_now).await;
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

                let effective_now = now.saturating_add(wait_started_at.elapsed().as_secs());

                if access_token_is_sufficiently_valid(&current, effective_now) {
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
    now: u64,
) -> AccessTokenResolution {
    let result = refresh_with_ownership_inner(state, session_id, owner_id, now).await;

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
    now: u64,
) -> AccessTokenResolution {
    let current = match state.session_store.get(session_id).await {
        Ok(Some(session)) => session,
        Ok(None) => return AccessTokenResolution::ReauthenticationRequired,
        Err(()) => return AccessTokenResolution::TemporarilyUnavailable,
    };

    // Re-read after acquiring the lock. Another request may have completed a
    // refresh between our initial read and lock acquisition.
    if access_token_is_sufficiently_valid(&current, now) {
        return AccessTokenResolution::Ready(current.access_token);
    }

    let Some(refresh_token_value) = current.refresh_token.as_ref() else {
        return AccessTokenResolution::ReauthenticationRequired;
    };

    let refresh_started_at = tokio::time::Instant::now();

    let provider_metadata = match provider_metadata(state).await {
        Ok(metadata) => metadata,
        Err(_) => return AccessTokenResolution::TemporarilyUnavailable,
    };

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
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

    // Base expiry on the time the token response was actually received rather
    // than on the time the refresh lock was acquired.
    let response_now = now.saturating_add(refresh_started_at.elapsed().as_secs());

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
        // Without an expiry hint there is no safe threshold to calculate.
        // Keep the current token rather than refreshing on every application
        // request.
        return true;
    };

    expires_at > now.saturating_add(ACCESS_TOKEN_REFRESH_SKEW.as_secs())
}

fn refreshed_access_token_expiry(now: u64, expires_in: Option<Duration>) -> Option<u64> {
    now.checked_add(expires_in?.as_secs())
}

fn unix_time_seconds() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

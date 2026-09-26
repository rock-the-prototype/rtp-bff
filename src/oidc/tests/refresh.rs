use super::support::*;

const TEST_NOW: u64 = 1_800_000_000;

async fn state_with_refresh_endpoint(
    refresh_token: String,
    outcome: MockRefreshOutcome,
    delay: Duration,
) -> (OidcState, MockRefreshTokenEndpoint) {
    let client_secret = runtime_secret();
    let endpoint =
        spawn_mock_refresh_token_endpoint(refresh_token, client_secret.clone(), outcome, delay)
            .await;

    let state = test_state_for_issuer(MOCK_ISSUER, client_secret);
    let signing_key = EphemeralEs256Key::generate();
    install_mock_provider_metadata(&state, &signing_key, &endpoint.url).await;

    (state, endpoint)
}

async fn put_session(
    state: &OidcState,
    session_id: &str,
    access_token: String,
    refresh_token: Option<String>,
    expires_at: Option<u64>,
) {
    state
        .session_store
        .put(
            session_id,
            &AuthenticatedSession {
                access_token,
                refresh_token,
                access_token_expires_at: expires_at,
            },
        )
        .await
        .expect("test session write must succeed");
}

fn assert_ready_token(resolution: AccessTokenResolution, expected: &str) {
    match resolution {
        AccessTokenResolution::Ready(token) => assert_eq!(token, expected),
        AccessTokenResolution::ReauthenticationRequired => {
            panic!("expected a usable access token, got reauthentication-required")
        }
        AccessTokenResolution::TemporarilyUnavailable => {
            panic!("expected a usable access token, got temporary-unavailable")
        }
    }
}

#[tokio::test]
async fn runtime_token_resolution_reuses_token_without_expiry_hint() {
    let state = test_state();
    let session_id = runtime_secret();
    let access_token = runtime_secret();

    put_session(
        &state,
        &session_id,
        access_token.clone(),
        Some(runtime_secret()),
        None,
    )
    .await;

    let resolution = resolve_access_token(&state, &session_id).await;

    assert_ready_token(resolution, &access_token);
}

#[tokio::test]
async fn valid_access_token_is_reused_without_refresh() {
    let refresh_token = runtime_secret();
    let (state, endpoint) = state_with_refresh_endpoint(
        refresh_token.clone(),
        MockRefreshOutcome::SuccessWithRotation,
        Duration::ZERO,
    )
    .await;
    let session_id = runtime_secret();
    let access_token = runtime_secret();

    put_session(
        &state,
        &session_id,
        access_token.clone(),
        Some(refresh_token),
        Some(TEST_NOW + 300),
    )
    .await;

    let resolution = resolve_access_token_at(&state, &session_id, TEST_NOW).await;

    assert_ready_token(resolution, &access_token);
    assert_eq!(endpoint.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn expiring_access_token_is_refreshed_and_persisted() {
    let session_id = runtime_secret();
    let expected_refresh_token = runtime_secret();
    let (state, endpoint) = state_with_refresh_endpoint(
        expected_refresh_token.clone(),
        MockRefreshOutcome::SuccessWithRotation,
        Duration::ZERO,
    )
    .await;
    put_session(
        &state,
        &session_id,
        runtime_secret(),
        Some(expected_refresh_token),
        Some(TEST_NOW + 10),
    )
    .await;

    let resolution = resolve_access_token_at(&state, &session_id, TEST_NOW).await;

    assert_ready_token(resolution, &endpoint.access_token);
    assert_eq!(endpoint.calls.load(Ordering::SeqCst), 1);
    assert_eq!(endpoint.client_auth_failures.load(Ordering::SeqCst), 0);
    assert_eq!(
        endpoint
            .client_secret_body_violations
            .load(Ordering::SeqCst),
        0
    );

    let stored = state
        .session_store
        .get(&session_id)
        .await
        .expect("session read must succeed")
        .expect("refreshed session must remain present");

    assert_eq!(stored.access_token, endpoint.access_token);
    assert_eq!(stored.refresh_token, endpoint.rotated_refresh_token);
    assert_eq!(stored.access_token_expires_at, Some(TEST_NOW + 300));
}

#[tokio::test]
async fn rotated_refresh_token_replaces_previous_value() {
    let original_refresh_token = runtime_secret();
    let (state, endpoint) = state_with_refresh_endpoint(
        original_refresh_token.clone(),
        MockRefreshOutcome::SuccessWithRotation,
        Duration::ZERO,
    )
    .await;
    let session_id = runtime_secret();

    put_session(
        &state,
        &session_id,
        runtime_secret(),
        Some(original_refresh_token.clone()),
        Some(TEST_NOW),
    )
    .await;

    let resolution = resolve_access_token_at(&state, &session_id, TEST_NOW).await;
    assert_ready_token(resolution, &endpoint.access_token);

    let stored = state
        .session_store
        .get(&session_id)
        .await
        .expect("session read must succeed")
        .expect("refreshed session must exist");
    let rotated = endpoint
        .rotated_refresh_token
        .as_ref()
        .expect("rotating mock endpoint must expose the rotated refresh token");

    assert_eq!(stored.refresh_token.as_deref(), Some(rotated.as_str()));
    assert_ne!(
        stored.refresh_token.as_deref(),
        Some(original_refresh_token.as_str())
    );
}

#[tokio::test]
async fn missing_rotated_refresh_token_preserves_previous_value() {
    let original_refresh_token = runtime_secret();
    let (state, endpoint) = state_with_refresh_endpoint(
        original_refresh_token.clone(),
        MockRefreshOutcome::SuccessWithoutRotation,
        Duration::ZERO,
    )
    .await;
    let session_id = runtime_secret();

    put_session(
        &state,
        &session_id,
        runtime_secret(),
        Some(original_refresh_token.clone()),
        Some(TEST_NOW),
    )
    .await;

    let resolution = resolve_access_token_at(&state, &session_id, TEST_NOW).await;
    assert_ready_token(resolution, &endpoint.access_token);

    let stored = state
        .session_store
        .get(&session_id)
        .await
        .expect("session read must succeed")
        .expect("refreshed session must exist");

    assert_eq!(
        stored.refresh_token.as_deref(),
        Some(original_refresh_token.as_str())
    );
}

#[tokio::test]
async fn missing_refresh_token_requires_reauthentication() {
    let expected_refresh_token = runtime_secret();
    let (state, endpoint) = state_with_refresh_endpoint(
        expected_refresh_token,
        MockRefreshOutcome::SuccessWithRotation,
        Duration::ZERO,
    )
    .await;
    let session_id = runtime_secret();

    put_session(&state, &session_id, runtime_secret(), None, Some(TEST_NOW)).await;

    let resolution = resolve_access_token_at(&state, &session_id, TEST_NOW).await;

    assert!(matches!(
        resolution,
        AccessTokenResolution::ReauthenticationRequired
    ));
    assert_eq!(endpoint.calls.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn invalid_grant_invalidates_authenticated_session() {
    let refresh_token = runtime_secret();
    let (state, endpoint) = state_with_refresh_endpoint(
        refresh_token.clone(),
        MockRefreshOutcome::InvalidGrant,
        Duration::ZERO,
    )
    .await;
    let session_id = runtime_secret();

    put_session(
        &state,
        &session_id,
        runtime_secret(),
        Some(refresh_token),
        Some(TEST_NOW),
    )
    .await;

    let resolution = resolve_access_token_at(&state, &session_id, TEST_NOW).await;

    assert!(matches!(
        resolution,
        AccessTokenResolution::ReauthenticationRequired
    ));
    assert_eq!(endpoint.calls.load(Ordering::SeqCst), 1);
    assert!(
        state
            .session_store
            .get(&session_id)
            .await
            .expect("session read must succeed")
            .is_none(),
        "invalid_grant must invalidate the authenticated BFF session"
    );
}

#[tokio::test]
async fn temporary_token_endpoint_failure_fails_closed_without_destroying_session() {
    let refresh_token = runtime_secret();
    let original_access_token = runtime_secret();
    let (state, endpoint) = state_with_refresh_endpoint(
        refresh_token.clone(),
        MockRefreshOutcome::TemporaryFailure,
        Duration::ZERO,
    )
    .await;
    let session_id = runtime_secret();

    put_session(
        &state,
        &session_id,
        original_access_token.clone(),
        Some(refresh_token.clone()),
        Some(TEST_NOW),
    )
    .await;

    let resolution = resolve_access_token_at(&state, &session_id, TEST_NOW).await;

    assert!(matches!(
        resolution,
        AccessTokenResolution::TemporarilyUnavailable
    ));
    assert_eq!(endpoint.calls.load(Ordering::SeqCst), 1);

    let stored = state
        .session_store
        .get(&session_id)
        .await
        .expect("session read must succeed")
        .expect("temporary upstream failure must not destroy the session");

    assert_eq!(stored.access_token, original_access_token);
    assert_eq!(
        stored.refresh_token.as_deref(),
        Some(refresh_token.as_str())
    );
}

#[tokio::test]
async fn refresh_persistence_failure_fails_closed() {
    let refresh_token = runtime_secret();
    let original_access_token = runtime_secret();
    let (mut state, endpoint) = state_with_refresh_endpoint(
        refresh_token.clone(),
        MockRefreshOutcome::SuccessWithRotation,
        Duration::ZERO,
    )
    .await;
    state.session_store = SessionStore::for_tests_failing_refresh_mutations();
    let session_id = runtime_secret();

    put_session(
        &state,
        &session_id,
        original_access_token.clone(),
        Some(refresh_token.clone()),
        Some(TEST_NOW),
    )
    .await;

    let resolution = resolve_access_token_at(&state, &session_id, TEST_NOW).await;

    assert!(matches!(
        resolution,
        AccessTokenResolution::TemporarilyUnavailable
    ));
    assert_eq!(endpoint.calls.load(Ordering::SeqCst), 1);

    let stored = state
        .session_store
        .get(&session_id)
        .await
        .expect("session read must succeed")
        .expect("failed refresh persistence must leave the original session intact");

    assert_eq!(stored.access_token, original_access_token);
    assert_eq!(
        stored.refresh_token.as_deref(),
        Some(refresh_token.as_str())
    );
}

#[tokio::test]
async fn refresh_lock_store_failure_fails_closed_without_token_exchange() {
    let refresh_token = runtime_secret();
    let (mut state, endpoint) = state_with_refresh_endpoint(
        refresh_token.clone(),
        MockRefreshOutcome::SuccessWithRotation,
        Duration::ZERO,
    )
    .await;
    state.session_store = SessionStore::for_tests_failing_refresh_lock_ops();
    let session_id = runtime_secret();

    put_session(
        &state,
        &session_id,
        runtime_secret(),
        Some(refresh_token),
        Some(TEST_NOW),
    )
    .await;

    let resolution = resolve_access_token_at(&state, &session_id, TEST_NOW).await;

    assert!(matches!(
        resolution,
        AccessTokenResolution::TemporarilyUnavailable
    ));
    assert_eq!(
        endpoint.calls.load(Ordering::SeqCst),
        0,
        "refresh must fail closed before token exchange when lock storage is unavailable"
    );
}

#[tokio::test]
async fn concurrent_refresh_requests_reach_token_endpoint_at_most_once() {
    let refresh_token = runtime_secret();
    let (state, endpoint) = state_with_refresh_endpoint(
        refresh_token.clone(),
        MockRefreshOutcome::SuccessWithRotation,
        Duration::from_millis(100),
    )
    .await;
    let session_id = runtime_secret();

    put_session(
        &state,
        &session_id,
        runtime_secret(),
        Some(refresh_token),
        Some(TEST_NOW),
    )
    .await;

    let barrier = Arc::new(Barrier::new(3));

    let state_a = state.clone();
    let session_a = session_id.clone();
    let barrier_a = barrier.clone();
    let task_a = tokio::spawn(async move {
        barrier_a.wait().await;
        resolve_access_token_at(&state_a, &session_a, TEST_NOW).await
    });

    let state_b = state.clone();
    let session_b = session_id.clone();
    let barrier_b = barrier.clone();
    let task_b = tokio::spawn(async move {
        barrier_b.wait().await;
        resolve_access_token_at(&state_b, &session_b, TEST_NOW).await
    });

    barrier.wait().await;

    let resolution_a = task_a.await.expect("first refresh task must complete");
    let resolution_b = task_b.await.expect("second refresh task must complete");

    assert_ready_token(resolution_a, &endpoint.access_token);
    assert_ready_token(resolution_b, &endpoint.access_token);
    assert_eq!(endpoint.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn refresh_waiter_reuses_token_written_by_owner() {
    let expected_refresh_token = runtime_secret();
    let (state, endpoint) = state_with_refresh_endpoint(
        expected_refresh_token.clone(),
        MockRefreshOutcome::SuccessWithRotation,
        Duration::ZERO,
    )
    .await;
    let session_id = runtime_secret();
    let owner_id = runtime_secret();
    let owner_access_token = runtime_secret();

    put_session(
        &state,
        &session_id,
        runtime_secret(),
        Some(expected_refresh_token.clone()),
        Some(TEST_NOW),
    )
    .await;

    assert!(
        state
            .session_store
            .try_acquire_refresh_lock(&session_id, &owner_id, Duration::from_secs(5))
            .await
            .expect("external refresh owner must acquire the lock")
    );

    let waiter_state = state.clone();
    let waiter_session = session_id.clone();
    let waiter = tokio::spawn(async move {
        resolve_access_token_at(&waiter_state, &waiter_session, TEST_NOW).await
    });

    tokio::time::sleep(Duration::from_millis(75)).await;

    let owner_session = AuthenticatedSession {
        access_token: owner_access_token.clone(),
        refresh_token: Some(expected_refresh_token),
        access_token_expires_at: Some(TEST_NOW + 300),
    };

    assert!(matches!(
        state
            .session_store
            .update_after_refresh(&session_id, &owner_id, &owner_session)
            .await
            .expect("external owner refresh update must succeed"),
        crate::session::RefreshOwnedMutation::Applied
    ));
    assert!(
        state
            .session_store
            .release_refresh_lock(&session_id, &owner_id)
            .await
            .expect("external owner lock release must succeed")
    );

    let resolution = waiter.await.expect("refresh waiter must complete");

    assert_ready_token(resolution, &owner_access_token);
    assert_eq!(
        endpoint.calls.load(Ordering::SeqCst),
        0,
        "a waiter must reuse the owner's persisted token instead of refreshing independently"
    );
}

#[tokio::test]
async fn no_browser_refresh_route_exists() {
    let response = oidc_router()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/auth/refresh")
                .extension(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 41_000))))
                .body(Body::empty())
                .expect("refresh-route test request must be valid"),
        )
        .await
        .expect("OIDC router must answer the request");

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
}
#[tokio::test]
async fn refreshed_token_expiry_includes_elapsed_refresh_time() {
    let refresh_token = runtime_secret();

    let (state, endpoint) = state_with_refresh_endpoint(
        refresh_token.clone(),
        MockRefreshOutcome::SuccessWithRotation,
        Duration::from_millis(1_100),
    )
    .await;

    let session_id = runtime_secret();

    put_session(
        &state,
        &session_id,
        runtime_secret(),
        Some(refresh_token),
        Some(TEST_NOW),
    )
    .await;

    let resolution = resolve_access_token_at(&state, &session_id, TEST_NOW).await;

    assert_ready_token(resolution, &endpoint.access_token);

    let stored = state
        .session_store
        .get(&session_id)
        .await
        .expect("session read must succeed")
        .expect("refreshed session must remain present");

    assert!(
        stored.access_token_expires_at >= Some(TEST_NOW + 301),
        "token expiry must include measurable elapsed refresh time"
    );
}

use super::support::*;

fn assert_no_store(response: &axum::response::Response) {
    assert_eq!(
        response.headers().get(CACHE_CONTROL),
        Some(&HeaderValue::from_static("no-store"))
    );
}

#[tokio::test]
async fn check_session_without_cookie_is_unauthorized() {
    let state = test_state();

    let response = check_session(State(state), CookieJar::new()).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_no_store(&response);
}

#[tokio::test]
async fn check_session_with_active_session_returns_no_content() {
    let state = test_state();
    let session_id = runtime_secret();

    let session = AuthenticatedSession {
        access_token: runtime_secret(),
        refresh_token: Some(runtime_secret()),
        access_token_expires_at: Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock must be after UNIX epoch")
                .as_secs()
                + 300,
        ),
    };

    state
        .session_store
        .put(&session_id, &session)
        .await
        .expect("test session store write must succeed");

    let cookie_name = session_cookie_name(state.config.secure_cookie());
    let jar = request_cookie_jar(&[(cookie_name, session_id.as_str())]);

    let response = check_session(State(state), jar).await;

    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_no_store(&response);
}

#[tokio::test]
async fn check_session_with_stale_cookie_is_unauthorized() {
    let state = test_state();
    let session_id = runtime_secret();
    let cookie_name = session_cookie_name(state.config.secure_cookie());
    let jar = request_cookie_jar(&[(cookie_name, session_id.as_str())]);

    let response = check_session(State(state), jar).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_no_store(&response);
}

#[tokio::test]
async fn check_session_store_failure_returns_service_unavailable() {
    let mut state = test_state();
    state.session_store = SessionStore::for_tests_failing_reads();

    let session_id = runtime_secret();
    let cookie_name = session_cookie_name(state.config.secure_cookie());
    let jar = request_cookie_jar(&[(cookie_name, session_id.as_str())]);

    let response = check_session(State(state), jar).await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_no_store(&response);
}

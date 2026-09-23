use super::support::*;

// AC-OIDC-TXN-001
#[tokio::test]
async fn login_transactions_generate_independent_security_material() {
    let state = test_state();
    let signing_key = EphemeralEs256Key::generate();
    install_mock_provider_metadata(&state, &signing_key, "https://mock.example/token").await;
    let peer = SocketAddr::from(([127, 0, 0, 1], 12345));

    let (first_jar, first_redirect) = login(
        State(state.clone()),
        ConnectInfo(peer),
        HeaderMap::new(),
        CookieJar::new(),
    )
    .await
    .expect("first login must start");

    let first_response = (first_jar, first_redirect).into_response();
    assert_eq!(first_response.status(), StatusCode::TEMPORARY_REDIRECT);

    let first_location = first_response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("first login response must contain a valid Location header")
        .to_owned();

    let (second_jar, second_redirect) = login(
        State(state.clone()),
        ConnectInfo(peer),
        HeaderMap::new(),
        CookieJar::new(),
    )
    .await
    .expect("second login must start");

    let second_response = (second_jar, second_redirect).into_response();
    assert_eq!(second_response.status(), StatusCode::TEMPORARY_REDIRECT);

    let second_location = second_response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("second login response must contain a valid Location header")
        .to_owned();

    assert_ne!(
        first_location, second_location,
        "independent login transactions must produce distinct authorization requests",
    );

    let pending = state
        .pending
        .lock()
        .expect("pending transaction store must be lockable");

    assert_eq!(pending.len(), 2);
    let mut transactions = pending.values();
    let first = transactions.next().expect("first transaction must exist");
    let second = transactions.next().expect("second transaction must exist");

    assert_ne!(first.nonce.secret(), second.nonce.secret());
    assert_ne!(first.pkce_verifier.secret(), second.pkce_verifier.secret());
    assert_ne!(first.browser_binding_hash, second.browser_binding_hash);
}
// AC-OIDC-TXN-008
#[tokio::test]
async fn oidc_error_callback_consumes_transaction_and_removes_cookie() {
    let state = test_state();
    let state_key = runtime_secret();
    let binding = runtime_secret();
    insert_random_transaction(&state, &state_key, &binding);
    let params = HashMap::from([
        ("error".to_owned(), "access_denied".to_owned()),
        ("state".to_owned(), state_key.clone()),
    ]);
    let cookie_name = preauth_cookie_name(&state_key);
    let jar = request_cookie_jar(&[(&cookie_name, &binding)]);
    let result = callback(State(state.clone()), Query(params), jar).await;
    let (returned_jar, status) = result.expect_err("OIDC error callback must fail");

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        !state
            .pending
            .lock()
            .expect("pending transaction store must be lockable")
            .contains_key(&state_key)
    );

    let response = (returned_jar, status).into_response();
    assert!(response_removes_cookie(&response, &cookie_name));
}
// AC-OIDC-TXN-004, AC-OIDC-TXN-009, AC-OIDC-TXN-018
#[tokio::test]
async fn wrong_browser_binding_is_rejected_without_consuming_transaction() {
    let state = test_state();
    let state_key = runtime_secret();
    let expected_binding = runtime_secret();
    let wrong_binding = runtime_secret();
    insert_random_transaction(&state, &state_key, &expected_binding);
    let params = HashMap::from([
        ("error".to_owned(), "access_denied".to_owned()),
        ("state".to_owned(), state_key.clone()),
    ]);
    let cookie_name = preauth_cookie_name(&state_key);
    let jar = request_cookie_jar(&[(&cookie_name, &wrong_binding)]);
    let result = callback(State(state.clone()), Query(params), jar).await;
    let (_, status) = result.expect_err("wrong browser binding must fail");

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        state
            .pending
            .lock()
            .expect("pending transaction store must be lockable")
            .contains_key(&state_key)
    );
}
#[tokio::test]
async fn malformed_callback_does_not_consume_transaction() {
    let state = test_state();
    let state_key = runtime_secret();
    let binding = runtime_secret();
    insert_random_transaction(&state, &state_key, &binding);
    let code = runtime_secret();
    let params = HashMap::from([
        ("code".to_owned(), code),
        ("error".to_owned(), "access_denied".to_owned()),
        ("state".to_owned(), state_key.clone()),
    ]);
    let cookie_name = preauth_cookie_name(&state_key);
    let jar = request_cookie_jar(&[(&cookie_name, &binding)]);
    let result = callback(State(state.clone()), Query(params), jar).await;
    let (_, status) = result.expect_err("malformed callback must fail");

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        state
            .pending
            .lock()
            .expect("pending transaction store must be lockable")
            .contains_key(&state_key)
    );
}
#[tokio::test]
async fn independent_authorization_transactions_keep_independent_bindings() {
    let state = test_state();
    let state_one = runtime_secret();
    let state_two = runtime_secret();
    let binding_one = runtime_secret();
    let binding_two = runtime_secret();
    insert_random_transaction(&state, &state_one, &binding_one);
    insert_random_transaction(&state, &state_two, &binding_two);
    let cookie_one = preauth_cookie_name(&state_one);
    let cookie_two = preauth_cookie_name(&state_two);
    let jar = request_cookie_jar(&[(&cookie_one, &binding_one), (&cookie_two, &binding_two)]);

    let first_params = HashMap::from([
        ("error".to_owned(), "access_denied".to_owned()),
        ("state".to_owned(), state_one.clone()),
    ]);
    assert!(
        callback(State(state.clone()), Query(first_params), jar.clone())
            .await
            .is_err()
    );

    {
        let pending = state
            .pending
            .lock()
            .expect("pending transaction store must be lockable");
        assert!(!pending.contains_key(&state_one));
        assert!(pending.contains_key(&state_two));
    }

    let second_params = HashMap::from([
        ("error".to_owned(), "access_denied".to_owned()),
        ("state".to_owned(), state_two.clone()),
    ]);
    assert!(
        callback(State(state.clone()), Query(second_params), jar)
            .await
            .is_err()
    );
    assert!(
        !state
            .pending
            .lock()
            .expect("pending transaction store must be lockable")
            .contains_key(&state_two)
    );
}
// AC-OIDC-TXN-006
#[tokio::test]
async fn concurrent_callbacks_for_same_transaction_reach_token_endpoint_at_most_once() {
    let state = test_state();
    let signing_key = EphemeralEs256Key::generate();
    let nonce = Nonce::new_random();
    let code = runtime_secret();
    let (_, verifier) = PkceCodeChallenge::new_random_sha256();
    let verifier_value = verifier.secret().to_owned();
    let token_endpoint = spawn_mock_token_endpoint(
        signing_key.compact_id_token(nonce.secret()),
        Some(code.clone()),
        Some(verifier_value),
        state.config.client_secret.secret().to_owned(),
    )
    .await;
    install_mock_provider_metadata(&state, &signing_key, &token_endpoint.url).await;
    let state_key = runtime_secret();
    let binding = runtime_secret();
    insert_transaction_with(
        &state,
        &state_key,
        &binding,
        verifier,
        nonce,
        Instant::now(),
    );
    let params = HashMap::from([
        ("code".to_owned(), code),
        ("state".to_owned(), state_key.clone()),
    ]);
    let cookie_name = preauth_cookie_name(&state_key);
    let jar = request_cookie_jar(&[(&cookie_name, &binding)]);
    let barrier = Arc::new(Barrier::new(2));

    let first = {
        let barrier = barrier.clone();
        let state = state.clone();
        let params = params.clone();
        let jar = jar.clone();
        async move {
            barrier.wait().await;
            callback(State(state), Query(params), jar).await
        }
    };
    let second = {
        let barrier = barrier.clone();
        let state = state.clone();
        let params = params.clone();
        let jar = jar.clone();
        async move {
            barrier.wait().await;
            callback(State(state), Query(params), jar).await
        }
    };

    let (first_result, second_result) = tokio::join!(first, second);
    let successes = [first_result.is_ok(), second_result.is_ok()]
        .into_iter()
        .filter(|succeeded| *succeeded)
        .count();

    assert_eq!(successes, 1);
    assert_eq!(token_endpoint.calls.load(Ordering::SeqCst), 1);
}
// AC-OIDC-TXN-007
#[tokio::test]
async fn expired_transaction_is_rejected_before_token_exchange() {
    let state = test_state();
    let signing_key = EphemeralEs256Key::generate();
    let nonce = Nonce::new_random();
    let code = runtime_secret();
    let (_, verifier) = PkceCodeChallenge::new_random_sha256();
    let token_endpoint = spawn_mock_token_endpoint(
        signing_key.compact_id_token(nonce.secret()),
        Some(code.clone()),
        Some(verifier.secret().to_owned()),
        state.config.client_secret.secret().to_owned(),
    )
    .await;
    install_mock_provider_metadata(&state, &signing_key, &token_endpoint.url).await;
    let state_key = runtime_secret();
    let binding = runtime_secret();

    insert_transaction_with(
        &state,
        &state_key,
        &binding,
        verifier,
        nonce,
        Instant::now() - LOGIN_TTL - Duration::from_secs(1),
    );

    let params = HashMap::from([
        ("code".to_owned(), code),
        ("state".to_owned(), state_key.clone()),
    ]);
    let cookie_name = preauth_cookie_name(&state_key);
    let jar = request_cookie_jar(&[(&cookie_name, &binding)]);
    let result = callback(State(state.clone()), Query(params), jar).await;
    let (_, status) = result.expect_err("expired transaction must fail");

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(token_endpoint.calls.load(Ordering::SeqCst), 0);
    assert!(
        !state
            .pending
            .lock()
            .expect("pending transaction store must be lockable")
            .contains_key(&state_key)
    );
}

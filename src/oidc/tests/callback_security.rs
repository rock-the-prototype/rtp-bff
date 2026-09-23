use super::support::*;

// AC-OIDC-TXN-003
#[tokio::test]
async fn callback_without_preauth_cookie_is_rejected_before_token_exchange() {
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
        Instant::now(),
    );

    let params = HashMap::from([
        ("code".to_owned(), code),
        ("state".to_owned(), state_key.clone()),
    ]);
    let result = callback(State(state.clone()), Query(params), CookieJar::new()).await;
    let (_, status) = result.expect_err("missing browser binding must be rejected");

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(token_endpoint.calls.load(Ordering::SeqCst), 0);
    assert!(
        state
            .pending
            .lock()
            .expect("pending transaction store must be lockable")
            .contains_key(&state_key)
    );
}
// AC-OIDC-TXN-010
#[tokio::test]
async fn incorrect_pkce_verifier_causes_token_exchange_failure() {
    let state = test_state();
    let signing_key = EphemeralEs256Key::generate();
    let nonce = Nonce::new_random();
    let code = runtime_secret();
    let (_, expected_verifier) = PkceCodeChallenge::new_random_sha256();
    let (_, wrong_verifier) = PkceCodeChallenge::new_random_sha256();
    let token_endpoint = spawn_mock_token_endpoint(
        signing_key.compact_id_token(nonce.secret()),
        Some(code.clone()),
        Some(expected_verifier.secret().to_owned()),
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
        wrong_verifier,
        nonce,
        Instant::now(),
    );

    let params = HashMap::from([
        ("code".to_owned(), code),
        ("state".to_owned(), state_key.clone()),
    ]);
    let cookie_name = preauth_cookie_name(&state_key);
    let jar = request_cookie_jar(&[(&cookie_name, &binding)]);
    let result = callback(State(state.clone()), Query(params), jar).await;
    let (returned_jar, status) = result.expect_err("wrong PKCE verifier must fail");

    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(token_endpoint.calls.load(Ordering::SeqCst), 1);

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
// AC-OIDC-TXN-011
#[tokio::test]
async fn wrong_nonce_is_rejected_without_jwks_refresh() {
    let config = mock_config();
    let signing_key = EphemeralEs256Key::generate();
    let rotated_key = EphemeralEs256Key::generate();
    let token_nonce = Nonce::new_random();
    let expected_nonce = Nonce::new_random();
    let token = signing_key.id_token(token_nonce.secret());
    let metadata = mock_provider_metadata(signing_key.jwks(), "https://mock.example/token");
    let refresh_count = Arc::new(AtomicUsize::new(0));
    let count = refresh_count.clone();

    let result = verify_id_token_with_single_refresh(
        &config,
        metadata,
        &token,
        &expected_nonce,
        move || async move {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(mock_provider_metadata(
                rotated_key.jwks(),
                "https://mock.example/token",
            ))
        },
    )
    .await;

    assert_eq!(result, Err(StatusCode::UNAUTHORIZED));
    assert_eq!(refresh_count.load(Ordering::SeqCst), 0);
}
#[tokio::test]
async fn disallowed_signing_algorithm_is_rejected_without_jwks_refresh() {
    let config = mock_config();
    let signing_key = EphemeralEs256Key::generate();
    let nonce = Nonce::new_random();
    let compact = signing_key.compact_id_token_with_algorithm(nonce.secret(), "HS256");
    let token = CoreIdToken::from_str(&compact).expect("runtime token must parse");
    let metadata = mock_provider_metadata(signing_key.jwks(), "https://mock.example/token");
    let refresh_count = Arc::new(AtomicUsize::new(0));
    let count = refresh_count.clone();

    let result = verify_id_token_with_single_refresh(
        &config,
        metadata,
        &token,
        &nonce,
        move || async move {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(mock_provider_metadata(
                signing_key.jwks(),
                "https://mock.example/token",
            ))
        },
    )
    .await;

    assert_eq!(result, Err(StatusCode::UNAUTHORIZED));
    assert_eq!(refresh_count.load(Ordering::SeqCst), 0);
}
// AC-OIDC-TXN-012
#[tokio::test]
async fn invalid_signature_is_rejected_without_jwks_refresh() {
    let config = mock_config();
    let trusted_key = EphemeralEs256Key::generate();
    let attacker_key = EphemeralEs256Key::generate();
    let nonce = Nonce::new_random();
    let compact = attacker_key.compact_id_token_with_kid(nonce.secret(), &trusted_key.kid);
    let token = CoreIdToken::from_str(&compact).expect("runtime token must parse");
    let metadata = mock_provider_metadata(trusted_key.jwks(), "https://mock.example/token");
    let refresh_count = Arc::new(AtomicUsize::new(0));
    let count = refresh_count.clone();

    let result = verify_id_token_with_single_refresh(
        &config,
        metadata,
        &token,
        &nonce,
        move || async move {
            count.fetch_add(1, Ordering::SeqCst);
            Ok(mock_provider_metadata(
                trusted_key.jwks(),
                "https://mock.example/token",
            ))
        },
    )
    .await;

    assert_eq!(result, Err(StatusCode::UNAUTHORIZED));
    assert_eq!(refresh_count.load(Ordering::SeqCst), 0);
}
// AC-OIDC-TXN-013, AC-OIDC-TXN-014
#[tokio::test]
async fn unknown_signing_key_refreshes_once_and_accepts_rotated_key() {
    let old_key = EphemeralEs256Key::generate();
    let rotated_key = EphemeralEs256Key::generate();
    let nonce = Nonce::new_random();
    let code = runtime_secret();
    let (_, verifier) = PkceCodeChallenge::new_random_sha256();
    let verifier_value = verifier.secret().to_owned();
    let client_secret = runtime_secret();

    let provider = spawn_mock_oidc_provider(
        old_key.jwks_json(),
        Some(rotated_key.jwks_json()),
        &rotated_key,
        nonce.secret(),
        code.clone(),
        verifier_value,
        client_secret.clone(),
    )
    .await;
    let state = test_state_for_issuer(&provider.issuer, client_secret);
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

    let (returned_jar, status) = callback(State(state), Query(params), jar)
        .await
        .expect("rotated signing key must succeed after one refresh");

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(provider.token_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.discovery_calls.load(Ordering::SeqCst), 2);
    assert_eq!(provider.jwks_calls.load(Ordering::SeqCst), 2);
    assert_eq!(provider.client_auth_failures.load(Ordering::SeqCst), 0);
    assert_eq!(
        provider
            .client_secret_body_violations
            .load(Ordering::SeqCst),
        0,
    );

    let response = (returned_jar, status).into_response();
    assert!(response_removes_cookie(&response, &cookie_name));
}
// AC-OIDC-TXN-015
#[tokio::test]
async fn unknown_signing_key_is_rejected_after_one_unsuccessful_refresh() {
    let stale_key = EphemeralEs256Key::generate();
    let unknown_key = EphemeralEs256Key::generate();
    let nonce = Nonce::new_random();
    let code = runtime_secret();
    let (_, verifier) = PkceCodeChallenge::new_random_sha256();
    let verifier_value = verifier.secret().to_owned();
    let client_secret = runtime_secret();

    let provider = spawn_mock_oidc_provider(
        stale_key.jwks_json(),
        None,
        &unknown_key,
        nonce.secret(),
        code.clone(),
        verifier_value,
        client_secret.clone(),
    )
    .await;
    let state = test_state_for_issuer(&provider.issuer, client_secret);
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

    let (returned_jar, status) = callback(State(state), Query(params), jar)
        .await
        .expect_err("unknown key must fail after exactly one stale refresh");

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(provider.token_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.discovery_calls.load(Ordering::SeqCst), 2);
    assert_eq!(provider.jwks_calls.load(Ordering::SeqCst), 2);
    assert_eq!(provider.client_auth_failures.load(Ordering::SeqCst), 0);
    assert_eq!(
        provider
            .client_secret_body_violations
            .load(Ordering::SeqCst),
        0,
    );

    let response = (returned_jar, status).into_response();
    assert!(response_removes_cookie(&response, &cookie_name));
}
// AC-OIDC-TXN-017, AC-OIDC-TXN-019
#[tokio::test]
async fn successful_callback_completes_flow_removes_cookie_and_prevents_replay() {
    let signing_key = EphemeralEs256Key::generate();
    let nonce = Nonce::new_random();
    let code = runtime_secret();
    let (_, verifier) = PkceCodeChallenge::new_random_sha256();
    let verifier_value = verifier.secret().to_owned();
    let client_secret = runtime_secret();

    let provider = spawn_mock_oidc_provider(
        signing_key.jwks_json(),
        None,
        &signing_key,
        nonce.secret(),
        code.clone(),
        verifier_value,
        client_secret.clone(),
    )
    .await;
    let state = test_state_for_issuer(&provider.issuer, client_secret.clone());
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

    let (returned_jar, status) = callback(State(state.clone()), Query(params.clone()), jar.clone())
        .await
        .expect("valid callback must succeed");

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(provider.token_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.discovery_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.jwks_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.client_auth_failures.load(Ordering::SeqCst), 0);
    assert_eq!(
        provider
            .client_secret_body_violations
            .load(Ordering::SeqCst),
        0,
    );

    assert!(
        !state
            .pending
            .lock()
            .expect("pending transaction store must be lockable")
            .contains_key(&state_key)
    );

    let response = (returned_jar, status).into_response();
    assert!(response_removes_cookie(&response, &cookie_name));

    for value in response.headers().values() {
        let value = value
            .to_str()
            .expect("browser-visible response header must be valid ASCII");
        assert!(!value.contains(&provider.access_token));
        assert!(!value.contains(&provider.refresh_token));
        assert!(!value.contains(&client_secret));
    }

    let body = to_bytes(response.into_body(), 1024)
        .await
        .expect("successful response body must be readable");
    assert!(body.is_empty());

    let replay_result = callback(State(state), Query(params), jar).await;
    let (_, replay_status) = replay_result.expect_err("replayed callback must fail");

    assert_eq!(replay_status, StatusCode::BAD_REQUEST);
    assert_eq!(provider.token_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.discovery_calls.load(Ordering::SeqCst), 1);
    assert_eq!(provider.jwks_calls.load(Ordering::SeqCst), 1);
}
#[tokio::test]
async fn confidential_client_exchange_uses_client_secret_basic_only() {
    let signing_key = EphemeralEs256Key::generate();
    let nonce = Nonce::new_random();
    let code = runtime_secret();
    let (_, verifier) = PkceCodeChallenge::new_random_sha256();
    let verifier_value = verifier.secret().to_owned();
    let client_secret = runtime_secret();

    let provider = spawn_mock_oidc_provider(
        signing_key.jwks_json(),
        None,
        &signing_key,
        nonce.secret(),
        code.clone(),
        verifier_value,
        client_secret.clone(),
    )
    .await;
    let state = test_state_for_issuer(&provider.issuer, client_secret);
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

    let (_, status) = callback(State(state), Query(params), jar)
        .await
        .expect("confidential-client callback must succeed");

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(provider.token_calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        provider.client_auth_failures.load(Ordering::SeqCst),
        0,
        "token endpoint must receive the expected client_secret_basic credentials",
    );
    assert_eq!(
        provider
            .client_secret_body_violations
            .load(Ordering::SeqCst),
        0,
        "client secret must never be sent in the token request form body",
    );
}

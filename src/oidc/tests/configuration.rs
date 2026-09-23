use super::support::*;

#[test]
fn local_ipv4_http_redirect_is_allowed() {
    assert!(validate_redirect_uri("http://127.0.0.1:3000/auth/callback".to_owned()).is_ok());
}
#[test]
fn localhost_http_redirect_is_allowed() {
    assert!(validate_redirect_uri("http://localhost:3000/auth/callback".to_owned()).is_ok());
}
#[test]
fn non_loopback_https_redirect_is_allowed() {
    assert!(validate_redirect_uri("https://example.test/auth/callback".to_owned()).is_ok());
}
#[test]
fn non_loopback_http_redirect_is_rejected() {
    assert_eq!(
        validate_redirect_uri("http://example.test/auth/callback".to_owned()),
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    );
}
#[test]
fn non_http_loopback_redirect_is_rejected() {
    assert_eq!(
        validate_redirect_uri("ftp://localhost/auth/callback".to_owned()),
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    );
}
#[test]
fn malformed_redirect_uri_is_rejected() {
    assert_eq!(
        validate_redirect_uri("not a valid URI".to_owned()),
        Err(StatusCode::INTERNAL_SERVER_ERROR)
    );
}
#[test]
fn missing_client_secret_is_rejected_during_configuration() {
    let result =
        OidcConfig::from_values(ISSUER, CLIENT_ID, None, LOCAL_REDIRECT_URI.to_owned(), None);

    assert!(result.is_err());
}
#[test]
fn empty_client_secret_is_rejected_during_configuration() {
    let result = OidcConfig::from_values(
        ISSUER,
        CLIENT_ID,
        Some(String::new()),
        LOCAL_REDIRECT_URI.to_owned(),
        None,
    );

    assert!(result.is_err());
}
#[test]
fn invalid_trusted_proxy_cidr_is_rejected_during_configuration() {
    let result = OidcConfig::from_values(
        ISSUER,
        CLIENT_ID,
        Some(runtime_secret()),
        LOCAL_REDIRECT_URI.to_owned(),
        Some("not-a-cidr".to_owned()),
    );

    assert!(result.is_err());
}
#[test]
fn preauth_cookie_is_short_lived_narrow_and_http_only() {
    let cookie = build_preauth_cookie(runtime_secret(), runtime_secret(), true);

    assert_eq!(
        cookie.max_age(),
        Some(CookieDuration::seconds(LOGIN_TTL_SECONDS))
    );
    assert_eq!(cookie.path(), Some(PREAUTH_COOKIE_PATH));
    assert_eq!(cookie.http_only(), Some(true));
    assert_eq!(cookie.secure(), Some(true));
    assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    assert!(cookie.domain().is_none());
}
#[test]
fn local_loopback_configuration_explicitly_allows_non_secure_cookie() {
    let config = OidcConfig::for_tests();
    assert!(!config.secure_cookie());
}
#[test]
fn untrusted_peer_cannot_spoof_forwarded_client_ip() {
    let extractor = SmartIp::new();
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.42"));
    let peer = SocketAddr::from(([198, 51, 100, 10], 12345));

    let resolved =
        extract_client_ip(&extractor, &headers, peer).expect("client IP extraction must succeed");

    assert_eq!(resolved, peer.ip());
}
#[test]
fn trusted_proxy_resolves_forwarded_client_ip() {
    let trusted_proxy: IpNet = "10.0.0.0/8".parse().expect("trusted proxy CIDR must parse");
    let extractor = SmartIp::new().with_trusted_proxies([trusted_proxy]);
    let mut headers = HeaderMap::new();
    headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.42"));
    let peer = SocketAddr::from(([10, 0, 0, 2], 12345));

    let resolved =
        extract_client_ip(&extractor, &headers, peer).expect("client IP extraction must succeed");

    assert_eq!(resolved, IpAddr::from([203, 0, 113, 42]));
}
#[tokio::test]
async fn login_rate_limit_rejects_after_burst() {
    let requests_per_minute = NonZeroU32::new(LOGIN_REQUESTS_PER_MINUTE)
        .expect("login requests per minute must be non-zero");
    let burst = NonZeroU32::new(LOGIN_BURST).expect("login burst must be non-zero");
    let rate_limit = GovernorConfigBuilder::default()
        .with_extractor(SmartIp::new())
        .expect_connect_info()
        .quota_default(Quota::requests_per_minute(requests_per_minute).burst(burst))
        .finish()
        .expect("login rate-limit configuration must be valid");
    let peer = SocketAddr::from(([127, 0, 0, 1], 12345));
    let app = Router::new()
        .route("/", get(|| async { StatusCode::NO_CONTENT }))
        .layer(GovernorLayer::new(rate_limit))
        .layer(Extension(ConnectInfo(peer)));

    for _ in 0..LOGIN_BURST {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("request must be constructible"),
            )
            .await
            .expect("rate-limit test request must succeed");

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    let response = app
        .oneshot(
            Request::builder()
                .uri("/")
                .body(Body::empty())
                .expect("request must be constructible"),
        )
        .await
        .expect("rate-limit test request must succeed");

    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

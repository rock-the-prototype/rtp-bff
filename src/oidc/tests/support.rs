// Security rule for this module:
// private keys, client secrets, authorization codes, PKCE verifiers,
// access tokens, refresh tokens and ID tokens are generated at runtime.
// No credential or token fixture is persisted in the repository.

pub(super) use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub(super) use axum::{
    Extension, Router,
    body::{Body, to_bytes},
    extract::{ConnectInfo, Query, State},
    http::{
        HeaderMap, HeaderValue, Request, StatusCode,
        header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE},
    },
    response::IntoResponse,
    routing::{get, post},
};
pub(super) use axum_extra::extract::cookie::{CookieJar, SameSite};
pub(super) use axum_governor::{GovernorConfigBuilder, GovernorLayer, Quota, extractor::SmartIp};
pub(super) use ipnet::IpNet;
pub(super) use openidconnect::{
    AuthUrl, CsrfToken, EmptyAdditionalProviderMetadata, IssuerUrl, JsonWebKeyId, JsonWebKeySetUrl,
    Nonce, PkceCodeChallenge, PkceCodeVerifier, ResponseTypes, TokenUrl,
    core::{
        CoreIdToken, CoreJsonCurveType, CoreJsonWebKey, CoreJsonWebKeySet, CoreJwsSigningAlgorithm,
        CoreProviderMetadata, CoreResponseType, CoreSubjectIdentifierType,
    },
};
pub(super) use p256::ecdsa::{Signature, SigningKey, signature::Signer};
pub(super) use sha2::{Digest, Sha256};
pub(super) use time::Duration as CookieDuration;
pub(super) use tokio::sync::{Barrier, Mutex as AsyncMutex};
pub(super) use tower::ServiceExt;

pub(super) use crate::session::{SessionStore, session_cookie_name};

pub(super) use super::super::{
    LOGIN_BURST, LOGIN_REQUESTS_PER_MINUTE, OidcState,
    config::{CLIENT_ID, ISSUER, LOCAL_REDIRECT_URI, OidcConfig, validate_redirect_uri},
    handlers::{callback, extract_client_ip, login},
    provider::{build_http_client, verify_id_token_with_single_refresh},
    transaction::{
        AuthorizationTransaction, BROWSER_BINDING_BYTES, LOGIN_TTL, LOGIN_TTL_SECONDS,
        PREAUTH_COOKIE_PATH, build_preauth_cookie, hash_browser_binding, preauth_cookie_name,
    },
};

pub(super) const MOCK_ISSUER: &str = "https://mock.example";

pub(super) fn runtime_secret() -> String {
    CsrfToken::new_random_len(BROWSER_BINDING_BYTES)
        .secret()
        .to_owned()
}

fn unix_time_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after UNIX epoch")
        .as_secs()
}

fn base64_standard(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut output = String::with_capacity(input.len().div_ceil(3) * 4);

    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or_default();
        let third = chunk.get(2).copied().unwrap_or_default();

        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[(((first & 0b0000_0011) << 4) | (second >> 4)) as usize] as char);

        if chunk.len() > 1 {
            output.push(ALPHABET[(((second & 0b0000_1111) << 2) | (third >> 6)) as usize] as char);
        } else {
            output.push('=');
        }

        if chunk.len() > 2 {
            output.push(ALPHABET[(third & 0b0011_1111) as usize] as char);
        } else {
            output.push('=');
        }
    }

    output
}

fn expected_basic_authorization(client_id: &str, client_secret: &str) -> String {
    let credentials = format!("{client_id}:{client_secret}");
    format!("Basic {}", base64_standard(credentials.as_bytes()))
}

fn request_uses_expected_basic_auth(
    headers: &HeaderMap,
    client_id: &str,
    client_secret: &str,
) -> bool {
    let expected = expected_basic_authorization(client_id, client_secret);

    headers
        .get(AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == expected)
}

fn base64url_no_pad(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut output = String::with_capacity((input.len() * 4).div_ceil(3));

    for chunk in input.chunks(3) {
        let first = chunk[0];
        let second = chunk.get(1).copied().unwrap_or_default();
        let third = chunk.get(2).copied().unwrap_or_default();

        output.push(ALPHABET[(first >> 2) as usize] as char);
        output.push(ALPHABET[(((first & 0x03) << 4) | (second >> 4)) as usize] as char);

        if chunk.len() > 1 {
            output.push(ALPHABET[(((second & 0x0f) << 2) | (third >> 6)) as usize] as char);
        }

        if chunk.len() > 2 {
            output.push(ALPHABET[(third & 0x3f) as usize] as char);
        }
    }

    output
}

pub(super) struct EphemeralEs256Key {
    signing_key: SigningKey,
    pub(super) kid: String,
}

impl EphemeralEs256Key {
    pub(super) fn generate() -> Self {
        loop {
            let seed = runtime_secret();
            let candidate = Sha256::digest(seed.as_bytes());

            if let Ok(signing_key) = SigningKey::from_slice(&candidate) {
                return Self {
                    signing_key,
                    kid: runtime_secret(),
                };
            }
        }
    }

    pub(super) fn jwks(&self) -> CoreJsonWebKeySet {
        let encoded = self.signing_key.verifying_key().to_encoded_point(false);
        let x = encoded
            .x()
            .expect("P-256 public key must contain an x coordinate")
            .to_vec();
        let y = encoded
            .y()
            .expect("P-256 public key must contain a y coordinate")
            .to_vec();

        CoreJsonWebKeySet::new(vec![CoreJsonWebKey::new_ec(
            x,
            y,
            CoreJsonCurveType::P256,
            Some(JsonWebKeyId::new(self.kid.clone())),
        )])
    }

    pub(super) fn jwks_json(&self) -> String {
        let encoded = self.signing_key.verifying_key().to_encoded_point(false);
        let x = base64url_no_pad(
            encoded
                .x()
                .expect("P-256 public key must contain an x coordinate"),
        );
        let y = base64url_no_pad(
            encoded
                .y()
                .expect("P-256 public key must contain a y coordinate"),
        );

        format!(
            r#"{{"keys":[{{"kty":"EC","use":"sig","kid":"{}","alg":"ES256","crv":"P-256","x":"{x}","y":"{y}"}}]}}"#,
            self.kid
        )
    }

    pub(super) fn compact_id_token(&self, nonce: &str) -> String {
        self.compact_id_token_with_header(nonce, "ES256", &self.kid, MOCK_ISSUER)
    }

    fn compact_id_token_for_issuer(&self, nonce: &str, issuer: &str) -> String {
        self.compact_id_token_with_header(nonce, "ES256", &self.kid, issuer)
    }

    pub(super) fn compact_id_token_with_kid(&self, nonce: &str, kid: &str) -> String {
        self.compact_id_token_with_header(nonce, "ES256", kid, MOCK_ISSUER)
    }

    pub(super) fn compact_id_token_with_algorithm(&self, nonce: &str, algorithm: &str) -> String {
        self.compact_id_token_with_header(nonce, algorithm, &self.kid, MOCK_ISSUER)
    }

    fn compact_id_token_with_header(
        &self,
        nonce: &str,
        algorithm: &str,
        kid: &str,
        issuer: &str,
    ) -> String {
        let now = unix_time_seconds();
        let subject = runtime_secret();

        let header = format!(r#"{{"alg":"{algorithm}","typ":"JWT","kid":"{kid}"}}"#);
        let claims = format!(
            r#"{{"iss":"{issuer}","sub":"{subject}","aud":"{CLIENT_ID}","exp":{},"iat":{},"nonce":"{nonce}"}}"#,
            now + 300,
            now
        );

        let encoded_header = base64url_no_pad(header.as_bytes());
        let encoded_claims = base64url_no_pad(claims.as_bytes());
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        let signature: Signature = self.signing_key.sign(signing_input.as_bytes());
        let signature_bytes = signature.to_bytes();
        let encoded_signature = base64url_no_pad(&signature_bytes);

        format!("{signing_input}.{encoded_signature}")
    }

    pub(super) fn id_token(&self, nonce: &str) -> CoreIdToken {
        CoreIdToken::from_str(&self.compact_id_token(nonce))
            .expect("runtime-generated ES256 ID token must parse")
    }
}

pub(super) fn test_state() -> OidcState {
    let config = OidcConfig::for_tests();

    let client_ip_extractor =
        SmartIp::new().with_trusted_proxies(config.trusted_proxy_cidrs.clone());

    let http_client = build_http_client();

    OidcState {
        config: Arc::new(config),
        http_client,
        client_ip_extractor,
        provider_metadata: Arc::new(AsyncMutex::new(None)),
        session_store: SessionStore::for_tests(),
        pending: Arc::new(Mutex::new(HashMap::new())),
    }
}

pub(super) fn test_state_for_issuer(issuer: &str, client_secret: String) -> OidcState {
    let config = OidcConfig::from_values(
        issuer,
        CLIENT_ID,
        Some(client_secret),
        LOCAL_REDIRECT_URI.to_owned(),
        None,
    )
    .expect("runtime mock issuer configuration must be valid");

    let client_ip_extractor =
        SmartIp::new().with_trusted_proxies(config.trusted_proxy_cidrs.clone());

    let http_client = build_http_client();

    OidcState {
        config: Arc::new(config),
        http_client,
        client_ip_extractor,
        provider_metadata: Arc::new(AsyncMutex::new(None)),
        session_store: SessionStore::for_tests(),
        pending: Arc::new(Mutex::new(HashMap::new())),
    }
}

pub(super) fn mock_config() -> OidcConfig {
    OidcConfig::from_values(
        MOCK_ISSUER,
        CLIENT_ID,
        Some(runtime_secret()),
        "https://app.example.test/auth/callback".to_owned(),
        None,
    )
    .expect("runtime-generated OIDC mock configuration must be valid")
}

pub(super) fn mock_provider_metadata(
    jwks: CoreJsonWebKeySet,
    token_endpoint: &str,
) -> CoreProviderMetadata {
    CoreProviderMetadata::new(
        IssuerUrl::new(MOCK_ISSUER.to_owned()).expect("mock issuer must be valid"),
        AuthUrl::new("https://mock.example/authorize".to_owned())
            .expect("mock authorization URL must be valid"),
        JsonWebKeySetUrl::new("https://mock.example/jwks".to_owned())
            .expect("mock JWKS URL must be valid"),
        vec![ResponseTypes::new(vec![CoreResponseType::Code])],
        vec![CoreSubjectIdentifierType::Public],
        vec![CoreJwsSigningAlgorithm::EcdsaP256Sha256],
        EmptyAdditionalProviderMetadata {},
    )
    .set_token_endpoint(Some(
        TokenUrl::new(token_endpoint.to_owned()).expect("mock token URL must be valid"),
    ))
    .set_jwks(jwks)
}

pub(super) async fn install_mock_provider_metadata(
    state: &OidcState,
    signing_key: &EphemeralEs256Key,
    token_endpoint: &str,
) {
    let mut metadata = state.provider_metadata.lock().await;
    *metadata = Some(mock_provider_metadata(signing_key.jwks(), token_endpoint));
}

pub(super) struct MockTokenEndpoint {
    pub(super) url: String,
    pub(super) calls: Arc<AtomicUsize>,
}

fn form_value<'a>(body: &'a str, name: &str) -> Option<&'a str> {
    body.split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (key == name).then_some(value)
    })
}

pub(super) async fn spawn_mock_token_endpoint(
    id_token: String,
    expected_code: Option<String>,
    expected_verifier: Option<String>,
    expected_client_secret: String,
) -> MockTokenEndpoint {
    let calls = Arc::new(AtomicUsize::new(0));
    let access_token = runtime_secret();
    let refresh_token = runtime_secret();

    let handler_calls = calls.clone();
    let handler_access_token = access_token.clone();
    let handler_refresh_token = refresh_token.clone();
    let expected_code = Arc::new(expected_code);
    let expected_verifier = Arc::new(expected_verifier);
    let expected_client_secret = Arc::new(expected_client_secret);

    let app = Router::new().route(
        "/token",
        post(move |headers: HeaderMap, body: String| {
            let calls = handler_calls.clone();
            let access_token = handler_access_token.clone();
            let refresh_token = handler_refresh_token.clone();
            let id_token = id_token.clone();
            let expected_code = expected_code.clone();
            let expected_verifier = expected_verifier.clone();
            let expected_client_secret = expected_client_secret.clone();

            async move {
                calls.fetch_add(1, Ordering::SeqCst);

                if form_value(&body, "client_secret").is_some() {
                    return (
                        StatusCode::BAD_REQUEST,
                        [(CONTENT_TYPE, "application/json")],
                        r#"{"error":"invalid_client"}"#.to_owned(),
                    )
                        .into_response();
                }

                if !request_uses_expected_basic_auth(
                    &headers,
                    CLIENT_ID,
                    expected_client_secret.as_str(),
                ) {
                    return (
                        StatusCode::UNAUTHORIZED,
                        [(CONTENT_TYPE, "application/json")],
                        r#"{"error":"invalid_client"}"#.to_owned(),
                    )
                        .into_response();
                }

                let code_matches = expected_code
                    .as_ref()
                    .as_ref()
                    .is_none_or(|expected| form_value(&body, "code") == Some(expected.as_str()));
                let verifier_matches = expected_verifier.as_ref().as_ref().is_none_or(
                    |expected| form_value(&body, "code_verifier") == Some(expected.as_str()),
                );

                if !code_matches || !verifier_matches {
                    return (
                        StatusCode::BAD_REQUEST,
                        [(CONTENT_TYPE, "application/json")],
                        r#"{"error":"invalid_grant"}"#.to_owned(),
                    )
                        .into_response();
                }

                let response = format!(
                    r#"{{"access_token":"{access_token}","refresh_token":"{refresh_token}","token_type":"Bearer","expires_in":300,"id_token":"{id_token}"}}"#
                );

                (
                    StatusCode::OK,
                    [(CONTENT_TYPE, "application/json")],
                    response,
                )
                    .into_response()
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock token endpoint must bind");
    let address = listener
        .local_addr()
        .expect("mock token endpoint must have an address");

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("mock token endpoint must run");
    });

    MockTokenEndpoint {
        url: format!("http://{address}/token"),
        calls,
    }
}

#[derive(Clone)]
struct MockProviderState {
    issuer: String,
    jwks: Arc<Mutex<String>>,
    rotate_jwks_on_token: Option<String>,
    id_token: String,
    access_token: String,
    refresh_token: String,
    expected_code: String,
    expected_verifier: String,
    expected_client_secret: String,
    discovery_calls: Arc<AtomicUsize>,
    jwks_calls: Arc<AtomicUsize>,
    token_calls: Arc<AtomicUsize>,
    client_auth_failures: Arc<AtomicUsize>,
    client_secret_body_violations: Arc<AtomicUsize>,
}

pub(super) struct MockOidcProvider {
    pub(super) issuer: String,
    pub(super) discovery_calls: Arc<AtomicUsize>,
    pub(super) jwks_calls: Arc<AtomicUsize>,
    pub(super) token_calls: Arc<AtomicUsize>,
    pub(super) client_auth_failures: Arc<AtomicUsize>,
    pub(super) client_secret_body_violations: Arc<AtomicUsize>,
    pub(super) access_token: String,
    pub(super) refresh_token: String,
}

async fn mock_discovery(State(state): State<MockProviderState>) -> impl IntoResponse {
    state.discovery_calls.fetch_add(1, Ordering::SeqCst);

    let document = format!(
        r#"{{"issuer":"{0}","authorization_endpoint":"{0}/authorize","token_endpoint":"{0}/token","jwks_uri":"{0}/jwks","response_types_supported":["code"],"subject_types_supported":["public"],"id_token_signing_alg_values_supported":["ES256"],"token_endpoint_auth_methods_supported":["client_secret_basic"]}}"#,
        state.issuer
    );

    (
        StatusCode::OK,
        [(CONTENT_TYPE, "application/json")],
        document,
    )
}

async fn mock_jwks(State(state): State<MockProviderState>) -> impl IntoResponse {
    state.jwks_calls.fetch_add(1, Ordering::SeqCst);

    let document = state
        .jwks
        .lock()
        .expect("runtime JWKS store must be lockable")
        .clone();

    (
        StatusCode::OK,
        [(CONTENT_TYPE, "application/json")],
        document,
    )
}

async fn mock_provider_token(
    State(state): State<MockProviderState>,
    headers: HeaderMap,
    body: String,
) -> axum::response::Response {
    state.token_calls.fetch_add(1, Ordering::SeqCst);

    if form_value(&body, "client_secret").is_some() {
        state
            .client_secret_body_violations
            .fetch_add(1, Ordering::SeqCst);

        return (
            StatusCode::BAD_REQUEST,
            [(CONTENT_TYPE, "application/json")],
            r#"{"error":"invalid_client"}"#.to_owned(),
        )
            .into_response();
    }

    if !request_uses_expected_basic_auth(&headers, CLIENT_ID, &state.expected_client_secret) {
        state.client_auth_failures.fetch_add(1, Ordering::SeqCst);

        return (
            StatusCode::UNAUTHORIZED,
            [(CONTENT_TYPE, "application/json")],
            r#"{"error":"invalid_client"}"#.to_owned(),
        )
            .into_response();
    }

    let valid_code = form_value(&body, "code") == Some(state.expected_code.as_str());
    let valid_verifier =
        form_value(&body, "code_verifier") == Some(state.expected_verifier.as_str());

    if !valid_code || !valid_verifier {
        return (
            StatusCode::BAD_REQUEST,
            [(CONTENT_TYPE, "application/json")],
            r#"{"error":"invalid_grant"}"#.to_owned(),
        )
            .into_response();
    }

    if let Some(rotated) = state.rotate_jwks_on_token.as_ref() {
        *state
            .jwks
            .lock()
            .expect("runtime JWKS store must be lockable") = rotated.clone();
    }

    let response = format!(
        r#"{{"access_token":"{}","refresh_token":"{}","token_type":"Bearer","expires_in":300,"id_token":"{}"}}"#,
        state.access_token, state.refresh_token, state.id_token
    );

    (
        StatusCode::OK,
        [(CONTENT_TYPE, "application/json")],
        response,
    )
        .into_response()
}

pub(super) async fn spawn_mock_oidc_provider(
    initial_jwks: String,
    rotate_jwks_on_token: Option<String>,
    token_signing_key: &EphemeralEs256Key,
    nonce: &str,
    expected_code: String,
    expected_verifier: String,
    expected_client_secret: String,
) -> MockOidcProvider {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("mock OIDC provider must bind");
    let address = listener
        .local_addr()
        .expect("mock OIDC provider must have an address");
    let issuer = format!("http://{address}");
    let id_token = token_signing_key.compact_id_token_for_issuer(nonce, &issuer);

    let discovery_calls = Arc::new(AtomicUsize::new(0));
    let jwks_calls = Arc::new(AtomicUsize::new(0));
    let token_calls = Arc::new(AtomicUsize::new(0));
    let client_auth_failures = Arc::new(AtomicUsize::new(0));
    let client_secret_body_violations = Arc::new(AtomicUsize::new(0));
    let access_token = runtime_secret();
    let refresh_token = runtime_secret();

    let state = MockProviderState {
        issuer: issuer.clone(),
        jwks: Arc::new(Mutex::new(initial_jwks)),
        rotate_jwks_on_token,
        id_token,
        access_token: access_token.clone(),
        refresh_token: refresh_token.clone(),
        expected_code,
        expected_verifier,
        expected_client_secret,
        discovery_calls: discovery_calls.clone(),
        jwks_calls: jwks_calls.clone(),
        token_calls: token_calls.clone(),
        client_auth_failures: client_auth_failures.clone(),
        client_secret_body_violations: client_secret_body_violations.clone(),
    };

    let app = Router::new()
        .route("/.well-known/openid-configuration", get(mock_discovery))
        .route("/jwks", get(mock_jwks))
        .route("/token", post(mock_provider_token))
        .with_state(state);

    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("mock OIDC provider must run");
    });

    MockOidcProvider {
        issuer,
        discovery_calls,
        jwks_calls,
        token_calls,
        client_auth_failures,
        client_secret_body_violations,
        access_token,
        refresh_token,
    }
}

pub(super) fn request_cookie_jar(cookies: &[(&str, &str)]) -> CookieJar {
    let cookie_header = cookies
        .iter()
        .map(|(name, value)| format!("{name}={value}"))
        .collect::<Vec<_>>()
        .join("; ");

    let mut headers = HeaderMap::new();
    headers.insert(
        COOKIE,
        HeaderValue::from_str(&cookie_header).expect("runtime cookie header must be valid"),
    );

    CookieJar::from_headers(&headers)
}

pub(super) fn response_removes_cookie(
    response: &axum::response::Response,
    cookie_name: &str,
) -> bool {
    response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(|set_cookie| {
            set_cookie.starts_with(&format!("{cookie_name}="))
                && (set_cookie.contains("Max-Age=0") || set_cookie.contains("Expires="))
        })
}

pub(super) fn insert_transaction_with(
    state: &OidcState,
    state_key: &str,
    binding: &str,
    pkce_verifier: PkceCodeVerifier,
    nonce: Nonce,
    created_at: Instant,
) {
    state
        .pending
        .lock()
        .expect("pending transaction store must be lockable")
        .insert(
            state_key.to_owned(),
            AuthorizationTransaction {
                pkce_verifier,
                nonce,
                browser_binding_hash: hash_browser_binding(binding),
                created_at,
                client_ip: IpAddr::from([127, 0, 0, 1]),
            },
        );
}

pub(super) fn insert_random_transaction(state: &OidcState, state_key: &str, binding: &str) {
    let (_, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    insert_transaction_with(
        state,
        state_key,
        binding,
        pkce_verifier,
        Nonce::new_random(),
        Instant::now(),
    );
}

use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

#[cfg(not(test))]
use std::env;

use axum::{
    Router,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, Request, StatusCode},
    response::Redirect,
    routing::get,
};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use axum_governor::{
    GovernorConfigBuilder, GovernorLayer, Quota,
    extractor::{KeyExtractor, SmartIp},
};
use ipnet::IpNet;
use openidconnect::{
    AuthorizationCode, ClaimsVerificationError, ClientId, ClientSecret, CsrfToken, IssuerUrl,
    Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, SignatureVerificationError,
    TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreIdToken, CoreProviderMetadata},
    reqwest,
};
use sha2::{Digest, Sha256};
use time::Duration as CookieDuration;
use tokio::sync::Mutex as AsyncMutex;

const ISSUER: &str = "https://id.rock-the-prototype.com/realms/RTP";
const CLIENT_ID: &str = "rtp-web";

const CLIENT_SECRET_ENV: &str = "RTP_OIDC_CLIENT_SECRET";

#[cfg(not(test))]
const REDIRECT_URI_ENV: &str = "RTP_OIDC_REDIRECT_URI";

#[cfg(not(test))]
const TRUSTED_PROXY_CIDRS_ENV: &str = "RTP_TRUSTED_PROXY_CIDRS";

const LOCAL_REDIRECT_URI: &str = "http://127.0.0.1:3000/auth/callback";

const LOGIN_TTL_SECONDS: i64 = 300;
const LOGIN_TTL: Duration = Duration::from_secs(LOGIN_TTL_SECONDS as u64);

const MAX_PENDING_LOGINS: usize = 128;
const MAX_PENDING_LOGINS_PER_CLIENT: usize = 8;

const LOGIN_REQUESTS_PER_MINUTE: u32 = 10;
const LOGIN_BURST: u32 = 4;

const OIDC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OIDC_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

const PREAUTH_COOKIE_PREFIX: &str = "rtp-preauth";
const PREAUTH_COOKIE_PATH: &str = "/auth/callback";
const BROWSER_BINDING_BYTES: u32 = 32;

#[derive(Clone)]
struct OidcConfig {
    issuer: IssuerUrl,
    client_id: String,
    client_secret: String,
    redirect_uri: RedirectUrl,
    trusted_proxy_cidrs: Vec<IpNet>,
}

impl OidcConfig {
    #[cfg(not(test))]
    fn from_env() -> Result<Self, String> {
        Self::from_values(
            ISSUER,
            CLIENT_ID,
            env::var(CLIENT_SECRET_ENV).ok(),
            env::var(REDIRECT_URI_ENV).unwrap_or_else(|_| LOCAL_REDIRECT_URI.to_owned()),
            env::var(TRUSTED_PROXY_CIDRS_ENV).ok(),
        )
    }

    fn from_values(
        issuer_raw: &str,
        client_id: &str,
        client_secret: Option<String>,
        redirect_raw: String,
        trusted_proxy_cidrs_raw: Option<String>,
    ) -> Result<Self, String> {
        let client_secret =
            client_secret.ok_or_else(|| format!("{CLIENT_SECRET_ENV} is required"))?;

        if client_secret.trim().is_empty() {
            return Err(format!("{CLIENT_SECRET_ENV} must not be empty"));
        }

        let issuer = IssuerUrl::new(issuer_raw.to_owned())
            .map_err(|_| "OIDC issuer URL is invalid".to_owned())?;

        let redirect_uri = validate_redirect_uri(redirect_raw)
            .map_err(|_| "OIDC redirect URI is invalid or insecure".to_owned())?;

        let trusted_proxy_cidrs = parse_trusted_proxy_cidrs(trusted_proxy_cidrs_raw)?;

        Ok(Self {
            issuer,
            client_id: client_id.to_owned(),
            client_secret,
            redirect_uri,
            trusted_proxy_cidrs,
        })
    }

    #[cfg(test)]
    fn for_tests() -> Self {
        Self::from_values(
            ISSUER,
            CLIENT_ID,
            Some("synthetic-test-client-secret".to_owned()),
            LOCAL_REDIRECT_URI.to_owned(),
            None,
        )
        .expect("synthetic OIDC test configuration must be valid")
    }

    fn secure_cookie(&self) -> bool {
        self.redirect_uri.url().scheme() == "https"
    }
}

struct AuthorizationTransaction {
    pkce_verifier: PkceCodeVerifier,
    nonce: Nonce,
    browser_binding_hash: [u8; 32],
    created_at: Instant,
    client_ip: IpAddr,
}

#[derive(Clone)]
struct OidcState {
    config: Arc<OidcConfig>,
    http_client: reqwest::Client,
    client_ip_extractor: SmartIp,
    provider_metadata: Arc<AsyncMutex<Option<CoreProviderMetadata>>>,
    pending: Arc<Mutex<HashMap<String, AuthorizationTransaction>>>,
}

type CallbackResult = Result<(CookieJar, StatusCode), (CookieJar, StatusCode)>;

fn parse_trusted_proxy_cidrs(raw: Option<String>) -> Result<Vec<IpNet>, String> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };

    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value
                .parse::<IpNet>()
                .map_err(|_| format!("invalid trusted proxy CIDR: {value}"))
        })
        .collect()
}

fn preauth_cookie_name(state: &str) -> String {
    let digest = Sha256::digest(state.as_bytes());

    let suffix = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    format!("{PREAUTH_COOKIE_PREFIX}-{suffix}")
}

fn hash_browser_binding(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

fn build_preauth_cookie(
    cookie_name: String,
    browser_binding_secret: String,
    secure: bool,
) -> Cookie<'static> {
    Cookie::build((cookie_name, browser_binding_secret))
        .path(PREAUTH_COOKIE_PATH)
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Lax)
        .max_age(CookieDuration::seconds(LOGIN_TTL_SECONDS))
        .build()
}

fn remove_preauth_cookie(jar: CookieJar, cookie_name: String, secure: bool) -> CookieJar {
    jar.remove(
        Cookie::build(cookie_name)
            .path(PREAUTH_COOKIE_PATH)
            .http_only(true)
            .secure(secure)
            .same_site(SameSite::Lax)
            .build(),
    )
}

fn extract_client_ip(
    extractor: &SmartIp,
    headers: &HeaderMap,
    peer: SocketAddr,
) -> Result<IpAddr, StatusCode> {
    let mut request = Request::new(());
    *request.headers_mut() = headers.clone();
    request.extensions_mut().insert(ConnectInfo(peer));

    let (parts, _) = request.into_parts();

    extractor
        .extract(&parts)
        .map(|outcome| outcome.key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

fn take_bound_transaction(
    state: &OidcState,
    returned_state: &str,
    presented_binding_hash: [u8; 32],
) -> Result<AuthorizationTransaction, StatusCode> {
    let mut pending = state
        .pending
        .lock()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    pending.retain(|_, transaction| transaction.created_at.elapsed() < LOGIN_TTL);

    let binding_matches = pending
        .get(returned_state)
        .map(|transaction| transaction.browser_binding_hash == presented_binding_hash)
        .ok_or(StatusCode::BAD_REQUEST)?;

    if !binding_matches {
        return Err(StatusCode::BAD_REQUEST);
    }

    pending
        .remove(returned_state)
        .ok_or(StatusCode::BAD_REQUEST)
}

pub fn router() -> Router {
    #[cfg(test)]
    let config = OidcConfig::for_tests();

    #[cfg(not(test))]
    let config = OidcConfig::from_env().unwrap_or_else(|error| {
        panic!("OIDC startup configuration invalid: {error}");
    });

    router_with_config(config)
}

fn router_with_config(config: OidcConfig) -> Router {
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(OIDC_CONNECT_TIMEOUT)
        .timeout(OIDC_REQUEST_TIMEOUT)
        .build()
        .expect("OIDC HTTP client must be constructible");

    let client_ip_extractor =
        SmartIp::new().with_trusted_proxies(config.trusted_proxy_cidrs.clone());

    let login_requests_per_minute = NonZeroU32::new(LOGIN_REQUESTS_PER_MINUTE)
        .expect("login requests per minute must be non-zero");

    let login_burst = NonZeroU32::new(LOGIN_BURST).expect("login burst must be non-zero");

    let login_rate_limit = GovernorConfigBuilder::default()
        .with_extractor(client_ip_extractor.clone())
        .expect_connect_info()
        .quota_default(Quota::requests_per_minute(login_requests_per_minute).burst(login_burst))
        .finish()
        .expect("login rate-limit configuration must be valid");

    let state = OidcState {
        config: Arc::new(config),
        http_client,
        client_ip_extractor,
        provider_metadata: Arc::new(AsyncMutex::new(None)),
        pending: Arc::new(Mutex::new(HashMap::new())),
    };

    let login_router = Router::new()
        .route("/auth/login", get(login))
        .layer(GovernorLayer::new(login_rate_limit));

    Router::new()
        .merge(login_router)
        .route("/auth/callback", get(callback))
        .with_state(state)
}

async fn provider_metadata(state: &OidcState) -> Result<CoreProviderMetadata, StatusCode> {
    let mut cached = state.provider_metadata.lock().await;

    if let Some(metadata) = cached.as_ref() {
        return Ok(metadata.clone());
    }

    let metadata =
        CoreProviderMetadata::discover_async(state.config.issuer.clone(), &state.http_client)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;

    *cached = Some(metadata.clone());

    Ok(metadata)
}

async fn refresh_provider_metadata(state: &OidcState) -> Result<CoreProviderMetadata, StatusCode> {
    let metadata =
        CoreProviderMetadata::discover_async(state.config.issuer.clone(), &state.http_client)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let mut cached = state.provider_metadata.lock().await;
    *cached = Some(metadata.clone());

    Ok(metadata)
}

fn verify_id_token_once(
    config: &OidcConfig,
    provider_metadata: &CoreProviderMetadata,
    id_token: &CoreIdToken,
    nonce: &Nonce,
) -> Result<(), ClaimsVerificationError> {
    let client = CoreClient::from_provider_metadata(
        provider_metadata.clone(),
        ClientId::new(config.client_id.clone()),
        Some(ClientSecret::new(config.client_secret.clone())),
    )
    .set_redirect_uri(config.redirect_uri.clone());

    let verifier = client.id_token_verifier();

    id_token.claims(&verifier, nonce).map(|_| ())
}

async fn verify_id_token_with_single_refresh<F, Fut>(
    config: &OidcConfig,
    initial_metadata: CoreProviderMetadata,
    id_token: &CoreIdToken,
    nonce: &Nonce,
    refresh: F,
) -> Result<(), StatusCode>
where
    F: FnOnce() -> Fut,
    Fut: Future<Output = Result<CoreProviderMetadata, StatusCode>>,
{
    match verify_id_token_once(config, &initial_metadata, id_token, nonce) {
        Ok(()) => Ok(()),

        Err(ClaimsVerificationError::SignatureVerification(
            SignatureVerificationError::NoMatchingKey,
        )) => {
            let refreshed_metadata = refresh().await?;

            verify_id_token_once(config, &refreshed_metadata, id_token, nonce)
                .map_err(|_| StatusCode::UNAUTHORIZED)
        }

        Err(_) => Err(StatusCode::UNAUTHORIZED),
    }
}

async fn login(
    State(state): State<OidcState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    jar: CookieJar,
) -> Result<(CookieJar, Redirect), StatusCode> {
    let provider_metadata = provider_metadata(&state).await?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(state.config.client_id.clone()),
        None,
    )
    .set_redirect_uri(state.config.redirect_uri.clone());

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    let browser_binding = CsrfToken::new_random_len(BROWSER_BINDING_BYTES);
    let browser_binding_secret = browser_binding.secret().to_owned();
    let browser_binding_hash = hash_browser_binding(&browser_binding_secret);

    let (authorization_url, csrf_token, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_owned()))
        .add_scope(Scope::new("email".to_owned()))
        .set_pkce_challenge(pkce_challenge)
        .url();

    let state_key = csrf_token.secret().to_owned();
    let transaction_cookie_name = preauth_cookie_name(&state_key);

    let client_ip = extract_client_ip(&state.client_ip_extractor, &headers, peer)?;

    {
        let mut pending = state
            .pending
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        pending.retain(|_, transaction| transaction.created_at.elapsed() < LOGIN_TTL);

        let pending_for_client = pending
            .values()
            .filter(|transaction| transaction.client_ip == client_ip)
            .count();

        if pending_for_client >= MAX_PENDING_LOGINS_PER_CLIENT {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        if pending.len() >= MAX_PENDING_LOGINS {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        pending.insert(
            state_key,
            AuthorizationTransaction {
                pkce_verifier,
                nonce,
                browser_binding_hash,
                created_at: Instant::now(),
                client_ip,
            },
        );
    }

    let preauth_cookie = build_preauth_cookie(
        transaction_cookie_name,
        browser_binding_secret,
        state.config.secure_cookie(),
    );

    let jar = jar.add(preauth_cookie);

    Ok((jar, Redirect::temporary(authorization_url.as_str())))
}

async fn callback(
    State(state): State<OidcState>,
    Query(params): Query<HashMap<String, String>>,
    jar: CookieJar,
) -> CallbackResult {
    let returned_state = match params.get("state") {
        Some(state) => state.clone(),
        None => return Err((jar, StatusCode::BAD_REQUEST)),
    };

    let transaction_cookie_name = preauth_cookie_name(&returned_state);

    let has_error = params.contains_key("error");
    let code = params.get("code").cloned();

    if !has_error && code.is_none() {
        return Err((jar, StatusCode::BAD_REQUEST));
    }

    let browser_binding_secret = match jar.get(&transaction_cookie_name) {
        Some(cookie) => cookie.value().to_owned(),
        None => return Err((jar, StatusCode::BAD_REQUEST)),
    };

    let presented_binding_hash = hash_browser_binding(&browser_binding_secret);

    let transaction = match take_bound_transaction(&state, &returned_state, presented_binding_hash)
    {
        Ok(transaction) => transaction,
        Err(status) => return Err((jar, status)),
    };

    let jar = remove_preauth_cookie(jar, transaction_cookie_name, state.config.secure_cookie());

    if has_error {
        return Err((jar, StatusCode::BAD_REQUEST));
    }

    let code = match code {
        Some(code) => code,
        None => return Err((jar, StatusCode::BAD_REQUEST)),
    };

    let provider_metadata = match provider_metadata(&state).await {
        Ok(metadata) => metadata,
        Err(status) => return Err((jar, status)),
    };

    let client = CoreClient::from_provider_metadata(
        provider_metadata.clone(),
        ClientId::new(state.config.client_id.clone()),
        Some(ClientSecret::new(state.config.client_secret.clone())),
    )
    .set_redirect_uri(state.config.redirect_uri.clone());

    let token_response = match client.exchange_code(AuthorizationCode::new(code)) {
        Ok(exchange) => match exchange
            .set_pkce_verifier(transaction.pkce_verifier)
            .request_async(&state.http_client)
            .await
        {
            Ok(response) => response,
            Err(_) => return Err((jar, StatusCode::BAD_GATEWAY)),
        },

        Err(_) => return Err((jar, StatusCode::BAD_GATEWAY)),
    };

    let id_token = match token_response.id_token() {
        Some(id_token) => id_token,
        None => return Err((jar, StatusCode::UNAUTHORIZED)),
    };

    let verification = verify_id_token_with_single_refresh(
        &state.config,
        provider_metadata,
        id_token,
        &transaction.nonce,
        || refresh_provider_metadata(&state),
    )
    .await;

    match verification {
        Ok(()) => Ok((jar, StatusCode::NO_CONTENT)),
        Err(status) => Err((jar, status)),
    }
}

fn validate_redirect_uri(raw: String) -> Result<RedirectUrl, StatusCode> {
    let redirect = RedirectUrl::new(raw).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let url = redirect.url();

    let is_loopback = matches!(
        url.host_str(),
        Some("127.0.0.1") | Some("localhost") | Some("::1") | Some("[::1]")
    );

    let is_https = url.scheme() == "https";
    let is_loopback_http = url.scheme() == "http" && is_loopback;

    if !is_https && !is_loopback_http {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(redirect)
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        str::FromStr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use axum::{
        Extension,
        body::Body,
        http::{
            HeaderValue, Request,
            header::{COOKIE, SET_COOKIE},
        },
        response::IntoResponse,
        routing::get,
    };

    use openidconnect::{
        AuthUrl, EmptyAdditionalProviderMetadata, JsonWebKeySetUrl, ResponseTypes, TokenUrl,
        core::{
            CoreJsonWebKeySet, CoreJwsSigningAlgorithm, CoreResponseType, CoreSubjectIdentifierType,
        },
    };

    use tokio::sync::Barrier;
    use tower::ServiceExt;

    const MOCK_ISSUER: &str = "https://mock.example";

    const JWKS_A: &str = r#"{
      "keys": [
        {
          "kty": "EC",
          "use": "sig",
          "kid": "key-a",
          "alg": "ES256",
          "crv": "P-256",
          "x": "rVcaLS_fV6M5-yB5EgeT04wKFEhnx_VZEDqU5wVf55I",
          "y": "OL87zFW5QiZq2p7u0THQQhBDK9LFlvVSpW4rBkJ2gjI"
        }
      ]
    }"#;

    const JWKS_B: &str = r#"{
      "keys": [
        {
          "kty": "EC",
          "use": "sig",
          "kid": "key-b",
          "alg": "ES256",
          "crv": "P-256",
          "x": "goimyeigIrEPrmO2dkzBzlOj8ErbOLmMlOR3W9SUgGg",
          "y": "v6yxUHprnSRksHKrQNGPCmwN8CkhxTzBzdjtV0F2Lqg"
        }
      ]
    }"#;

    // Purely synthetic ES256 test tokens. No production identity,
    // production key, production token or real user data is contained here.
    const VALID_TOKEN_KEY_A: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS1hIn0.eyJpc3MiOiJodHRwczovL21vY2suZXhhbXBsZSIsInN1YiI6InN5bnRoZXRpYy11c2VyIiwiYXVkIjoicnRwLXdlYiIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJub25jZSI6ImV4cGVjdGVkLW5vbmNlIn0.Ex3NnyhbjcI-1zZjqiD7114lxWBP7lRORt6kxIpqGcfK3-NyZCfrjIIdjrA5p_70IOdjD27Vb2zn285yIqkU_A";

    const VALID_TOKEN_KEY_B: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS1iIn0.eyJpc3MiOiJodHRwczovL21vY2suZXhhbXBsZSIsInN1YiI6InN5bnRoZXRpYy11c2VyIiwiYXVkIjoicnRwLXdlYiIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJub25jZSI6ImV4cGVjdGVkLW5vbmNlIn0.h6YJ15__7gOl9RdTkHRbhVHgMMEctOZ-Z6pTBIrTUy_odIABCm3IdMDTJP0cooGvnXP5QfF8QuvaxlPPQvnQ-w";

    // Header declares kid=key-a, but the token is signed with synthetic key-b.
    const INVALID_SIGNATURE_TOKEN: &str = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtleS1hIn0.eyJpc3MiOiJodHRwczovL21vY2suZXhhbXBsZSIsInN1YiI6InN5bnRoZXRpYy11c2VyIiwiYXVkIjoicnRwLXdlYiIsImV4cCI6NDEwMjQ0NDgwMCwiaWF0IjoxNzAwMDAwMDAwLCJub25jZSI6ImV4cGVjdGVkLW5vbmNlIn0.mKEsTXglylOZByCq2WMyc3EBs88uJry7d4fWqFus4v3Xy4w3_y5WrFmFea86WuMYZ6x8MkrM5vIg8UzjfbR54g";

    fn test_state() -> OidcState {
        let config = OidcConfig::for_tests();

        let client_ip_extractor =
            SmartIp::new().with_trusted_proxies(config.trusted_proxy_cidrs.clone());

        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(OIDC_CONNECT_TIMEOUT)
            .timeout(OIDC_REQUEST_TIMEOUT)
            .build()
            .expect("synthetic OIDC HTTP client must be constructible");

        OidcState {
            config: Arc::new(config),
            http_client,
            client_ip_extractor,
            provider_metadata: Arc::new(AsyncMutex::new(None)),
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn mock_config() -> OidcConfig {
        OidcConfig::from_values(
            MOCK_ISSUER,
            CLIENT_ID,
            Some("synthetic-test-client-secret".to_owned()),
            "https://app.example.test/auth/callback".to_owned(),
            None,
        )
        .expect("mock OIDC configuration must be valid")
    }

    fn mock_provider_metadata(jwks_json: &str) -> CoreProviderMetadata {
        let jwks: CoreJsonWebKeySet =
            serde_json::from_str(jwks_json).expect("synthetic JWKS must deserialize");

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
            TokenUrl::new("https://mock.example/token".to_owned())
                .expect("mock token URL must be valid"),
        ))
        .set_jwks(jwks)
    }

    fn parse_test_id_token(raw: &str) -> CoreIdToken {
        CoreIdToken::from_str(raw).expect("synthetic ID token must parse")
    }

    fn insert_transaction(state: &OidcState, state_key: &str, binding: &str) {
        let (_, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

        state
            .pending
            .lock()
            .expect("pending transaction store must be lockable")
            .insert(
                state_key.to_owned(),
                AuthorizationTransaction {
                    pkce_verifier,
                    nonce: Nonce::new_random(),
                    browser_binding_hash: hash_browser_binding(binding),
                    created_at: Instant::now(),
                    client_ip: IpAddr::from([127, 0, 0, 1]),
                },
            );
    }

    #[test]
    fn local_ipv4_http_redirect_is_allowed() {
        let result = validate_redirect_uri("http://127.0.0.1:3000/auth/callback".to_owned());

        assert!(result.is_ok());
    }

    #[test]
    fn localhost_http_redirect_is_allowed() {
        let result = validate_redirect_uri("http://localhost:3000/auth/callback".to_owned());

        assert!(result.is_ok());
    }

    #[test]
    fn non_loopback_https_redirect_is_allowed() {
        let result = validate_redirect_uri("https://example.test/auth/callback".to_owned());

        assert!(result.is_ok());
    }

    #[test]
    fn non_loopback_http_redirect_is_rejected() {
        let result = validate_redirect_uri("http://example.test/auth/callback".to_owned());

        assert_eq!(result, Err(StatusCode::INTERNAL_SERVER_ERROR));
    }

    #[test]
    fn non_http_loopback_redirect_is_rejected() {
        let result = validate_redirect_uri("ftp://localhost/auth/callback".to_owned());

        assert_eq!(result, Err(StatusCode::INTERNAL_SERVER_ERROR));
    }

    #[test]
    fn malformed_redirect_uri_is_rejected() {
        let result = validate_redirect_uri("not a valid URI".to_owned());

        assert_eq!(result, Err(StatusCode::INTERNAL_SERVER_ERROR));
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
            Some("   ".to_owned()),
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
            Some("synthetic-secret".to_owned()),
            LOCAL_REDIRECT_URI.to_owned(),
            Some("this-is-not-a-cidr".to_owned()),
        );

        assert!(result.is_err());
    }

    #[test]
    fn preauth_cookie_has_bounded_lifetime() {
        let cookie = build_preauth_cookie(
            "rtp-preauth-test".to_owned(),
            "synthetic-binding".to_owned(),
            true,
        );

        assert_eq!(
            cookie.max_age(),
            Some(CookieDuration::seconds(LOGIN_TTL_SECONDS))
        );
        assert_eq!(cookie.path(), Some(PREAUTH_COOKIE_PATH));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax));
    }

    #[test]
    fn untrusted_peer_cannot_spoof_forwarded_client_ip() {
        let extractor = SmartIp::new();

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.42"));

        let peer = SocketAddr::from(([198, 51, 100, 10], 12345));

        let resolved = extract_client_ip(&extractor, &headers, peer)
            .expect("client IP extraction must succeed");

        assert_eq!(resolved, peer.ip());
    }

    #[test]
    fn trusted_proxy_resolves_forwarded_client_ip() {
        let trusted_proxy: IpNet = "10.0.0.0/8".parse().expect("trusted proxy CIDR must parse");

        let extractor = SmartIp::new().with_trusted_proxies([trusted_proxy]);

        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", HeaderValue::from_static("203.0.113.42"));

        let peer = SocketAddr::from(([10, 0, 0, 2], 12345));

        let resolved = extract_client_ip(&extractor, &headers, peer)
            .expect("client IP extraction must succeed");

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

    #[tokio::test]
    async fn oidc_error_callback_consumes_transaction_and_removes_cookie() {
        let state = test_state();

        let state_key = "test-state".to_owned();
        let browser_binding_secret = "test-browser-binding";

        insert_transaction(&state, &state_key, browser_binding_secret);

        let params = HashMap::from([
            ("error".to_owned(), "access_denied".to_owned()),
            ("state".to_owned(), state_key.clone()),
        ]);

        let cookie_name = preauth_cookie_name(&state_key);
        let mut request_headers = HeaderMap::new();

        request_headers.insert(
            COOKIE,
            HeaderValue::from_str(&format!("{cookie_name}={browser_binding_secret}"))
                .expect("synthetic request cookie header must be valid"),
        );

        let jar = CookieJar::from_headers(&request_headers);

        let result = callback(State(state.clone()), Query(params), jar).await;

        let (returned_jar, status) =
            result.expect_err("OIDC error callback must return an error response");

        assert_eq!(status, StatusCode::BAD_REQUEST);

        let pending = state
            .pending
            .lock()
            .expect("pending transaction store must be lockable");

        assert!(!pending.contains_key(&state_key));
        drop(pending);

        let response = (returned_jar, status).into_response();

        let removal_found = response
            .headers()
            .get_all(SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .any(|set_cookie| {
                set_cookie.starts_with(&format!("{cookie_name}="))
                    && (set_cookie.contains("Max-Age=0") || set_cookie.contains("Expires="))
            });

        assert!(
            removal_found,
            "consumed transaction must remove pre-auth cookie"
        );
    }

    #[tokio::test]
    async fn wrong_browser_binding_does_not_consume_transaction() {
        let state = test_state();

        let state_key = "test-state".to_owned();

        insert_transaction(&state, &state_key, "browser-a");

        let params = HashMap::from([
            ("error".to_owned(), "access_denied".to_owned()),
            ("state".to_owned(), state_key.clone()),
        ]);

        let jar = CookieJar::new().add(Cookie::new(preauth_cookie_name(&state_key), "browser-b"));

        let result = callback(State(state.clone()), Query(params), jar).await;

        let (_, status) = result.expect_err("wrong browser binding must be rejected");

        assert_eq!(status, StatusCode::BAD_REQUEST);

        let pending = state
            .pending
            .lock()
            .expect("pending transaction store must be lockable");

        assert!(pending.contains_key(&state_key));
    }

    #[tokio::test]
    async fn independent_authorization_transactions_keep_independent_bindings() {
        let state = test_state();

        let state_one = "state-one".to_owned();
        let state_two = "state-two".to_owned();

        let binding_one = "browser-binding-one";
        let binding_two = "browser-binding-two";

        assert_ne!(
            preauth_cookie_name(&state_one),
            preauth_cookie_name(&state_two),
        );

        insert_transaction(&state, &state_one, binding_one);
        insert_transaction(&state, &state_two, binding_two);

        let jar = CookieJar::new()
            .add(Cookie::new(preauth_cookie_name(&state_one), binding_one))
            .add(Cookie::new(preauth_cookie_name(&state_two), binding_two));

        let first_params = HashMap::from([
            ("error".to_owned(), "access_denied".to_owned()),
            ("state".to_owned(), state_one.clone()),
        ]);

        let first_result = callback(State(state.clone()), Query(first_params), jar.clone()).await;

        assert!(first_result.is_err());

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

        let second_result = callback(State(state.clone()), Query(second_params), jar).await;

        assert!(second_result.is_err());

        let pending = state
            .pending
            .lock()
            .expect("pending transaction store must be lockable");

        assert!(!pending.contains_key(&state_two));
    }

    #[tokio::test]
    async fn same_transaction_is_consumed_atomically() {
        let state = test_state();

        let state_key = "atomic-state".to_owned();
        let binding = "atomic-browser-binding";

        insert_transaction(&state, &state_key, binding);

        let presented_hash = hash_browser_binding(binding);

        let barrier = Arc::new(Barrier::new(3));
        let token_exchange_boundary_calls = Arc::new(AtomicUsize::new(0));

        let state_a = state.clone();
        let state_key_a = state_key.clone();
        let barrier_a = barrier.clone();
        let calls_a = token_exchange_boundary_calls.clone();

        let first = tokio::spawn(async move {
            barrier_a.wait().await;

            let result = take_bound_transaction(&state_a, &state_key_a, presented_hash);

            if result.is_ok() {
                calls_a.fetch_add(1, Ordering::SeqCst);
            }

            result.is_ok()
        });

        let state_b = state.clone();
        let state_key_b = state_key.clone();
        let barrier_b = barrier.clone();
        let calls_b = token_exchange_boundary_calls.clone();

        let second = tokio::spawn(async move {
            barrier_b.wait().await;

            let result = take_bound_transaction(&state_b, &state_key_b, presented_hash);

            if result.is_ok() {
                calls_b.fetch_add(1, Ordering::SeqCst);
            }

            result.is_ok()
        });

        barrier.wait().await;

        let first_succeeded = first.await.expect("first callback task must complete");

        let second_succeeded = second.await.expect("second callback task must complete");

        assert_ne!(
            first_succeeded, second_succeeded,
            "exactly one competing callback must consume the transaction",
        );

        assert_eq!(
            token_exchange_boundary_calls.load(Ordering::SeqCst),
            1,
            "at most one callback may cross the token-exchange boundary",
        );

        let pending = state
            .pending
            .lock()
            .expect("pending transaction store must be lockable");

        assert!(!pending.contains_key(&state_key));
    }

    #[tokio::test]
    async fn wrong_nonce_is_rejected_without_jwks_refresh() {
        let config = mock_config();
        let metadata = mock_provider_metadata(JWKS_A);
        let id_token = parse_test_id_token(VALID_TOKEN_KEY_A);

        let refresh_count = Arc::new(AtomicUsize::new(0));
        let count = refresh_count.clone();

        let result = verify_id_token_with_single_refresh(
            &config,
            metadata,
            &id_token,
            &Nonce::new("wrong-nonce".to_owned()),
            move || async move {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(mock_provider_metadata(JWKS_B))
            },
        )
        .await;

        assert_eq!(result, Err(StatusCode::UNAUTHORIZED));
        assert_eq!(
            refresh_count.load(Ordering::SeqCst),
            0,
            "nonce failure must not trigger JWKS refresh",
        );
    }

    #[tokio::test]
    async fn invalid_signature_is_rejected_without_jwks_refresh() {
        let config = mock_config();
        let metadata = mock_provider_metadata(JWKS_A);
        let id_token = parse_test_id_token(INVALID_SIGNATURE_TOKEN);

        let refresh_count = Arc::new(AtomicUsize::new(0));
        let count = refresh_count.clone();

        let result = verify_id_token_with_single_refresh(
            &config,
            metadata,
            &id_token,
            &Nonce::new("expected-nonce".to_owned()),
            move || async move {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(mock_provider_metadata(JWKS_B))
            },
        )
        .await;

        assert_eq!(result, Err(StatusCode::UNAUTHORIZED));
        assert_eq!(
            refresh_count.load(Ordering::SeqCst),
            0,
            "signature failure with a matching key must not trigger key-rotation refresh",
        );
    }

    #[tokio::test]
    async fn unknown_signing_key_triggers_exactly_one_refresh_and_accepts_rotated_key() {
        let config = mock_config();

        let initial_metadata = mock_provider_metadata(JWKS_A);
        let rotated_metadata = mock_provider_metadata(JWKS_B);
        let id_token = parse_test_id_token(VALID_TOKEN_KEY_B);

        let refresh_count = Arc::new(AtomicUsize::new(0));
        let count = refresh_count.clone();

        let result = verify_id_token_with_single_refresh(
            &config,
            initial_metadata,
            &id_token,
            &Nonce::new("expected-nonce".to_owned()),
            move || async move {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(rotated_metadata)
            },
        )
        .await;

        assert_eq!(result, Ok(()));
        assert_eq!(refresh_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn unknown_signing_key_is_rejected_after_single_unsuccessful_refresh() {
        let config = mock_config();

        let initial_metadata = mock_provider_metadata(JWKS_A);
        let still_stale_metadata = mock_provider_metadata(JWKS_A);
        let id_token = parse_test_id_token(VALID_TOKEN_KEY_B);

        let refresh_count = Arc::new(AtomicUsize::new(0));
        let count = refresh_count.clone();

        let result = verify_id_token_with_single_refresh(
            &config,
            initial_metadata,
            &id_token,
            &Nonce::new("expected-nonce".to_owned()),
            move || async move {
                count.fetch_add(1, Ordering::SeqCst);
                Ok(still_stale_metadata)
            },
        )
        .await;

        assert_eq!(result, Err(StatusCode::UNAUTHORIZED));
        assert_eq!(
            refresh_count.load(Ordering::SeqCst),
            1,
            "verification must not enter an unbounded refresh loop",
        );
    }
}

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
    core::{
        CoreAuthenticationFlow, CoreClient, CoreIdToken, CoreJwsSigningAlgorithm,
        CoreProviderMetadata,
    },
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
    client_secret: ClientSecret,
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

        let client_secret = ClientSecret::new(client_secret);

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
        let client_secret = CsrfToken::new_random_len(BROWSER_BINDING_BYTES)
            .secret()
            .to_owned();

        Self::from_values(
            ISSUER,
            CLIENT_ID,
            Some(client_secret),
            LOCAL_REDIRECT_URI.to_owned(),
            None,
        )
        .expect("runtime-generated OIDC test configuration must be valid")
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
        Some(config.client_secret.clone()),
    )
    .set_redirect_uri(config.redirect_uri.clone());

    let verifier = client
        .id_token_verifier()
        .set_allowed_algs([CoreJwsSigningAlgorithm::EcdsaP256Sha256]);

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

    // OAuth/OIDC authorization responses contain exactly one of `code` or `error`.
    // Reject malformed responses before consuming any server-side transaction.
    if has_error == code.is_some() {
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
        Some(state.config.client_secret.clone()),
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

    // Security rule for this module:
    // private keys, client secrets, authorization codes, PKCE verifiers,
    // access tokens, refresh tokens and ID tokens are generated at runtime.
    // No credential or token fixture is persisted in the repository.

    use std::{
        str::FromStr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    use axum::{
        Extension,
        body::{Body, to_bytes},
        http::{
            HeaderValue, Request,
            header::{CONTENT_TYPE, COOKIE, LOCATION, SET_COOKIE},
        },
        response::IntoResponse,
        routing::{get, post},
    };
    use openidconnect::{
        AuthUrl, EmptyAdditionalProviderMetadata, JsonWebKeyId, JsonWebKeySetUrl, ResponseTypes,
        TokenUrl,
        core::{
            CoreJsonCurveType, CoreJsonWebKey, CoreJsonWebKeySet, CoreResponseType,
            CoreSubjectIdentifierType,
        },
    };
    use p256::ecdsa::{Signature, SigningKey, signature::Signer};
    use tokio::sync::Barrier;
    use tower::ServiceExt;

    const MOCK_ISSUER: &str = "https://mock.example";

    fn runtime_secret() -> String {
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

    fn base64url_no_pad(input: &[u8]) -> String {
        const ALPHABET: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

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

    struct EphemeralEs256Key {
        signing_key: SigningKey,
        kid: String,
    }

    impl EphemeralEs256Key {
        fn generate() -> Self {
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

        fn jwks(&self) -> CoreJsonWebKeySet {
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

        fn jwks_json(&self) -> String {
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

        fn compact_id_token(&self, nonce: &str) -> String {
            self.compact_id_token_with_header(nonce, "ES256", &self.kid, MOCK_ISSUER)
        }

        fn compact_id_token_for_issuer(&self, nonce: &str, issuer: &str) -> String {
            self.compact_id_token_with_header(nonce, "ES256", &self.kid, issuer)
        }

        fn compact_id_token_with_kid(&self, nonce: &str, kid: &str) -> String {
            self.compact_id_token_with_header(nonce, "ES256", kid, MOCK_ISSUER)
        }

        fn compact_id_token_with_algorithm(&self, nonce: &str, algorithm: &str) -> String {
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

        fn id_token(&self, nonce: &str) -> CoreIdToken {
            CoreIdToken::from_str(&self.compact_id_token(nonce))
                .expect("runtime-generated ES256 ID token must parse")
        }
    }

    fn test_state() -> OidcState {
        let config = OidcConfig::for_tests();

        let client_ip_extractor =
            SmartIp::new().with_trusted_proxies(config.trusted_proxy_cidrs.clone());

        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(OIDC_CONNECT_TIMEOUT)
            .timeout(OIDC_REQUEST_TIMEOUT)
            .build()
            .expect("OIDC test HTTP client must be constructible");

        OidcState {
            config: Arc::new(config),
            http_client,
            client_ip_extractor,
            provider_metadata: Arc::new(AsyncMutex::new(None)),
            pending: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn test_state_for_issuer(issuer: &str) -> OidcState {
        let config = OidcConfig::from_values(
            issuer,
            CLIENT_ID,
            Some(runtime_secret()),
            LOCAL_REDIRECT_URI.to_owned(),
            None,
        )
        .expect("runtime mock issuer configuration must be valid");

        let client_ip_extractor =
            SmartIp::new().with_trusted_proxies(config.trusted_proxy_cidrs.clone());

        let http_client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(OIDC_CONNECT_TIMEOUT)
            .timeout(OIDC_REQUEST_TIMEOUT)
            .build()
            .expect("OIDC test HTTP client must be constructible");

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
            Some(runtime_secret()),
            "https://app.example.test/auth/callback".to_owned(),
            None,
        )
        .expect("runtime-generated OIDC mock configuration must be valid")
    }

    fn mock_provider_metadata(
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

    async fn install_mock_provider_metadata(
        state: &OidcState,
        signing_key: &EphemeralEs256Key,
        token_endpoint: &str,
    ) {
        let mut metadata = state.provider_metadata.lock().await;
        *metadata = Some(mock_provider_metadata(signing_key.jwks(), token_endpoint));
    }

    struct MockTokenEndpoint {
        url: String,
        calls: Arc<AtomicUsize>,
    }

    fn form_value<'a>(body: &'a str, name: &str) -> Option<&'a str> {
        body.split('&').find_map(|part| {
            let (key, value) = part.split_once('=')?;
            (key == name).then_some(value)
        })
    }

    async fn spawn_mock_token_endpoint(
        id_token: String,
        expected_code: Option<String>,
        expected_verifier: Option<String>,
    ) -> MockTokenEndpoint {
        let calls = Arc::new(AtomicUsize::new(0));
        let access_token = runtime_secret();
        let refresh_token = runtime_secret();

        let handler_calls = calls.clone();
        let handler_access_token = access_token.clone();
        let handler_refresh_token = refresh_token.clone();
        let expected_code = Arc::new(expected_code);
        let expected_verifier = Arc::new(expected_verifier);

        let app = Router::new().route(
            "/token",
            post(move |body: String| {
                let calls = handler_calls.clone();
                let access_token = handler_access_token.clone();
                let refresh_token = handler_refresh_token.clone();
                let id_token = id_token.clone();
                let expected_code = expected_code.clone();
                let expected_verifier = expected_verifier.clone();

                async move {
                    calls.fetch_add(1, Ordering::SeqCst);

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
        discovery_calls: Arc<AtomicUsize>,
        jwks_calls: Arc<AtomicUsize>,
        token_calls: Arc<AtomicUsize>,
    }

    struct MockOidcProvider {
        issuer: String,
        discovery_calls: Arc<AtomicUsize>,
        jwks_calls: Arc<AtomicUsize>,
        token_calls: Arc<AtomicUsize>,
        access_token: String,
        refresh_token: String,
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
        body: String,
    ) -> axum::response::Response {
        state.token_calls.fetch_add(1, Ordering::SeqCst);

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

    async fn spawn_mock_oidc_provider(
        initial_jwks: String,
        rotate_jwks_on_token: Option<String>,
        token_signing_key: &EphemeralEs256Key,
        nonce: &str,
        expected_code: String,
        expected_verifier: String,
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
            discovery_calls: discovery_calls.clone(),
            jwks_calls: jwks_calls.clone(),
            token_calls: token_calls.clone(),
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
            access_token,
            refresh_token,
        }
    }

    fn request_cookie_jar(cookies: &[(&str, &str)]) -> CookieJar {
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

    fn response_removes_cookie(response: &axum::response::Response, cookie_name: &str) -> bool {
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

    fn insert_transaction_with(
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

    fn insert_random_transaction(state: &OidcState, state_key: &str, binding: &str) {
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

        let provider = spawn_mock_oidc_provider(
            old_key.jwks_json(),
            Some(rotated_key.jwks_json()),
            &rotated_key,
            nonce.secret(),
            code.clone(),
            verifier_value,
        )
        .await;
        let state = test_state_for_issuer(&provider.issuer);
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

        let provider = spawn_mock_oidc_provider(
            stale_key.jwks_json(),
            None,
            &unknown_key,
            nonce.secret(),
            code.clone(),
            verifier_value,
        )
        .await;
        let state = test_state_for_issuer(&provider.issuer);
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

        let response = (returned_jar, status).into_response();
        assert!(response_removes_cookie(&response, &cookie_name));
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

    // AC-OIDC-TXN-002, AC-OIDC-TXN-005, AC-OIDC-TXN-016,
    // AC-OIDC-TXN-017, AC-OIDC-TXN-019
    #[tokio::test]
    async fn successful_callback_completes_flow_removes_cookie_and_prevents_replay() {
        let signing_key = EphemeralEs256Key::generate();
        let nonce = Nonce::new_random();
        let code = runtime_secret();
        let (_, verifier) = PkceCodeChallenge::new_random_sha256();
        let verifier_value = verifier.secret().to_owned();

        let provider = spawn_mock_oidc_provider(
            signing_key.jwks_json(),
            None,
            &signing_key,
            nonce.secret(),
            code.clone(),
            verifier_value,
        )
        .await;
        let state = test_state_for_issuer(&provider.issuer);
        let state_key = runtime_secret();
        let binding = runtime_secret();
        let client_secret = state.config.client_secret.secret().to_owned();

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

        let (returned_jar, status) =
            callback(State(state.clone()), Query(params.clone()), jar.clone())
                .await
                .expect("valid callback must succeed");

        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(provider.token_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.discovery_calls.load(Ordering::SeqCst), 1);
        assert_eq!(provider.jwks_calls.load(Ordering::SeqCst), 1);

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
}

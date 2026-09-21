use std::{
    collections::HashMap,
    env,
    net::{IpAddr, SocketAddr},
    num::NonZeroU32,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Router,
    extract::{ConnectInfo, Query, State},
    http::StatusCode,
    response::Redirect,
    routing::get,
};

use axum_governor::{GovernorConfigBuilder, GovernorLayer, Quota, extractor::PeerIp};

use openidconnect::{
    AuthorizationCode, ClaimsVerificationError, ClientId, ClientSecret, CsrfToken, IssuerUrl,
    Nonce, PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, SignatureVerificationError,
    TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest,
};

use tokio::sync::Mutex as AsyncMutex;

const ISSUER: &str = "https://id.rock-the-prototype.com/realms/RTP";
const CLIENT_ID: &str = "rtp-web";

const REDIRECT_URI_ENV: &str = "RTP_OIDC_REDIRECT_URI";
const LOCAL_REDIRECT_URI: &str = "http://127.0.0.1:3000/auth/callback";

const LOGIN_TTL: Duration = Duration::from_secs(300);

const MAX_PENDING_LOGINS: usize = 128;
const MAX_PENDING_LOGINS_PER_CLIENT: usize = 8;

const LOGIN_REQUESTS_PER_MINUTE: u32 = 10;
const LOGIN_BURST: u32 = 4;
const OIDC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const OIDC_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

struct PendingLogin {
    pkce_verifier: PkceCodeVerifier,
    nonce: Nonce,
    created_at: Instant,
    client_ip: IpAddr,
}

#[derive(Clone)]
struct OidcState {
    http_client: reqwest::Client,
    provider_metadata: Arc<AsyncMutex<Option<CoreProviderMetadata>>>,
    pending: Arc<Mutex<HashMap<String, PendingLogin>>>,
}

pub fn router() -> Router {
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(OIDC_CONNECT_TIMEOUT)
        .timeout(OIDC_REQUEST_TIMEOUT)
        .build()
        .expect("OIDC HTTP client must be constructible");

    let login_requests_per_minute = NonZeroU32::new(LOGIN_REQUESTS_PER_MINUTE)
        .expect("login requests per minute must be non-zero");

    let login_burst = NonZeroU32::new(LOGIN_BURST).expect("login burst must be non-zero");

    let login_rate_limit = GovernorConfigBuilder::default()
        .with_extractor(PeerIp::default())
        .expect_connect_info()
        .quota_default(Quota::requests_per_minute(login_requests_per_minute).burst(login_burst))
        .finish()
        .expect("login rate-limit configuration must be valid");

    let state = OidcState {
        http_client,
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

    let issuer =
        IssuerUrl::new(ISSUER.to_owned()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let metadata = CoreProviderMetadata::discover_async(issuer, &state.http_client)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    *cached = Some(metadata.clone());

    Ok(metadata)
}

async fn refresh_provider_metadata(state: &OidcState) -> Result<CoreProviderMetadata, StatusCode> {
    let issuer =
        IssuerUrl::new(ISSUER.to_owned()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let metadata = CoreProviderMetadata::discover_async(issuer, &state.http_client)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let mut cached = state.provider_metadata.lock().await;
    *cached = Some(metadata.clone());

    Ok(metadata)
}

async fn login(
    State(state): State<OidcState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
) -> Result<Redirect, StatusCode> {
    let provider_metadata = provider_metadata(&state).await?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(CLIENT_ID.to_owned()),
        None,
    )
    .set_redirect_uri(redirect_uri()?);

    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

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

    {
        let mut pending = state
            .pending
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        pending.retain(|_, login| login.created_at.elapsed() < LOGIN_TTL);

        let client_ip = peer.ip();

        let pending_for_client = pending
            .values()
            .filter(|login| login.client_ip == client_ip)
            .count();

        if pending_for_client >= MAX_PENDING_LOGINS_PER_CLIENT {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        if pending.len() >= MAX_PENDING_LOGINS {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        pending.insert(
            state_key,
            PendingLogin {
                pkce_verifier,
                nonce,
                created_at: Instant::now(),
                client_ip,
            },
        );
    }

    Ok(Redirect::temporary(authorization_url.as_str()))
}

async fn callback(
    State(state): State<OidcState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<StatusCode, StatusCode> {
    let returned_state = params
        .get("state")
        .cloned()
        .ok_or(StatusCode::BAD_REQUEST)?;

    let pending_login = {
        let mut pending = state
            .pending
            .lock()
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

        pending.retain(|_, login| login.created_at.elapsed() < LOGIN_TTL);

        pending
            .remove(&returned_state)
            .ok_or(StatusCode::BAD_REQUEST)?
    };

    if params.contains_key("error") {
        return Err(StatusCode::BAD_REQUEST);
    }

    let code = params.get("code").cloned().ok_or(StatusCode::BAD_REQUEST)?;

    let client_secret =
        env::var("RTP_OIDC_CLIENT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let provider_metadata = provider_metadata(&state).await?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(CLIENT_ID.to_owned()),
        Some(ClientSecret::new(client_secret.clone())),
    )
    .set_redirect_uri(redirect_uri()?);

    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|_| StatusCode::BAD_GATEWAY)?
        .set_pkce_verifier(pending_login.pkce_verifier)
        .request_async(&state.http_client)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let id_token = token_response.id_token().ok_or(StatusCode::UNAUTHORIZED)?;

    let id_token_verifier = client.id_token_verifier();

    match id_token.claims(&id_token_verifier, &pending_login.nonce) {
        Ok(_) => {}

        Err(ClaimsVerificationError::SignatureVerification(
            SignatureVerificationError::NoMatchingKey,
        )) => {
            let refreshed_metadata = refresh_provider_metadata(&state).await?;

            let refreshed_client = CoreClient::from_provider_metadata(
                refreshed_metadata,
                ClientId::new(CLIENT_ID.to_owned()),
                Some(ClientSecret::new(client_secret)),
            )
            .set_redirect_uri(redirect_uri()?);

            let refreshed_verifier = refreshed_client.id_token_verifier();

            id_token
                .claims(&refreshed_verifier, &pending_login.nonce)
                .map_err(|_| StatusCode::UNAUTHORIZED)?;
        }

        Err(_) => {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    Ok(StatusCode::NO_CONTENT)
}

fn redirect_uri() -> Result<RedirectUrl, StatusCode> {
    let raw = env::var(REDIRECT_URI_ENV).unwrap_or_else(|_| LOCAL_REDIRECT_URI.to_owned());

    validate_redirect_uri(raw)
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

    use axum::{Extension, body::Body, http::Request, routing::get};
    use tower::ServiceExt;

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

    #[tokio::test]
    async fn login_rate_limit_rejects_after_burst() {
        let requests_per_minute = NonZeroU32::new(LOGIN_REQUESTS_PER_MINUTE)
            .expect("login requests per minute must be non-zero");

        let burst = NonZeroU32::new(LOGIN_BURST).expect("login burst must be non-zero");

        let rate_limit = GovernorConfigBuilder::default()
            .with_extractor(PeerIp::default())
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
}

#[tokio::test]
async fn oidc_error_callback_consumes_pending_transaction() {
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("OIDC HTTP client must be constructible");

    let state = OidcState {
        http_client,
        provider_metadata: Arc::new(AsyncMutex::new(None)),
        pending: Arc::new(Mutex::new(HashMap::new())),
    };

    let state_key = "test-state".to_owned();

    let (_, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    state
        .pending
        .lock()
        .expect("pending login store must be lockable")
        .insert(
            state_key.clone(),
            PendingLogin {
                pkce_verifier,
                nonce: Nonce::new_random(),
                created_at: Instant::now(),
                client_ip: IpAddr::from([127, 0, 0, 1]),
            },
        );

    let params = HashMap::from([
        ("error".to_owned(), "access_denied".to_owned()),
        ("state".to_owned(), state_key.clone()),
    ]);

    let result = callback(State(state.clone()), Query(params)).await;

    assert_eq!(result, Err(StatusCode::BAD_REQUEST));

    let pending = state
        .pending
        .lock()
        .expect("pending login store must be lockable");

    assert!(!pending.contains_key(&state_key));
}

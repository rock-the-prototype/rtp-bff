use std::{
    collections::HashMap,
    env,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    Router,
    extract::{Query, State},
    http::StatusCode,
    response::Redirect,
    routing::get,
};

use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    reqwest,
};

const ISSUER: &str = "https://id.rock-the-prototype.com/realms/RTP";
const CLIENT_ID: &str = "rtp-web";
const REDIRECT_URI: &str = "http://127.0.0.1:3000/auth/callback";

const LOGIN_TTL: Duration = Duration::from_secs(300);
const MAX_PENDING_LOGINS: usize = 128;

#[derive(Clone)]
struct OidcState {
    http_client: reqwest::Client,
    pending: Arc<Mutex<HashMap<String, PendingLogin>>>,
}

struct PendingLogin {
    pkce_verifier: PkceCodeVerifier,
    nonce: Nonce,
    created_at: Instant,
}

pub fn router() -> Router {
    let http_client = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("OIDC HTTP client must be constructible");

    let state = OidcState {
        http_client,
        pending: Arc::new(Mutex::new(HashMap::new())),
    };

    Router::new()
        .route("/auth/login", get(login))
        .route("/auth/callback", get(callback))
        .with_state(state)
}

async fn login(State(state): State<OidcState>) -> Result<Redirect, StatusCode> {
    let issuer =
        IssuerUrl::new(ISSUER.to_owned()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let provider_metadata = CoreProviderMetadata::discover_async(issuer, &state.http_client)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(CLIENT_ID.to_owned()),
        None,
    )
    .set_redirect_uri(
        RedirectUrl::new(REDIRECT_URI.to_owned()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );

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

        if pending.len() >= MAX_PENDING_LOGINS {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        pending.insert(
            state_key,
            PendingLogin {
                pkce_verifier,
                nonce,
                created_at: Instant::now(),
            },
        );
    }

    Ok(Redirect::temporary(authorization_url.as_str()))
}

async fn callback(
    State(state): State<OidcState>,
    Query(params): Query<HashMap<String, String>>,
) -> Result<StatusCode, StatusCode> {
    if params.contains_key("error") {
        return Err(StatusCode::BAD_REQUEST);
    }

    let code = params.get("code").cloned().ok_or(StatusCode::BAD_REQUEST)?;

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

    let client_secret =
        env::var("RTP_OIDC_CLIENT_SECRET").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let issuer =
        IssuerUrl::new(ISSUER.to_owned()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let provider_metadata = CoreProviderMetadata::discover_async(issuer, &state.http_client)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let client = CoreClient::from_provider_metadata(
        provider_metadata,
        ClientId::new(CLIENT_ID.to_owned()),
        Some(ClientSecret::new(client_secret)),
    )
    .set_redirect_uri(
        RedirectUrl::new(REDIRECT_URI.to_owned()).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );

    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .map_err(|_| StatusCode::BAD_GATEWAY)?
        .set_pkce_verifier(pending_login.pkce_verifier)
        .request_async(&state.http_client)
        .await
        .map_err(|_| StatusCode::BAD_GATEWAY)?;

    let id_token = token_response.id_token().ok_or(StatusCode::UNAUTHORIZED)?;

    let id_token_verifier = client.id_token_verifier();

    id_token
        .claims(&id_token_verifier, &pending_login.nonce)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    Ok(StatusCode::NO_CONTENT)
}

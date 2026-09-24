use std::{collections::HashMap, net::SocketAddr, time::Instant};

use axum::{
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, Request, StatusCode},
    response::Redirect,
};
use axum_extra::extract::cookie::CookieJar;
use axum_governor::extractor::KeyExtractor;
use openidconnect::{
    AuthorizationCode, ClientId, CsrfToken, Nonce, OAuth2TokenResponse, PkceCodeChallenge, Scope,
    TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient},
};

use crate::session::{
    AuthenticatedSession, access_token_expiry, build_session_cookie, new_session_id,
};

use super::{
    OidcState,
    provider::{provider_metadata, refresh_provider_metadata, verify_id_token_with_single_refresh},
    transaction::{
        AuthorizationTransaction, BROWSER_BINDING_BYTES, LOGIN_TTL, MAX_PENDING_LOGINS,
        MAX_PENDING_LOGINS_PER_CLIENT, build_preauth_cookie, hash_browser_binding,
        preauth_cookie_name, remove_preauth_cookie, take_bound_transaction,
    },
};

pub(super) type CallbackResult = Result<(CookieJar, StatusCode), (CookieJar, StatusCode)>;

pub(super) fn extract_client_ip(
    extractor: &axum_governor::extractor::SmartIp,
    headers: &HeaderMap,
    peer: SocketAddr,
) -> Result<std::net::IpAddr, StatusCode> {
    let mut request = Request::new(());
    *request.headers_mut() = headers.clone();
    request.extensions_mut().insert(ConnectInfo(peer));

    let (parts, _) = request.into_parts();

    extractor
        .extract(&parts)
        .map(|outcome| outcome.key)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
}

pub(super) async fn login(
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

    Ok((
        jar.add(preauth_cookie),
        Redirect::temporary(authorization_url.as_str()),
    ))
}

pub(super) async fn callback(
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

    let transaction =
        match take_bound_transaction(&state.pending, &returned_state, presented_binding_hash) {
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

    if let Err(status) = verification {
        return Err((jar, status));
    }

    let authenticated_session = AuthenticatedSession {
        access_token: token_response.access_token().secret().to_owned(),
        refresh_token: token_response
            .refresh_token()
            .map(|token| token.secret().to_owned()),
        access_token_expires_at: access_token_expiry(token_response.expires_in()),
    };
    let session_id = new_session_id();

    if state
        .session_store
        .put(&session_id, &authenticated_session)
        .await
        .is_err()
    {
        return Err((jar, StatusCode::SERVICE_UNAVAILABLE));
    }

    let session_cookie = build_session_cookie(
        session_id,
        state.config.secure_cookie(),
        state.session_store.ttl(),
    );

    Ok((jar.add(session_cookie), StatusCode::NO_CONTENT))
}

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::Mutex,
    time::{Duration, Instant},
};

use axum::http::StatusCode;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use openidconnect::{Nonce, PkceCodeVerifier};
use sha2::{Digest, Sha256};
use time::Duration as CookieDuration;

use super::config::OIDC_CALLBACK_PATH;

pub(super) const LOGIN_TTL_SECONDS: i64 = 300;
pub(super) const LOGIN_TTL: Duration = Duration::from_secs(LOGIN_TTL_SECONDS as u64);
pub(super) const MAX_PENDING_LOGINS: usize = 128;
pub(super) const MAX_PENDING_LOGINS_PER_CLIENT: usize = 8;
pub(super) const PREAUTH_COOKIE_PATH: &str = OIDC_CALLBACK_PATH;
pub(super) const BROWSER_BINDING_BYTES: u32 = 32;

const PREAUTH_COOKIE_PREFIX: &str = "rtp-preauth";

pub(super) struct AuthorizationTransaction {
    pub(super) pkce_verifier: PkceCodeVerifier,
    pub(super) nonce: Nonce,
    pub(super) browser_binding_hash: [u8; 32],
    pub(super) created_at: Instant,
    pub(super) client_ip: IpAddr,
}

pub(super) fn preauth_cookie_name(state: &str) -> String {
    let digest = Sha256::digest(state.as_bytes());
    let suffix = digest
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();

    format!("{PREAUTH_COOKIE_PREFIX}-{suffix}")
}

pub(super) fn hash_browser_binding(secret: &str) -> [u8; 32] {
    Sha256::digest(secret.as_bytes()).into()
}

pub(super) fn build_preauth_cookie(
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

pub(super) fn remove_preauth_cookie(
    jar: CookieJar,
    cookie_name: String,
    secure: bool,
) -> CookieJar {
    jar.remove(
        Cookie::build(cookie_name)
            .path(PREAUTH_COOKIE_PATH)
            .http_only(true)
            .secure(secure)
            .same_site(SameSite::Lax)
            .build(),
    )
}

pub(super) fn take_bound_transaction(
    pending: &Mutex<HashMap<String, AuthorizationTransaction>>,
    returned_state: &str,
    presented_binding_hash: [u8; 32],
) -> Result<AuthorizationTransaction, StatusCode> {
    let mut pending = pending
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

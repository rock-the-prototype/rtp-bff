use std::{
    collections::HashMap,
    num::NonZeroU32,
    sync::{Arc, Mutex},
};

use axum::{Router, routing::get};
use axum_governor::{GovernorConfigBuilder, GovernorLayer, Quota, extractor::SmartIp};
use openidconnect::core::CoreProviderMetadata;
use tokio::sync::Mutex as AsyncMutex;

mod config;
mod handlers;
mod provider;
mod refresh;
mod transaction;

use crate::session::SessionStore;
use config::{OIDC_CALLBACK_PATH, OidcConfig};
use handlers::{callback, check_session, login};
use provider::build_http_client;
use transaction::AuthorizationTransaction;

const LOGIN_REQUESTS_PER_MINUTE: u32 = 10;
const LOGIN_BURST: u32 = 4;

#[derive(Clone)]
struct OidcState {
    config: Arc<OidcConfig>,
    http_client: openidconnect::reqwest::Client,
    client_ip_extractor: SmartIp,
    provider_metadata: Arc<AsyncMutex<Option<CoreProviderMetadata>>>,
    session_store: SessionStore,
    // Current implementation slice: authorization transactions are process-local.
    // Deployment is therefore constrained to exactly one BFF replica. A process
    // restart intentionally invalidates pending logins. Horizontal scaling MUST
    // replace this store with shared storage providing atomic bound take + TTL.
    pending: Arc<Mutex<HashMap<String, AuthorizationTransaction>>>,
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
    let http_client = build_http_client();
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

    #[cfg(test)]
    let session_store = SessionStore::for_tests();

    #[cfg(not(test))]
    let session_store = SessionStore::from_env().unwrap_or_else(|error| {
        panic!("BFF session-store startup configuration invalid: {error}");
    });

    let state = OidcState {
        config: Arc::new(config),
        http_client,
        client_ip_extractor,
        provider_metadata: Arc::new(AsyncMutex::new(None)),
        session_store,
        pending: Arc::new(Mutex::new(HashMap::new())),
    };

    let login_router = Router::new()
        .route("/auth/login", get(login))
        .layer(GovernorLayer::new(login_rate_limit));

    Router::new()
        .merge(login_router)
        .route(OIDC_CALLBACK_PATH, get(callback))
        .route("/auth/session", get(check_session))
        .with_state(state)
}

#[cfg(test)]
mod tests;

use std::{future::Future, time::Duration};

use axum::http::StatusCode;
use openidconnect::{
    ClaimsVerificationError, ClientId, Nonce, SignatureVerificationError,
    core::{CoreClient, CoreIdToken, CoreProviderMetadata},
    reqwest,
};

use super::{
    OidcState,
    config::{OidcConfig, accepted_id_token_signing_algorithms},
};

const OIDC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

pub(super) const OIDC_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

pub(super) fn build_http_client() -> reqwest::Client {
    reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(OIDC_CONNECT_TIMEOUT)
        .timeout(OIDC_REQUEST_TIMEOUT)
        .build()
        .expect("OIDC HTTP client must be constructible")
}

pub(super) async fn provider_metadata(
    state: &OidcState,
) -> Result<CoreProviderMetadata, StatusCode> {
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

pub(super) async fn refresh_provider_metadata(
    state: &OidcState,
) -> Result<CoreProviderMetadata, StatusCode> {
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
        .set_allowed_algs(accepted_id_token_signing_algorithms());

    id_token.claims(&verifier, nonce).map(|_| ())
}

pub(super) async fn verify_id_token_with_single_refresh<F, Fut>(
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

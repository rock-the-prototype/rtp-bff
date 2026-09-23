#[cfg(not(test))]
use std::env;

use axum::http::StatusCode;
use ipnet::IpNet;
use openidconnect::{ClientSecret, IssuerUrl, RedirectUrl, core::CoreJwsSigningAlgorithm};

#[cfg(test)]
use openidconnect::CsrfToken;

pub(super) const ISSUER: &str = "https://id.rock-the-prototype.com/realms/RTP";

pub(super) const CLIENT_ID: &str = "rtp-web";

pub(super) const OIDC_CALLBACK_PATH: &str = "/auth/callback";

pub(super) const LOCAL_REDIRECT_URI: &str = "http://127.0.0.1:3000/auth/callback";

const CLIENT_SECRET_ENV: &str = "RTP_OIDC_CLIENT_SECRET";

#[cfg(not(test))]
const REDIRECT_URI_ENV: &str = "RTP_OIDC_REDIRECT_URI";

#[cfg(not(test))]
const TRUSTED_PROXY_CIDRS_ENV: &str = "RTP_TRUSTED_PROXY_CIDRS";

#[derive(Clone)]
pub(super) struct OidcConfig {
    pub(super) issuer: IssuerUrl,
    pub(super) client_id: String,
    pub(super) client_secret: ClientSecret,
    pub(super) redirect_uri: RedirectUrl,
    pub(super) trusted_proxy_cidrs: Vec<IpNet>,
}

impl OidcConfig {
    #[cfg(not(test))]
    pub(super) fn from_env() -> Result<Self, String> {
        Self::from_values(
            ISSUER,
            CLIENT_ID,
            env::var(CLIENT_SECRET_ENV).ok(),
            env::var(REDIRECT_URI_ENV).unwrap_or_else(|_| LOCAL_REDIRECT_URI.to_owned()),
            env::var(TRUSTED_PROXY_CIDRS_ENV).ok(),
        )
    }

    pub(super) fn from_values(
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
            client_secret: ClientSecret::new(client_secret),
            redirect_uri,
            trusted_proxy_cidrs,
        })
    }

    #[cfg(test)]
    pub(super) fn for_tests() -> Self {
        const TEST_SECRET_BYTES: u32 = 32;

        let client_secret = CsrfToken::new_random_len(TEST_SECRET_BYTES)
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

    pub(super) fn secure_cookie(&self) -> bool {
        self.redirect_uri.url().scheme() == "https"
    }
}

pub(super) fn accepted_id_token_signing_algorithms() -> [CoreJwsSigningAlgorithm; 1] {
    // OIDC requires ID-token signature validation.
    // ES256 is the currently selected RTP deployment profile and MUST match
    // the Keycloak configuration.
    [CoreJwsSigningAlgorithm::EcdsaP256Sha256]
}

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

pub(super) fn validate_redirect_uri(raw: String) -> Result<RedirectUrl, StatusCode> {
    let redirect = RedirectUrl::new(raw).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let url = redirect.url();

    let is_loopback = matches!(
        url.host_str(),
        Some("127.0.0.1") | Some("localhost") | Some("::1") | Some("[::1]")
    );

    let is_https = url.scheme() == "https";
    let is_loopback_http = url.scheme() == "http" && is_loopback;

    let targets_callback = url.path() == OIDC_CALLBACK_PATH && url.fragment().is_none();

    if (!is_https && !is_loopback_http) || !targets_callback {
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }

    Ok(redirect)
}

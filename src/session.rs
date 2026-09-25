#[cfg(test)]
use std::{collections::HashMap, sync::Arc, time::Instant};
use std::{time::Duration, time::SystemTime, time::UNIX_EPOCH};

use axum_extra::extract::cookie::{Cookie, SameSite};
use openidconnect::CsrfToken;
#[cfg(not(test))]
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use time::Duration as CookieDuration;
#[cfg(test)]
use tokio::sync::Mutex;

const SESSION_ID_BYTES: u32 = 32;

#[cfg(not(test))]
const SESSION_KEY_PREFIX: &str = "rtp:bff:session:";

const PROD_SESSION_COOKIE_NAME: &str = "__Host-Http-rtp_session";
const DEV_SESSION_COOKIE_NAME: &str = "rtp_session_dev";

#[cfg(not(test))]
const REDIS_URL_ENV: &str = "RTP_REDIS_URL";
#[cfg(not(test))]
const SESSION_TTL_SECONDS_ENV: &str = "RTP_BFF_SESSION_TTL_SECONDS";
#[cfg(not(test))]
const REDIS_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
#[cfg(not(test))]
const REDIS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, PartialEq, Eq)]
pub(super) struct AuthenticatedSession {
    pub(super) access_token: String,
    pub(super) refresh_token: Option<String>,
    pub(super) access_token_expires_at: Option<u64>,
}

#[cfg(not(test))]
#[derive(Clone)]
pub(super) struct SessionStore {
    redis: ConnectionManager,
    ttl: Duration,
}

#[cfg(test)]
#[derive(Clone)]
pub(super) struct SessionStore {
    sessions: Arc<Mutex<HashMap<String, StoredTestSession>>>,
    fail_writes: bool,
    fail_reads: bool,
    ttl: Duration,
}

#[cfg(test)]
#[derive(Clone)]
struct StoredTestSession {
    session: AuthenticatedSession,
    stored_at: Instant,
}

impl SessionStore {
    #[cfg(not(test))]
    pub(super) fn from_env() -> Result<Self, String> {
        let redis_url =
            std::env::var(REDIS_URL_ENV).map_err(|_| format!("{REDIS_URL_ENV} is required"))?;

        if redis_url.trim().is_empty() {
            return Err(format!("{REDIS_URL_ENV} must not be empty"));
        }

        let ttl_seconds = std::env::var(SESSION_TTL_SECONDS_ENV)
            .map_err(|_| format!("{SESSION_TTL_SECONDS_ENV} is required"))?
            .parse::<u64>()
            .map_err(|_| format!("{SESSION_TTL_SECONDS_ENV} must be a positive integer"))?;

        if ttl_seconds == 0 || ttl_seconds > i64::MAX as u64 {
            return Err(format!(
                "{SESSION_TTL_SECONDS_ENV} must be between 1 and {}",
                i64::MAX
            ));
        }

        let client = redis::Client::open(redis_url)
            .map_err(|_| format!("{REDIS_URL_ENV} is not a valid Redis URL"))?;
        let manager_config = ConnectionManagerConfig::new()
            .set_connection_timeout(Some(REDIS_CONNECT_TIMEOUT))
            .set_response_timeout(Some(REDIS_RESPONSE_TIMEOUT));
        let redis = client
            .get_connection_manager_lazy(manager_config)
            .map_err(|_| "Redis connection manager configuration is invalid".to_owned())?;

        Ok(Self {
            redis,
            ttl: Duration::from_secs(ttl_seconds),
        })
    }

    #[cfg(test)]
    pub(super) fn for_tests() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            fail_writes: false,
            fail_reads: false,
            ttl: Duration::from_secs(3600),
        }
    }

    #[cfg(test)]
    pub(super) fn for_tests_failing_writes() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            fail_writes: true,
            fail_reads: false,
            ttl: Duration::from_secs(3600),
        }
    }

    #[cfg(test)]
    pub(super) fn for_tests_failing_reads() -> Self {
        Self {
            sessions: Arc::new(Mutex::new(HashMap::new())),
            fail_writes: false,
            fail_reads: true,
            ttl: Duration::from_secs(3600),
        }
    }

    pub(super) fn ttl(&self) -> Duration {
        self.ttl
    }

    #[cfg(not(test))]
    pub(super) async fn put(
        &self,
        session_id: &str,
        session: &AuthenticatedSession,
    ) -> Result<(), ()> {
        let key = session_key(session_id);
        let mut connection = self.redis.clone();
        let refresh_token = session.refresh_token.as_deref().unwrap_or("");
        let access_token_expires_at = session.access_token_expires_at.unwrap_or(0);

        redis::pipe()
            .atomic()
            .cmd("HSET")
            .arg(&key)
            .arg("access_token")
            .arg(&session.access_token)
            .arg("refresh_token")
            .arg(refresh_token)
            .arg("access_token_expires_at")
            .arg(access_token_expires_at)
            .ignore()
            .cmd("EXPIRE")
            .arg(&key)
            .arg(self.ttl.as_secs())
            .ignore()
            .query_async::<()>(&mut connection)
            .await
            .map_err(|_| ())
    }

    #[cfg(not(test))]
    pub(super) async fn get(&self, session_id: &str) -> Result<Option<AuthenticatedSession>, ()> {
        let key = session_key(session_id);
        let mut connection = self.redis.clone();

        let values: (Option<String>, Option<String>, Option<u64>) = redis::cmd("HMGET")
            .arg(&key)
            .arg("access_token")
            .arg("refresh_token")
            .arg("access_token_expires_at")
            .query_async(&mut connection)
            .await
            .map_err(|_| ())?;

        let (access_token, refresh_token, access_token_expires_at) = values;

        let Some(access_token) = access_token else {
            return Ok(None);
        };

        Ok(Some(AuthenticatedSession {
            access_token,
            refresh_token: refresh_token.filter(|token| !token.is_empty()),
            access_token_expires_at: access_token_expires_at.filter(|timestamp| *timestamp != 0),
        }))
    }

    #[cfg(test)]
    pub(super) async fn put(
        &self,
        session_id: &str,
        session: &AuthenticatedSession,
    ) -> Result<(), ()> {
        if self.fail_writes {
            return Err(());
        }

        let mut sessions = self.sessions.lock().await;
        sessions.retain(|_, stored| stored.stored_at.elapsed() < self.ttl);
        sessions.insert(
            session_id.to_owned(),
            StoredTestSession {
                session: session.clone(),
                stored_at: Instant::now(),
            },
        );
        Ok(())
    }

    #[cfg(test)]
    pub(super) async fn get(&self, session_id: &str) -> Result<Option<AuthenticatedSession>, ()> {
        if self.fail_reads {
            return Err(());
        }

        let mut sessions = self.sessions.lock().await;
        sessions.retain(|_, stored| stored.stored_at.elapsed() < self.ttl);
        Ok(sessions
            .get(session_id)
            .map(|stored| stored.session.clone()))
    }
}

pub(super) fn new_session_id() -> String {
    CsrfToken::new_random_len(SESSION_ID_BYTES)
        .secret()
        .to_owned()
}

pub(super) fn session_cookie_name(secure: bool) -> &'static str {
    if secure {
        PROD_SESSION_COOKIE_NAME
    } else {
        DEV_SESSION_COOKIE_NAME
    }
}

pub(super) fn build_session_cookie(
    session_id: String,
    secure: bool,
    ttl: Duration,
) -> Cookie<'static> {
    let max_age_seconds = i64::try_from(ttl.as_secs()).unwrap_or(i64::MAX);

    Cookie::build((session_cookie_name(secure), session_id))
        .path("/")
        .http_only(true)
        .secure(secure)
        .same_site(SameSite::Strict)
        .max_age(CookieDuration::seconds(max_age_seconds))
        .build()
}

pub(super) fn access_token_expiry(expires_in: Option<Duration>) -> Option<u64> {
    let expires_at = SystemTime::now().checked_add(expires_in?)?;
    expires_at
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

#[cfg(not(test))]
fn session_key(session_id: &str) -> String {
    format!("{SESSION_KEY_PREFIX}{session_id}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn session_store_keeps_tokens_server_side() {
        let store = SessionStore::for_tests();
        let session_id = new_session_id();
        let session = AuthenticatedSession {
            access_token: "access-secret".to_owned(),
            refresh_token: Some("refresh-secret".to_owned()),
            access_token_expires_at: Some(12345),
        };

        store
            .put(&session_id, &session)
            .await
            .expect("test session store write must succeed");

        let stored = store
            .get(&session_id)
            .await
            .expect("test session store read must succeed")
            .expect("stored session must exist");

        assert!(
            stored == session,
            "stored session must match the session written to the store"
        );
    }

    #[test]
    fn production_session_cookie_uses_rfc_10017_security_profile() {
        let cookie = build_session_cookie(
            "opaque-session-id".to_owned(),
            true,
            Duration::from_secs(3600),
        );

        assert_eq!(cookie.name(), PROD_SESSION_COOKIE_NAME);
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Strict));
        assert!(cookie.domain().is_none());
        assert_eq!(cookie.value(), "opaque-session-id");
    }
}

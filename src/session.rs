#[cfg(test)]
use std::{collections::HashMap, sync::Arc, time::Instant};
use std::{time::Duration, time::SystemTime, time::UNIX_EPOCH};

use axum_extra::extract::cookie::{Cookie, SameSite};
use openidconnect::CsrfToken;
use redis::aio::{ConnectionManager, ConnectionManagerConfig};
use time::Duration as CookieDuration;
#[cfg(test)]
use tokio::sync::Mutex;

const SESSION_ID_BYTES: u32 = 32;
const SESSION_KEY_PREFIX: &str = "rtp:bff:session:";
const REFRESH_LOCK_KEY_PREFIX: &str = "rtp:bff:refresh-lock:";
const PROD_SESSION_COOKIE_NAME: &str = "__Host-Http-rtp_session";
const DEV_SESSION_COOKIE_NAME: &str = "rtp_session_dev";

#[cfg(not(test))]
const REDIS_URL_ENV: &str = "RTP_REDIS_URL";
#[cfg(not(test))]
const SESSION_TTL_SECONDS_ENV: &str = "RTP_BFF_SESSION_TTL_SECONDS";
#[cfg(test)]
const REDIS_INTEGRATION_URL_ENV: &str = "RTP_REDIS_INTEGRATION_URL";

const REDIS_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const REDIS_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);

const REFRESH_UPDATE_SCRIPT: &str = r#"
local lock_owner = redis.call('GET', KEYS[2])
if lock_owner ~= ARGV[1] then
    return -1
end

if redis.call('EXISTS', KEYS[1]) == 0 then
    return 0
end

redis.call(
    'HSET',
    KEYS[1],
    'access_token', ARGV[2],
    'refresh_token', ARGV[3],
    'access_token_expires_at', ARGV[4]
)
return 1
"#;

const REFRESH_INVALIDATE_SCRIPT: &str = r#"
local lock_owner = redis.call('GET', KEYS[2])
if lock_owner ~= ARGV[1] then
    return -1
end

if redis.call('EXISTS', KEYS[1]) == 0 then
    return 0
end

redis.call('DEL', KEYS[1])
return 1
"#;

const REFRESH_LOCK_RELEASE_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
end
return 0
"#;

#[derive(Clone, PartialEq, Eq)]
pub(super) struct AuthenticatedSession {
    pub(super) access_token: String,
    pub(super) refresh_token: Option<String>,
    pub(super) access_token_expires_at: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum RefreshOwnedMutation {
    Applied,
    SessionMissing,
    OwnershipLost,
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
    state: Arc<Mutex<TestStoreState>>,
    fail_writes: bool,
    fail_reads: bool,
    fail_refresh_mutations: bool,
    fail_refresh_lock_ops: bool,
    ttl: Duration,
}

#[cfg(test)]
#[derive(Default)]
struct TestStoreState {
    sessions: HashMap<String, StoredTestSession>,
    refresh_locks: HashMap<String, StoredTestRefreshLock>,
}

#[cfg(test)]
#[derive(Clone)]
struct StoredTestSession {
    session: AuthenticatedSession,
    stored_at: Instant,
}

#[cfg(test)]
struct StoredTestRefreshLock {
    owner_id: String,
    expires_at: Instant,
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

        let redis = redis_connection_manager(&redis_url)?;

        Ok(Self {
            redis,
            ttl: Duration::from_secs(ttl_seconds),
        })
    }

    #[cfg(test)]
    fn for_tests_with_failures(
        fail_writes: bool,
        fail_reads: bool,
        fail_refresh_mutations: bool,
        fail_refresh_lock_ops: bool,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(TestStoreState::default())),
            fail_writes,
            fail_reads,
            fail_refresh_mutations,
            fail_refresh_lock_ops,
            ttl: Duration::from_secs(3600),
        }
    }

    #[cfg(test)]
    pub(super) fn for_tests() -> Self {
        Self::for_tests_with_failures(false, false, false, false)
    }

    #[cfg(test)]
    pub(super) fn for_tests_failing_writes() -> Self {
        Self::for_tests_with_failures(true, false, false, false)
    }

    #[cfg(test)]
    pub(super) fn for_tests_failing_reads() -> Self {
        Self::for_tests_with_failures(false, true, false, false)
    }

    #[cfg(test)]
    pub(super) fn for_tests_failing_refresh_mutations() -> Self {
        Self::for_tests_with_failures(false, false, true, false)
    }

    #[cfg(test)]
    pub(super) fn for_tests_failing_refresh_lock_ops() -> Self {
        Self::for_tests_with_failures(false, false, false, true)
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
        redis_put(&self.redis, self.ttl, session_id, session).await
    }

    #[cfg(not(test))]
    pub(super) async fn get(&self, session_id: &str) -> Result<Option<AuthenticatedSession>, ()> {
        redis_get(&self.redis, session_id).await
    }

    #[cfg(not(test))]
    pub(super) async fn try_acquire_refresh_lock(
        &self,
        session_id: &str,
        owner_id: &str,
        lease: Duration,
    ) -> Result<bool, ()> {
        redis_try_acquire_refresh_lock(&self.redis, session_id, owner_id, lease).await
    }

    #[cfg(not(test))]
    pub(super) async fn release_refresh_lock(
        &self,
        session_id: &str,
        owner_id: &str,
    ) -> Result<bool, ()> {
        redis_release_refresh_lock(&self.redis, session_id, owner_id).await
    }

    #[cfg(not(test))]
    pub(super) async fn update_after_refresh(
        &self,
        session_id: &str,
        owner_id: &str,
        session: &AuthenticatedSession,
    ) -> Result<RefreshOwnedMutation, ()> {
        redis_update_after_refresh(&self.redis, session_id, owner_id, session).await
    }

    #[cfg(not(test))]
    pub(super) async fn invalidate_for_refresh(
        &self,
        session_id: &str,
        owner_id: &str,
    ) -> Result<RefreshOwnedMutation, ()> {
        redis_invalidate_for_refresh(&self.redis, session_id, owner_id).await
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

        let now = Instant::now();
        let mut state = self.state.lock().await;
        retain_live_test_state(&mut state, self.ttl, now);
        state.sessions.insert(
            session_id.to_owned(),
            StoredTestSession {
                session: session.clone(),
                stored_at: now,
            },
        );
        Ok(())
    }

    #[cfg(test)]
    pub(super) async fn get(&self, session_id: &str) -> Result<Option<AuthenticatedSession>, ()> {
        if self.fail_reads {
            return Err(());
        }

        let now = Instant::now();
        let mut state = self.state.lock().await;
        retain_live_test_state(&mut state, self.ttl, now);

        Ok(state
            .sessions
            .get(session_id)
            .map(|stored| stored.session.clone()))
    }

    #[cfg(test)]
    pub(super) async fn try_acquire_refresh_lock(
        &self,
        session_id: &str,
        owner_id: &str,
        lease: Duration,
    ) -> Result<bool, ()> {
        if self.fail_refresh_lock_ops || lease.is_zero() {
            return Err(());
        }

        let now = Instant::now();
        let Some(expires_at) = now.checked_add(lease) else {
            return Err(());
        };

        let mut state = self.state.lock().await;
        retain_live_test_state(&mut state, self.ttl, now);

        if state.refresh_locks.contains_key(session_id) {
            return Ok(false);
        }

        state.refresh_locks.insert(
            session_id.to_owned(),
            StoredTestRefreshLock {
                owner_id: owner_id.to_owned(),
                expires_at,
            },
        );
        Ok(true)
    }

    #[cfg(test)]
    pub(super) async fn release_refresh_lock(
        &self,
        session_id: &str,
        owner_id: &str,
    ) -> Result<bool, ()> {
        if self.fail_refresh_lock_ops {
            return Err(());
        }

        let now = Instant::now();
        let mut state = self.state.lock().await;
        retain_live_test_state(&mut state, self.ttl, now);

        let owned = state
            .refresh_locks
            .get(session_id)
            .is_some_and(|lock| lock.owner_id == owner_id);

        if owned {
            state.refresh_locks.remove(session_id);
        }

        Ok(owned)
    }

    #[cfg(test)]
    pub(super) async fn update_after_refresh(
        &self,
        session_id: &str,
        owner_id: &str,
        session: &AuthenticatedSession,
    ) -> Result<RefreshOwnedMutation, ()> {
        if self.fail_refresh_mutations {
            return Err(());
        }

        let now = Instant::now();
        let mut state = self.state.lock().await;
        retain_live_test_state(&mut state, self.ttl, now);

        if !state
            .refresh_locks
            .get(session_id)
            .is_some_and(|lock| lock.owner_id == owner_id)
        {
            return Ok(RefreshOwnedMutation::OwnershipLost);
        }

        let Some(stored) = state.sessions.get_mut(session_id) else {
            return Ok(RefreshOwnedMutation::SessionMissing);
        };

        stored.session = session.clone();
        Ok(RefreshOwnedMutation::Applied)
    }

    #[cfg(test)]
    pub(super) async fn invalidate_for_refresh(
        &self,
        session_id: &str,
        owner_id: &str,
    ) -> Result<RefreshOwnedMutation, ()> {
        if self.fail_refresh_mutations {
            return Err(());
        }

        let now = Instant::now();
        let mut state = self.state.lock().await;
        retain_live_test_state(&mut state, self.ttl, now);

        if !state
            .refresh_locks
            .get(session_id)
            .is_some_and(|lock| lock.owner_id == owner_id)
        {
            return Ok(RefreshOwnedMutation::OwnershipLost);
        }

        if state.sessions.remove(session_id).is_some() {
            Ok(RefreshOwnedMutation::Applied)
        } else {
            Ok(RefreshOwnedMutation::SessionMissing)
        }
    }
}

#[cfg(test)]
fn retain_live_test_state(state: &mut TestStoreState, ttl: Duration, now: Instant) {
    state
        .sessions
        .retain(|_, stored| now.duration_since(stored.stored_at) < ttl);
    state.refresh_locks.retain(|_, lock| lock.expires_at > now);
}

fn redis_connection_manager(redis_url: &str) -> Result<ConnectionManager, String> {
    let client = redis::Client::open(redis_url).map_err(|_| "Redis URL is invalid".to_owned())?;
    let manager_config = ConnectionManagerConfig::new()
        .set_connection_timeout(Some(REDIS_CONNECT_TIMEOUT))
        .set_response_timeout(Some(REDIS_RESPONSE_TIMEOUT));

    client
        .get_connection_manager_lazy(manager_config)
        .map_err(|_| "Redis connection manager configuration is invalid".to_owned())
}

async fn redis_put(
    redis: &ConnectionManager,
    ttl: Duration,
    session_id: &str,
    session: &AuthenticatedSession,
) -> Result<(), ()> {
    let key = session_key(session_id);
    let mut connection = redis.clone();
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
        .arg(ttl.as_secs())
        .ignore()
        .query_async::<()>(&mut connection)
        .await
        .map_err(|_| ())
}

async fn redis_get(
    redis: &ConnectionManager,
    session_id: &str,
) -> Result<Option<AuthenticatedSession>, ()> {
    let key = session_key(session_id);
    let mut connection = redis.clone();

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

    let refresh_token = refresh_token.filter(|token| !token.is_empty());

    let access_token_expires_at = match access_token_expires_at {
        Some(0) | None => None,
        Some(value) => Some(value),
    };

    Ok(Some(AuthenticatedSession {
        access_token,
        refresh_token,
        access_token_expires_at,
    }))
}

async fn redis_try_acquire_refresh_lock(
    redis: &ConnectionManager,
    session_id: &str,
    owner_id: &str,
    lease: Duration,
) -> Result<bool, ()> {
    let lease_ms = u64::try_from(lease.as_millis()).map_err(|_| ())?;
    if lease_ms == 0 {
        return Err(());
    }

    let key = refresh_lock_key(session_id);
    let mut connection = redis.clone();

    let result: Option<String> = redis::cmd("SET")
        .arg(key)
        .arg(owner_id)
        .arg("NX")
        .arg("PX")
        .arg(lease_ms)
        .query_async(&mut connection)
        .await
        .map_err(|_| ())?;

    Ok(result.is_some())
}

async fn redis_release_refresh_lock(
    redis: &ConnectionManager,
    session_id: &str,
    owner_id: &str,
) -> Result<bool, ()> {
    let key = refresh_lock_key(session_id);
    let mut connection = redis.clone();

    let deleted: i64 = redis::cmd("EVAL")
        .arg(REFRESH_LOCK_RELEASE_SCRIPT)
        .arg(1)
        .arg(key)
        .arg(owner_id)
        .query_async(&mut connection)
        .await
        .map_err(|_| ())?;

    Ok(deleted == 1)
}

async fn redis_update_after_refresh(
    redis: &ConnectionManager,
    session_id: &str,
    owner_id: &str,
    session: &AuthenticatedSession,
) -> Result<RefreshOwnedMutation, ()> {
    let session_key = session_key(session_id);
    let lock_key = refresh_lock_key(session_id);
    let refresh_token = session.refresh_token.as_deref().unwrap_or("");
    let access_token_expires_at = session.access_token_expires_at.unwrap_or(0);
    let mut connection = redis.clone();

    let result: i64 = redis::cmd("EVAL")
        .arg(REFRESH_UPDATE_SCRIPT)
        .arg(2)
        .arg(session_key)
        .arg(lock_key)
        .arg(owner_id)
        .arg(&session.access_token)
        .arg(refresh_token)
        .arg(access_token_expires_at)
        .query_async(&mut connection)
        .await
        .map_err(|_| ())?;

    match result {
        1 => Ok(RefreshOwnedMutation::Applied),
        0 => Ok(RefreshOwnedMutation::SessionMissing),
        -1 => Ok(RefreshOwnedMutation::OwnershipLost),
        _ => Err(()),
    }
}

async fn redis_invalidate_for_refresh(
    redis: &ConnectionManager,
    session_id: &str,
    owner_id: &str,
) -> Result<RefreshOwnedMutation, ()> {
    let session_key = session_key(session_id);
    let lock_key = refresh_lock_key(session_id);
    let mut connection = redis.clone();

    let result: i64 = redis::cmd("EVAL")
        .arg(REFRESH_INVALIDATE_SCRIPT)
        .arg(2)
        .arg(session_key)
        .arg(lock_key)
        .arg(owner_id)
        .query_async(&mut connection)
        .await
        .map_err(|_| ())?;

    match result {
        1 => Ok(RefreshOwnedMutation::Applied),
        0 => Ok(RefreshOwnedMutation::SessionMissing),
        -1 => Ok(RefreshOwnedMutation::OwnershipLost),
        _ => Err(()),
    }
}

pub(super) fn new_session_id() -> String {
    CsrfToken::new_random_len(SESSION_ID_BYTES)
        .secret()
        .to_owned()
}

pub(super) fn new_refresh_owner_id() -> String {
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

fn session_key(session_id: &str) -> String {
    format!("{SESSION_KEY_PREFIX}{session_id}")
}

fn refresh_lock_key(session_id: &str) -> String {
    format!("{REFRESH_LOCK_KEY_PREFIX}{session_id}")
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

    #[tokio::test]
    async fn refresh_update_preserves_test_session_lifetime_origin() {
        let store = SessionStore::for_tests();
        let session_id = new_session_id();
        let owner_id = new_refresh_owner_id();
        let initial = AuthenticatedSession {
            access_token: "initial-access".to_owned(),
            refresh_token: Some("initial-refresh".to_owned()),
            access_token_expires_at: Some(100),
        };
        let refreshed = AuthenticatedSession {
            access_token: "refreshed-access".to_owned(),
            refresh_token: Some("refreshed-refresh".to_owned()),
            access_token_expires_at: Some(200),
        };

        store
            .put(&session_id, &initial)
            .await
            .expect("test session store write must succeed");
        assert!(
            store
                .try_acquire_refresh_lock(&session_id, &owner_id, Duration::from_secs(5))
                .await
                .expect("test refresh lock acquisition must succeed")
        );

        assert!(matches!(
            store
                .update_after_refresh(&session_id, &owner_id, &refreshed)
                .await
                .expect("test refresh update must succeed"),
            RefreshOwnedMutation::Applied
        ));

        let stored = store
            .get(&session_id)
            .await
            .expect("test session store read must succeed")
            .expect("updated session must exist");
        assert!(stored == refreshed);
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

#[cfg(test)]
mod redis_integration_tests {
    use super::*;

    const TEST_TTL: Duration = Duration::from_secs(3600);
    const SHORT_TTL_SECONDS: i64 = 30;
    const TEST_LOCK_LEASE: Duration = Duration::from_secs(5);

    fn redis_manager() -> ConnectionManager {
        let redis_url = std::env::var(REDIS_INTEGRATION_URL_ENV)
            .expect("RTP_REDIS_INTEGRATION_URL must be set for Redis integration tests");

        redis_connection_manager(&redis_url)
            .expect("Redis integration connection manager must be created")
    }

    async fn delete_session_key(redis: &ConnectionManager, session_id: &str) {
        let key = session_key(session_id);
        let mut connection = redis.clone();

        let _: i64 = redis::cmd("DEL")
            .arg(key)
            .query_async(&mut connection)
            .await
            .expect("Redis integration test session key must be deletable");
    }

    async fn delete_refresh_lock(redis: &ConnectionManager, session_id: &str) {
        let key = refresh_lock_key(session_id);
        let mut connection = redis.clone();

        let _: i64 = redis::cmd("DEL")
            .arg(key)
            .query_async(&mut connection)
            .await
            .expect("Redis integration test refresh lock must be deletable");
    }

    async fn cleanup(redis: &ConnectionManager, session_id: &str) {
        delete_session_key(redis, session_id).await;
        delete_refresh_lock(redis, session_id).await;
    }

    async fn ttl_seconds(redis: &ConnectionManager, session_id: &str) -> i64 {
        let key = session_key(session_id);
        let mut connection = redis.clone();

        redis::cmd("TTL")
            .arg(key)
            .query_async(&mut connection)
            .await
            .expect("Redis TTL must be readable")
    }

    async fn set_ttl(redis: &ConnectionManager, session_id: &str, seconds: i64) {
        let key = session_key(session_id);
        let mut connection = redis.clone();

        let applied: bool = redis::cmd("EXPIRE")
            .arg(key)
            .arg(seconds)
            .query_async(&mut connection)
            .await
            .expect("Redis TTL must be settable");

        assert!(applied, "Redis integration test key must exist");
    }

    async fn set_ttl_millis(redis: &ConnectionManager, session_id: &str, millis: u64) {
        let key = session_key(session_id);
        let mut connection = redis.clone();

        let applied: bool = redis::cmd("PEXPIRE")
            .arg(key)
            .arg(millis)
            .query_async(&mut connection)
            .await
            .expect("Redis millisecond TTL must be settable");

        assert!(applied, "Redis integration test key must exist");
    }

    async fn session_exists(redis: &ConnectionManager, session_id: &str) -> bool {
        let key = session_key(session_id);
        let mut connection = redis.clone();

        let exists: i64 = redis::cmd("EXISTS")
            .arg(key)
            .query_async(&mut connection)
            .await
            .expect("Redis session existence must be readable");

        exists == 1
    }

    #[tokio::test]
    #[ignore = "requires Redis at RTP_REDIS_INTEGRATION_URL"]
    async fn redis_backed_lookup_round_trips_absent_optional_fields() {
        let redis = redis_manager();
        let session_id = new_session_id();
        let session = AuthenticatedSession {
            access_token: "integration-access-token".to_owned(),
            refresh_token: None,
            access_token_expires_at: None,
        };

        redis_put(&redis, TEST_TTL, &session_id, &session)
            .await
            .expect("Redis-backed session write must succeed");

        let stored = redis_get(&redis, &session_id)
            .await
            .expect("Redis-backed session read must succeed")
            .expect("Redis-backed session must exist");

        assert!(
            stored == session,
            "Redis-backed session must preserve absent optional fields"
        );

        cleanup(&redis, &session_id).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis at RTP_REDIS_INTEGRATION_URL"]
    async fn redis_backed_lookup_returns_none_for_unknown_key() {
        let redis = redis_manager();
        let session_id = new_session_id();

        cleanup(&redis, &session_id).await;

        let stored = redis_get(&redis, &session_id)
            .await
            .expect("Redis-backed lookup must succeed for an unknown key");

        assert!(
            stored.is_none(),
            "unknown Redis session key must resolve to None"
        );
    }

    #[tokio::test]
    #[ignore = "requires Redis at RTP_REDIS_INTEGRATION_URL"]
    async fn redis_backed_lookup_does_not_extend_ttl() {
        let redis = redis_manager();
        let session_id = new_session_id();
        let session = AuthenticatedSession {
            access_token: "integration-access-token".to_owned(),
            refresh_token: Some("integration-refresh-token".to_owned()),
            access_token_expires_at: Some(12345),
        };

        redis_put(&redis, TEST_TTL, &session_id, &session)
            .await
            .expect("Redis-backed session write must succeed");

        set_ttl(&redis, &session_id, SHORT_TTL_SECONDS).await;

        let ttl_before = ttl_seconds(&redis, &session_id).await;
        assert!(
            ttl_before > 0 && ttl_before <= SHORT_TTL_SECONDS,
            "precondition: Redis key must have the shortened TTL"
        );

        let stored = redis_get(&redis, &session_id)
            .await
            .expect("Redis-backed session read must succeed")
            .expect("Redis-backed session must exist");

        assert!(
            stored == session,
            "Redis-backed session must remain readable"
        );

        let ttl_after = ttl_seconds(&redis, &session_id).await;

        assert!(
            ttl_after > 0,
            "session key must remain alive during the lookup"
        );
        assert!(
            ttl_after <= ttl_before,
            "session lookup must not extend the Redis TTL"
        );
        assert!(
            ttl_after < TEST_TTL.as_secs() as i64,
            "session lookup must not reset the Redis TTL to the configured session TTL"
        );

        cleanup(&redis, &session_id).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis at RTP_REDIS_INTEGRATION_URL"]
    async fn redis_backed_refresh_update_preserves_remaining_session_ttl() {
        let redis = redis_manager();
        let session_id = new_session_id();
        let owner_id = new_refresh_owner_id();
        let initial = AuthenticatedSession {
            access_token: "initial-access".to_owned(),
            refresh_token: Some("initial-refresh".to_owned()),
            access_token_expires_at: Some(100),
        };
        let refreshed = AuthenticatedSession {
            access_token: "refreshed-access".to_owned(),
            refresh_token: Some("refreshed-refresh".to_owned()),
            access_token_expires_at: Some(200),
        };

        redis_put(&redis, TEST_TTL, &session_id, &initial)
            .await
            .expect("Redis-backed session write must succeed");
        set_ttl(&redis, &session_id, SHORT_TTL_SECONDS).await;

        assert!(
            redis_try_acquire_refresh_lock(&redis, &session_id, &owner_id, TEST_LOCK_LEASE)
                .await
                .expect("Redis refresh lock acquisition must succeed")
        );

        let ttl_before = ttl_seconds(&redis, &session_id).await;
        let update = redis_update_after_refresh(&redis, &session_id, &owner_id, &refreshed)
            .await
            .expect("Redis refresh update must succeed");
        assert!(matches!(update, RefreshOwnedMutation::Applied));

        let stored = redis_get(&redis, &session_id)
            .await
            .expect("Redis-backed session read must succeed")
            .expect("Redis-backed session must exist");
        assert!(stored == refreshed);

        let ttl_after = ttl_seconds(&redis, &session_id).await;
        assert!(ttl_after > 0);
        assert!(ttl_after <= ttl_before);
        assert!(ttl_after < TEST_TTL.as_secs() as i64);

        assert!(
            redis_release_refresh_lock(&redis, &session_id, &owner_id)
                .await
                .expect("Redis refresh lock release must succeed")
        );
        cleanup(&redis, &session_id).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis at RTP_REDIS_INTEGRATION_URL"]
    async fn redis_backed_refresh_update_does_not_recreate_expired_session() {
        let redis = redis_manager();
        let session_id = new_session_id();
        let owner_id = new_refresh_owner_id();
        let initial = AuthenticatedSession {
            access_token: "initial-access".to_owned(),
            refresh_token: Some("initial-refresh".to_owned()),
            access_token_expires_at: Some(100),
        };
        let refreshed = AuthenticatedSession {
            access_token: "refreshed-access".to_owned(),
            refresh_token: Some("refreshed-refresh".to_owned()),
            access_token_expires_at: Some(200),
        };

        redis_put(&redis, TEST_TTL, &session_id, &initial)
            .await
            .expect("Redis-backed session write must succeed");
        assert!(
            redis_try_acquire_refresh_lock(&redis, &session_id, &owner_id, TEST_LOCK_LEASE)
                .await
                .expect("Redis refresh lock acquisition must succeed")
        );

        set_ttl_millis(&redis, &session_id, 10).await;
        tokio::time::sleep(Duration::from_millis(30)).await;

        let update = redis_update_after_refresh(&redis, &session_id, &owner_id, &refreshed)
            .await
            .expect("Redis refresh update must produce a semantic result");
        assert!(matches!(update, RefreshOwnedMutation::SessionMissing));
        assert!(!session_exists(&redis, &session_id).await);

        let _ = redis_release_refresh_lock(&redis, &session_id, &owner_id).await;
        cleanup(&redis, &session_id).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis at RTP_REDIS_INTEGRATION_URL"]
    async fn redis_backed_refresh_lock_is_exclusive() {
        let redis = redis_manager();
        let session_id = new_session_id();
        let owner_a = new_refresh_owner_id();
        let owner_b = new_refresh_owner_id();

        cleanup(&redis, &session_id).await;

        assert!(
            redis_try_acquire_refresh_lock(&redis, &session_id, &owner_a, TEST_LOCK_LEASE)
                .await
                .expect("first Redis refresh lock acquisition must succeed")
        );
        assert!(
            !redis_try_acquire_refresh_lock(&redis, &session_id, &owner_b, TEST_LOCK_LEASE)
                .await
                .expect("second Redis refresh lock acquisition must return a result")
        );
        assert!(
            redis_release_refresh_lock(&redis, &session_id, &owner_a)
                .await
                .expect("first Redis refresh lock release must succeed")
        );
        assert!(
            redis_try_acquire_refresh_lock(&redis, &session_id, &owner_b, TEST_LOCK_LEASE)
                .await
                .expect("second owner must acquire released refresh lock")
        );
        assert!(
            redis_release_refresh_lock(&redis, &session_id, &owner_b)
                .await
                .expect("second Redis refresh lock release must succeed")
        );

        cleanup(&redis, &session_id).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis at RTP_REDIS_INTEGRATION_URL"]
    async fn redis_backed_refresh_lock_release_requires_owner() {
        let redis = redis_manager();
        let session_id = new_session_id();
        let owner_a = new_refresh_owner_id();
        let owner_b = new_refresh_owner_id();

        cleanup(&redis, &session_id).await;

        assert!(
            redis_try_acquire_refresh_lock(&redis, &session_id, &owner_a, TEST_LOCK_LEASE)
                .await
                .expect("Redis refresh lock acquisition must succeed")
        );
        assert!(
            !redis_release_refresh_lock(&redis, &session_id, &owner_b)
                .await
                .expect("non-owner release must return a result")
        );
        assert!(
            !redis_try_acquire_refresh_lock(&redis, &session_id, &owner_b, TEST_LOCK_LEASE)
                .await
                .expect("lock must remain owned by first owner")
        );
        assert!(
            redis_release_refresh_lock(&redis, &session_id, &owner_a)
                .await
                .expect("owner release must succeed")
        );

        cleanup(&redis, &session_id).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis at RTP_REDIS_INTEGRATION_URL"]
    async fn redis_backed_refresh_invalidation_requires_owner() {
        let redis = redis_manager();
        let session_id = new_session_id();
        let owner_a = new_refresh_owner_id();
        let owner_b = new_refresh_owner_id();
        let session = AuthenticatedSession {
            access_token: "integration-access-token".to_owned(),
            refresh_token: Some("integration-refresh-token".to_owned()),
            access_token_expires_at: Some(12345),
        };

        redis_put(&redis, TEST_TTL, &session_id, &session)
            .await
            .expect("Redis-backed session write must succeed");

        assert!(
            redis_try_acquire_refresh_lock(&redis, &session_id, &owner_a, TEST_LOCK_LEASE)
                .await
                .expect("Redis refresh lock acquisition must succeed")
        );

        let non_owner = redis_invalidate_for_refresh(&redis, &session_id, &owner_b)
            .await
            .expect("non-owner invalidation must produce a semantic result");

        assert!(matches!(non_owner, RefreshOwnedMutation::OwnershipLost));

        assert!(
            session_exists(&redis, &session_id).await,
            "non-owner invalidation must not delete the authenticated session"
        );

        let owner = redis_invalidate_for_refresh(&redis, &session_id, &owner_a)
            .await
            .expect("owner invalidation must succeed");

        assert!(matches!(owner, RefreshOwnedMutation::Applied));

        assert!(
            !session_exists(&redis, &session_id).await,
            "owner invalidation must delete the authenticated session"
        );

        assert!(
            redis_release_refresh_lock(&redis, &session_id, &owner_a)
                .await
                .expect("owner refresh lock release must succeed")
        );

        cleanup(&redis, &session_id).await;
    }

    #[tokio::test]
    #[ignore = "requires Redis at RTP_REDIS_INTEGRATION_URL"]
    async fn redis_backed_stale_refresh_owner_cannot_update_or_release_new_owner_lock() {
        let redis = redis_manager();
        let session_id = new_session_id();
        let owner_a = new_refresh_owner_id();
        let owner_b = new_refresh_owner_id();
        let initial = AuthenticatedSession {
            access_token: "initial-access".to_owned(),
            refresh_token: Some("initial-refresh".to_owned()),
            access_token_expires_at: Some(100),
        };
        let stale_update = AuthenticatedSession {
            access_token: "stale-access".to_owned(),
            refresh_token: Some("stale-refresh".to_owned()),
            access_token_expires_at: Some(200),
        };
        let current_update = AuthenticatedSession {
            access_token: "current-access".to_owned(),
            refresh_token: Some("current-refresh".to_owned()),
            access_token_expires_at: Some(300),
        };

        redis_put(&redis, TEST_TTL, &session_id, &initial)
            .await
            .expect("Redis-backed session write must succeed");
        assert!(
            redis_try_acquire_refresh_lock(
                &redis,
                &session_id,
                &owner_a,
                Duration::from_millis(20),
            )
            .await
            .expect("first Redis refresh lock acquisition must succeed")
        );

        tokio::time::sleep(Duration::from_millis(40)).await;

        assert!(
            redis_try_acquire_refresh_lock(&redis, &session_id, &owner_b, TEST_LOCK_LEASE)
                .await
                .expect("new owner must acquire expired refresh lock")
        );

        let stale_result = redis_update_after_refresh(&redis, &session_id, &owner_a, &stale_update)
            .await
            .expect("stale update must produce a semantic result");
        assert!(matches!(stale_result, RefreshOwnedMutation::OwnershipLost));
        assert!(
            !redis_release_refresh_lock(&redis, &session_id, &owner_a)
                .await
                .expect("stale release must return a result")
        );

        let current_result =
            redis_update_after_refresh(&redis, &session_id, &owner_b, &current_update)
                .await
                .expect("current owner update must succeed");
        assert!(matches!(current_result, RefreshOwnedMutation::Applied));

        let stored = redis_get(&redis, &session_id)
            .await
            .expect("Redis-backed session read must succeed")
            .expect("Redis-backed session must exist");
        assert!(stored == current_update);

        assert!(
            redis_release_refresh_lock(&redis, &session_id, &owner_b)
                .await
                .expect("current owner release must succeed")
        );
        cleanup(&redis, &session_id).await;
    }
}

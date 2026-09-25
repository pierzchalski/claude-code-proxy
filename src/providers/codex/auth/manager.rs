use std::sync::Arc;
use std::sync::LazyLock;
#[cfg(test)]
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Mutex as AsyncMutex;

use super::constants::{CLIENT_ID, ISSUER, REFRESH_MARGIN_MS};
use super::jwt::{TokenResponse, extract_account_id, validate_token_response};
use super::token_store::{CodexAuthStorage, CodexTokenStore, StoredAuth};
use crate::logging::create_logger;

static CODEX_REFRESH_LOCK: LazyLock<Arc<AsyncMutex<()>>> =
    LazyLock::new(|| Arc::new(AsyncMutex::new(())));

pub struct CodexAuthManager<S: CodexAuthStorage> {
    pub store: CodexTokenStore<S>,
    #[cfg(test)]
    test_auth: Arc<Mutex<Option<StoredAuth>>>,
    refresh_lock: Arc<AsyncMutex<()>>,
    refresh_client: reqwest::Client,
    token_endpoint: String,
}

impl<S: CodexAuthStorage> CodexAuthManager<S> {
    pub fn new(store: CodexTokenStore<S>) -> Self {
        Self::new_with_token_endpoint(store, format!("{ISSUER}/oauth/token"))
    }

    fn new_with_token_endpoint(store: CodexTokenStore<S>, token_endpoint: String) -> Self {
        Self {
            store,
            #[cfg(test)]
            test_auth: Arc::new(Mutex::new(None)),
            refresh_lock: CODEX_REFRESH_LOCK.clone(),
            refresh_client: reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(15))
                .timeout(Duration::from_secs(30))
                .build()
                .expect("failed to create Codex OAuth refresh client"),
            token_endpoint,
        }
    }

    fn now_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    }

    pub async fn get_auth(&self) -> Result<StoredAuth, anyhow::Error> {
        let stored = self.load_auth()?.ok_or_else(|| {
            anyhow::anyhow!("Not authenticated. Run: claude-code-proxy codex auth login")
        })?;

        if stored.expires > Self::now_ms() + REFRESH_MARGIN_MS {
            return Ok(stored);
        }

        self.refresh(false, None).await
    }

    pub async fn force_refresh(&self, rejected_access: &str) -> Result<StoredAuth, anyhow::Error> {
        self.refresh(true, Some(rejected_access)).await
    }

    fn load_auth(&self) -> Result<Option<StoredAuth>, anyhow::Error> {
        #[cfg(test)]
        if let Some(auth) = self
            .test_auth
            .lock()
            .map_err(|e| anyhow::anyhow!("{e}"))?
            .clone()
        {
            return Ok(Some(auth));
        }

        self.store.load_auth()
    }

    async fn refresh(
        &self,
        force: bool,
        rejected_access: Option<&str>,
    ) -> Result<StoredAuth, anyhow::Error> {
        let _refresh_guard = self.refresh_lock.lock().await;
        // A store with a refresh lock file is shared with other programs.
        let lock_path = self.store.refresh_lock_path();
        let shared_store = lock_path.is_some();
        let _file_guard = match lock_path {
            Some(path) => Some(lock_file_exclusive(path).await?),
            None => None,
        };

        // Reload from durable storage after acquiring the single-flight lock.
        // Another request may have rotated and persisted the token while this
        // caller was waiting.
        let current = self
            .load_auth()?
            .ok_or_else(|| anyhow::anyhow!("Not authenticated"))?;

        if (!force && current.expires > Self::now_ms() + REFRESH_MARGIN_MS)
            || rejected_access.is_some_and(|access| current.access != access)
        {
            if !shared_store {
                return Ok(current);
            }
            create_logger("codex").info(
                "codex_auth_adopted",
                Some(serde_json::Map::from_iter([
                    (
                        "path".to_string(),
                        serde_json::json!(self.store.auth_path()),
                    ),
                    (
                        "reason".to_string(),
                        serde_json::json!("changed_before_refresh"),
                    ),
                ])),
            );
            return Ok(current);
        }

        self.refresh_now(&current).await
    }

    async fn refresh_now(&self, current: &StoredAuth) -> Result<StoredAuth, anyhow::Error> {
        if current.refresh.is_empty() {
            anyhow::bail!("No refresh token stored; re-authenticate");
        }

        let form = [
            ("client_id", CLIENT_ID.to_string()),
            ("grant_type", "refresh_token".to_string()),
            ("refresh_token", current.refresh.clone()),
        ];

        let resp = self
            .refresh_client
            .post(&self.token_endpoint)
            .form(&form)
            .send()
            .await
            .map_err(|e| anyhow::anyhow!("refresh network error: {e}"))?;

        let status = resp.status().as_u16();
        if status == 401 || status == 403 {
            if let Some(latest) = self.store.load_auth()?
                && latest != *current
            {
                return Ok(latest);
            }
            let err_msg = resp
                .text()
                .await
                .unwrap_or_else(|_| "Token refresh unauthorized".to_string());
            if let Err(clear_err) = self.store.clear_auth() {
                anyhow::bail!("{err_msg} ({clear_err})");
            }
            anyhow::bail!("{err_msg}");
        }

        if !resp.status().is_success() {
            anyhow::bail!("Token refresh failed: {status}");
        }

        let tokens: TokenResponse = resp
            .json()
            .await
            .map_err(|e| anyhow::anyhow!("failed to parse token response: {e}"))?;
        validate_token_response(&tokens)?;
        let account_id = extract_account_id(&tokens).or_else(|| current.account_id.clone());
        let expires = Self::now_ms() + (tokens.expires_in.unwrap_or(3600) * 1000);
        let next = StoredAuth {
            access: tokens.access_token,
            refresh: tokens.refresh_token,
            expires,
            account_id,
        };
        self.store
            .save_refreshed(current, next, tokens.id_token.as_deref())
    }

    pub fn persist_initial_tokens(
        &self,
        tokens: &TokenResponse,
    ) -> Result<StoredAuth, anyhow::Error> {
        validate_token_response(tokens)?;
        let account_id = extract_account_id(tokens);
        let expires = Self::now_ms() + (tokens.expires_in.unwrap_or(3600) * 1000);
        let auth = StoredAuth {
            access: tokens.access_token.clone(),
            refresh: tokens.refresh_token.clone(),
            expires,
            account_id,
        };
        self.store.save_auth(auth.clone())?;
        Ok(auth)
    }

    #[cfg(test)]
    pub fn set_test_auth(&self, auth: StoredAuth) {
        if let Ok(mut guard) = self.test_auth.lock() {
            *guard = Some(auth);
        }
    }
}

/// Exclusive advisory lock on `path` (created if absent), released on drop.
async fn lock_file_exclusive(path: std::path::PathBuf) -> Result<std::fs::File, anyhow::Error> {
    tokio::task::spawn_blocking(move || {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&path)
            .map_err(|err| anyhow::anyhow!("failed to open lock file {}: {err}", path.display()))?;
        file.lock()
            .map_err(|err| anyhow::anyhow!("failed to lock {}: {err}", path.display()))?;
        Ok(file)
    })
    .await
    .map_err(|err| anyhow::anyhow!("lock task failed: {err}"))?
}

#[cfg(test)]
mod tests {
    use super::super::codex_cli_store::CodexCliAuthStore;
    use super::super::codex_cli_store::test_support::{self, jwt};
    use super::*;
    use crate::auth::{AuthStorage, InMemoryAuthStore};
    use serde_json::{Value, json};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    fn test_store() -> CodexTokenStore<InMemoryAuthStore<StoredAuth>> {
        CodexTokenStore::new(InMemoryAuthStore::new())
    }

    #[tokio::test]
    async fn get_auth_returns_stored() {
        let store = test_store();
        let auth = StoredAuth {
            access: "test_access".into(),
            refresh: "test_refresh".into(),
            expires: 9999999999999,
            account_id: Some("acct_1".into()),
        };
        store.save_auth(auth.clone()).unwrap();
        let manager = CodexAuthManager::new(store);
        let result = manager.get_auth().await.unwrap();
        assert_eq!(result.access, "test_access");
        assert_eq!(result.account_id.as_deref(), Some("acct_1"));
    }

    #[tokio::test]
    async fn get_auth_fails_when_no_auth() {
        let store = test_store();
        let manager = CodexAuthManager::new(store);
        assert!(manager.get_auth().await.is_err());
        assert!(
            manager
                .get_auth()
                .await
                .unwrap_err()
                .to_string()
                .contains("Not authenticated")
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn concurrent_expired_auth_refreshes_once() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let refreshes = Arc::new(AtomicUsize::new(0));
        let server_refreshes = refreshes.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let read = stream.read(&mut request).unwrap();
            assert!(read > 0);
            assert!(String::from_utf8_lossy(&request[..read]).contains("refresh_token=stale"));
            server_refreshes.fetch_add(1, Ordering::SeqCst);

            let body = br#"{"access_token":"rotated","refresh_token":"rotated-refresh","expires_in":3600}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });

        let store = test_store();
        store
            .save_auth(StoredAuth {
                access: "expired".into(),
                refresh: "stale".into(),
                expires: 0,
                account_id: Some("acct_1".into()),
            })
            .unwrap();
        let manager = Arc::new(CodexAuthManager::new_with_token_endpoint(
            store,
            format!("http://{addr}/oauth/token"),
        ));
        let (first, second) = tokio::join!(manager.get_auth(), manager.get_auth());
        let results = [first.unwrap(), second.unwrap()];
        server.join().unwrap();

        assert_eq!(refreshes.load(Ordering::SeqCst), 1);
        assert!(results.iter().all(|auth| auth.access == "rotated"));
        assert!(results.iter().all(|auth| auth.refresh == "rotated-refresh"));
    }

    #[tokio::test]
    async fn stale_401_reuses_already_rotated_auth() {
        let store = test_store();
        store
            .save_auth(StoredAuth {
                access: "rotated".into(),
                refresh: "rotated-refresh".into(),
                expires: u64::MAX,
                account_id: Some("acct_1".into()),
            })
            .unwrap();
        let manager = CodexAuthManager::new_with_token_endpoint(
            store,
            "http://127.0.0.1:1/should-not-be-called".into(),
        );

        let auth = manager.force_refresh("rejected").await.unwrap();
        assert_eq!(auth.access, "rotated");
        assert_eq!(auth.refresh, "rotated-refresh");
    }

    #[tokio::test]
    async fn unauthorized_refresh_preserves_changed_refresh_token() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let backing = InMemoryAuthStore::new();
        let server_backing = backing.clone();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            assert!(stream.read(&mut request).unwrap() > 0);
            server_backing
                .save(StoredAuth {
                    access: "same-access".into(),
                    refresh: "replacement-refresh".into(),
                    expires: u64::MAX,
                    account_id: Some("acct_1".into()),
                })
                .unwrap();
            let body = b"rejected refresh token";
            let response = format!(
                "HTTP/1.1 401 Unauthorized\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(body).unwrap();
        });

        let store = CodexTokenStore::new(backing);
        store
            .save_auth(StoredAuth {
                access: "same-access".into(),
                refresh: "rejected-refresh".into(),
                expires: 0,
                account_id: Some("acct_1".into()),
            })
            .unwrap();
        let manager =
            CodexAuthManager::new_with_token_endpoint(store, format!("http://{addr}/oauth/token"));

        let auth = manager.get_auth().await.unwrap();
        server.join().unwrap();
        assert_eq!(auth.access, "same-access");
        assert_eq!(auth.refresh, "replacement-refresh");
        assert_eq!(manager.store.load_auth().unwrap(), Some(auth));
    }

    #[tokio::test]
    async fn durable_rotation_and_logout_are_observed_by_shared_manager() {
        let store = test_store();
        store
            .save_auth(StoredAuth {
                access: "first".into(),
                refresh: "first-refresh".into(),
                expires: u64::MAX,
                account_id: Some("acct_1".into()),
            })
            .unwrap();
        let manager = CodexAuthManager::new(store);
        assert_eq!(manager.get_auth().await.unwrap().access, "first");

        manager
            .store
            .save_auth(StoredAuth {
                access: "rotated".into(),
                refresh: "rotated-refresh".into(),
                expires: u64::MAX,
                account_id: Some("acct_2".into()),
            })
            .unwrap();
        let rotated = manager.get_auth().await.unwrap();
        assert_eq!(rotated.access, "rotated");
        assert_eq!(rotated.account_id.as_deref(), Some("acct_2"));

        manager.store.clear_auth().unwrap();
        assert!(manager.get_auth().await.is_err());
    }

    /// Answer one token-endpoint request with `status_line` and `body`,
    /// running `before_reply` (given the request text) first.
    fn serve_once(
        status_line: &'static str,
        body: String,
        before_reply: impl FnOnce(&str) + Send + 'static,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/oauth/token", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0u8; 4096];
            let read = stream.read(&mut request).unwrap();
            before_reply(&String::from_utf8_lossy(&request[..read]));
            let response = format!(
                "{status_line}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).unwrap();
        });
        (url, server)
    }

    fn codex_cli_file(access: &str, refresh: &str) -> Value {
        json!({
            "OPENAI_API_KEY": null,
            "tokens": {
                "id_token": jwt(json!({"chatgpt_account_id": "acct_1"})),
                "access_token": access,
                "refresh_token": refresh,
                "account_id": "acct_1"
            },
            "last_refresh": "2026-01-01T00:00:00Z",
            "unknown_to_ccp": [1, 2, 3]
        })
    }

    fn write_json(path: &std::path::Path, value: &Value) {
        std::fs::write(path, serde_json::to_string_pretty(value).unwrap()).unwrap();
    }

    fn read_json(path: &std::path::Path) -> Value {
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    #[tokio::test]
    async fn codex_cli_file_changed_underneath_is_adopted_without_refresh() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("auth.json");
        // ccp's request was rejected with "rejected-access"; by the time the
        // refresh reloads, the Codex CLI has already rotated the file.
        write_json(&path, &codex_cli_file("cli-rotated", "cli-rotated-refresh"));
        let before = std::fs::read(&path).unwrap();
        let manager = CodexAuthManager::new_with_token_endpoint(
            CodexTokenStore::new(CodexCliAuthStore::new(path.clone())),
            "http://127.0.0.1:1/should-not-be-called".into(),
        );

        let auth = manager.force_refresh("rejected-access").await.unwrap();
        assert_eq!(auth.access, "cli-rotated");
        assert_eq!(auth.refresh, "cli-rotated-refresh");
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[tokio::test]
    async fn codex_cli_file_unchanged_is_refreshed_and_written_back() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("auth.json");
        let expired = jwt(json!({"exp": 1}));
        write_json(&path, &codex_cli_file(&expired, "stale"));
        let rotated_access = jwt(json!({"exp": 4_102_444_800u64}));
        let rotated_id = jwt(json!({"chatgpt_account_id": "acct_1", "email": "new"}));
        let body = json!({
            "id_token": rotated_id,
            "access_token": rotated_access,
            "refresh_token": "rotated-refresh",
            "expires_in": 3600
        })
        .to_string();
        let (url, server) = serve_once("HTTP/1.1 200 OK", body, |request| {
            assert!(request.contains("refresh_token=stale"));
        });
        let manager = CodexAuthManager::new_with_token_endpoint(
            CodexTokenStore::new(CodexCliAuthStore::new(path.clone())),
            url,
        );

        let auth = manager.get_auth().await.unwrap();
        server.join().unwrap();
        assert_eq!(auth.access, rotated_access);
        assert_eq!(auth.refresh, "rotated-refresh");
        assert_eq!(auth.account_id.as_deref(), Some("acct_1"));

        let on_disk = read_json(&path);
        assert_eq!(on_disk["tokens"]["access_token"], json!(rotated_access));
        assert_eq!(on_disk["tokens"]["refresh_token"], "rotated-refresh");
        assert_eq!(on_disk["tokens"]["id_token"], json!(rotated_id));
        assert_eq!(on_disk["tokens"]["account_id"], "acct_1");
        assert!(on_disk["OPENAI_API_KEY"].is_null());
        assert_eq!(on_disk["unknown_to_ccp"], json!([1, 2, 3]));
        assert_ne!(on_disk["last_refresh"], "2026-01-01T00:00:00Z");
        // A later load sees the written-back tokens, not an expired copy.
        assert_eq!(manager.get_auth().await.unwrap().access, rotated_access);
    }

    #[tokio::test]
    async fn codex_cli_rotation_during_refresh_is_kept() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("auth.json");
        write_json(&path, &codex_cli_file(&jwt(json!({"exp": 1})), "stale"));
        let server_path = path.clone();
        let body = json!({
            "access_token": "ccp-rotated",
            "refresh_token": "ccp-rotated-refresh",
            "expires_in": 3600
        })
        .to_string();
        let (url, server) = serve_once("HTTP/1.1 200 OK", body, move |_| {
            // The Codex CLI refreshes the same login while ccp's request is
            // in flight (it does not take ccp's lock).
            write_json(
                &server_path,
                &codex_cli_file("cli-rotated", "cli-rotated-refresh"),
            );
        });
        let manager = CodexAuthManager::new_with_token_endpoint(
            CodexTokenStore::new(CodexCliAuthStore::new(path.clone())),
            url,
        );

        let auth = manager.get_auth().await.unwrap();
        server.join().unwrap();
        assert_eq!(auth.access, "cli-rotated");
        assert_eq!(auth.refresh, "cli-rotated-refresh");
        assert_eq!(
            read_json(&path),
            codex_cli_file("cli-rotated", "cli-rotated-refresh")
        );
    }

    #[tokio::test]
    async fn codex_cli_rejected_refresh_keeps_the_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("auth.json");
        write_json(&path, &codex_cli_file(&jwt(json!({"exp": 1})), "revoked"));
        let before = std::fs::read(&path).unwrap();
        let (url, server) = serve_once(
            "HTTP/1.1 401 Unauthorized",
            "refresh token revoked".to_string(),
            |_| {},
        );
        let manager = CodexAuthManager::new_with_token_endpoint(
            CodexTokenStore::new(CodexCliAuthStore::new(path.clone())),
            url,
        );

        let err = manager.get_auth().await.unwrap_err().to_string();
        server.join().unwrap();
        assert!(err.contains("refresh token revoked"), "{err}");
        assert!(err.contains("codex login"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn codex_cli_refresh_waits_for_another_ccp_holding_the_file_lock() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("auth.json");
        write_json(&path, &codex_cli_file("old-access", "old-refresh"));
        let store = CodexCliAuthStore::new(path.clone());
        let lock_path = store.refresh_lock_path().unwrap();
        // Another ccp process is mid-refresh and holds the sidecar lock.
        let other = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .unwrap();
        other.lock().unwrap();
        let manager = Arc::new(CodexAuthManager::new_with_token_endpoint(
            CodexTokenStore::new(store),
            "http://127.0.0.1:1/should-not-be-called".into(),
        ));
        let waiting = tokio::spawn({
            let manager = manager.clone();
            async move { manager.force_refresh("old-access").await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        assert!(!waiting.is_finished());

        // The other process writes its refreshed tokens, then unlocks.
        write_json(
            &path,
            &codex_cli_file("other-rotated", "other-rotated-refresh"),
        );
        drop(other);

        let auth = waiting.await.unwrap().unwrap();
        assert_eq!(auth.access, "other-rotated");
        assert_eq!(auth.refresh, "other-rotated-refresh");
    }

    #[tokio::test]
    async fn codex_cli_token_without_exp_is_used_without_refresh() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("auth.json");
        write_json(&path, &codex_cli_file("opaque-access", "refresh"));
        let before = std::fs::read(&path).unwrap();
        let manager = CodexAuthManager::new_with_token_endpoint(
            CodexTokenStore::new(CodexCliAuthStore::new(path.clone())),
            "http://127.0.0.1:1/should-not-be-called".into(),
        );

        let auth = manager.get_auth().await.unwrap();
        assert_eq!(auth.access, "opaque-access");
        assert_eq!(auth.refresh, "refresh");
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[tokio::test]
    async fn codex_cli_unsaved_refresh_is_reported() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("auth.json");
        write_json(&path, &codex_cli_file(&jwt(json!({"exp": 1})), "stale"));
        let before = std::fs::read(&path).unwrap();
        let body = json!({
            "access_token": "rotated",
            "refresh_token": "rotated-refresh",
            "expires_in": 3600
        })
        .to_string();
        let (url, server) = serve_once("HTTP/1.1 200 OK", body, |_| {});
        let manager = CodexAuthManager::new_with_token_endpoint(
            CodexTokenStore::new(CodexCliAuthStore::with_writers(
                path.clone(),
                test_support::fail_atomic_replace,
                test_support::fail_in_place_write,
            )),
            url,
        );

        let err = manager.get_auth().await.unwrap_err().to_string();
        server.join().unwrap();
        assert!(err.contains("could not be saved"), "{err}");
        assert!(err.contains("codex login"), "{err}");
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }

    #[tokio::test]
    async fn codex_cli_persist_initial_tokens_is_refused() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("auth.json");
        write_json(&path, &codex_cli_file("access", "refresh"));
        let before = std::fs::read(&path).unwrap();
        let manager =
            CodexAuthManager::new(CodexTokenStore::new(CodexCliAuthStore::new(path.clone())));
        let tokens: TokenResponse = serde_json::from_value(json!({
            "access_token": "login-access",
            "refresh_token": "login-refresh"
        }))
        .unwrap();
        assert!(manager.persist_initial_tokens(&tokens).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
    }
}

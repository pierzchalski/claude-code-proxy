use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Once;

use super::codex_cli_store::CodexCliAuthStore;
use crate::auth::{
    AuthStorage, InMemoryAuthStore, Keychain, KeychainFileAuthStore, SystemKeychain,
};
use crate::logging::create_logger;
use crate::{config, paths};

pub const KEYCHAIN_SERVICE: &str = "claude-code-proxy.codex";
pub const KEYCHAIN_ACCOUNT: &str = "auth";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StoredAuth {
    pub access: String,
    pub refresh: String,
    pub expires: u64,
    #[serde(
        default,
        rename = "accountId",
        alias = "account_id",
        skip_serializing_if = "Option::is_none"
    )]
    pub account_id: Option<String>,
}

/// Codex-specific hooks around a token refresh. The defaults are what ccp's
/// own store needs; a store that another program also writes overrides them.
pub trait CodexAuthStorage: AuthStorage<StoredAuth> {
    /// File to hold an exclusive lock on from the pre-refresh reload until the
    /// refreshed tokens are stored, so ccp processes sharing the store do not
    /// refresh the same token concurrently.
    fn refresh_lock_path(&self) -> Option<PathBuf> {
        None
    }

    /// Store `next`, the result of refreshing `previous`, and return what is
    /// stored afterwards. `id_token` is the refresh response's, if any.
    fn save_refreshed(
        &self,
        previous: &StoredAuth,
        next: StoredAuth,
        id_token: Option<&str>,
    ) -> Result<StoredAuth, anyhow::Error> {
        let _ = (previous, id_token);
        self.save(next.clone())?;
        Ok(next)
    }
}

impl CodexAuthStorage for InMemoryAuthStore<StoredAuth> {}

impl<K: Keychain> CodexAuthStorage for KeychainFileAuthStore<StoredAuth, K> {}

pub struct CodexTokenStore<S: AuthStorage<StoredAuth>> {
    store: S,
}

impl<S: CodexAuthStorage> CodexTokenStore<S> {
    pub fn refresh_lock_path(&self) -> Option<PathBuf> {
        self.store.refresh_lock_path()
    }

    pub fn save_refreshed(
        &self,
        previous: &StoredAuth,
        next: StoredAuth,
        id_token: Option<&str>,
    ) -> Result<StoredAuth, anyhow::Error> {
        self.store.save_refreshed(previous, next, id_token)
    }
}

impl<S: AuthStorage<StoredAuth>> CodexTokenStore<S> {
    pub fn new(store: S) -> Self {
        Self { store }
    }

    pub fn load_auth(&self) -> Result<Option<StoredAuth>, anyhow::Error> {
        self.store.load()
    }

    pub fn save_auth(&self, value: StoredAuth) -> Result<(), anyhow::Error> {
        self.store.save(value)
    }

    pub fn clear_auth(&self) -> Result<(), anyhow::Error> {
        self.store.clear()
    }

    pub fn auth_path(&self) -> String {
        self.store.path()
    }
}

/// Where Codex credentials live: ccp's own store, or the Codex CLI's
/// `auth.json` when `codex.authFile` / `CCP_CODEX_AUTH_FILE` is set.
pub enum CodexAuthStore {
    Proxy(KeychainFileAuthStore<StoredAuth, SystemKeychain>),
    CodexCli(CodexCliAuthStore),
}

pub type DefaultCodexAuthStore = CodexAuthStore;

impl AuthStorage<StoredAuth> for CodexAuthStore {
    fn load(&self) -> anyhow::Result<Option<StoredAuth>> {
        match self {
            Self::Proxy(store) => store.load(),
            Self::CodexCli(store) => store.load(),
        }
    }

    fn save(&self, value: StoredAuth) -> anyhow::Result<()> {
        match self {
            Self::Proxy(store) => store.save(value),
            Self::CodexCli(store) => store.save(value),
        }
    }

    fn clear(&self) -> anyhow::Result<()> {
        match self {
            Self::Proxy(store) => store.clear(),
            Self::CodexCli(store) => store.clear(),
        }
    }

    fn path(&self) -> String {
        match self {
            Self::Proxy(store) => store.path(),
            Self::CodexCli(store) => store.path(),
        }
    }
}

impl CodexAuthStorage for CodexAuthStore {
    fn refresh_lock_path(&self) -> Option<PathBuf> {
        match self {
            Self::Proxy(store) => store.refresh_lock_path(),
            Self::CodexCli(store) => store.refresh_lock_path(),
        }
    }

    fn save_refreshed(
        &self,
        previous: &StoredAuth,
        next: StoredAuth,
        id_token: Option<&str>,
    ) -> Result<StoredAuth, anyhow::Error> {
        match self {
            Self::Proxy(store) => store.save_refreshed(previous, next, id_token),
            Self::CodexCli(store) => store.save_refreshed(previous, next, id_token),
        }
    }
}

pub fn file_store() -> CodexTokenStore<DefaultCodexAuthStore> {
    let store = match config::codex_auth_file() {
        Some(path) => CodexAuthStore::CodexCli(CodexCliAuthStore::new(path)),
        None => {
            let primary = paths::provider_auth_file("codex");
            let legacy = paths::provider_legacy_auth_file("codex");
            CodexAuthStore::Proxy(KeychainFileAuthStore::new(
                primary.to_string_lossy().to_string(),
                legacy.to_string_lossy().to_string(),
                KEYCHAIN_SERVICE,
                KEYCHAIN_ACCOUNT,
                use_macos_keychain(),
                SystemKeychain,
            ))
        }
    };
    log_auth_source_once(&store);
    CodexTokenStore::new(store)
}

fn log_auth_source_once(store: &CodexAuthStore) {
    static LOGGED: Once = Once::new();
    LOGGED.call_once(|| {
        let source = match store {
            CodexAuthStore::Proxy(_) => "ccp",
            CodexAuthStore::CodexCli(_) => "codex-cli-file",
        };
        create_logger("codex").info(
            "codex_auth_source",
            Some(serde_json::Map::from_iter([
                ("source".to_string(), serde_json::json!(source)),
                ("path".to_string(), serde_json::json!(store.path())),
            ])),
        );
    });
}

fn use_macos_keychain() -> bool {
    cfg!(target_os = "macos") && std::env::var_os("CCP_CONFIG_DIR").is_none()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::InMemoryAuthStore;
    use serde_json::json;

    #[test]
    fn stored_auth_reads_account_id_alias() {
        let auth: StoredAuth = serde_json::from_value(json!({
            "access": "a",
            "refresh": "r",
            "expires": 123,
            "accountId": "acct"
        }))
        .unwrap();
        assert_eq!(auth.account_id.as_deref(), Some("acct"));
    }

    #[test]
    fn stored_auth_writes_account_id_key() {
        let auth = StoredAuth {
            access: "a".into(),
            refresh: "r".into(),
            expires: 4102444800000,
            account_id: Some("acct_1".into()),
        };
        let value = serde_json::to_value(auth).unwrap();
        assert_eq!(value["accountId"], "acct_1");
        assert!(value.get("account_id").is_none());
    }

    #[test]
    fn stored_auth_roundtrip() {
        let store = CodexTokenStore::new(InMemoryAuthStore::new());
        let auth = StoredAuth {
            access: "token".into(),
            refresh: "refresh".into(),
            expires: 9999999999999,
            account_id: Some("acct_1".into()),
        };
        store.save_auth(auth.clone()).unwrap();
        let loaded = store.load_auth().unwrap().unwrap();
        assert_eq!(loaded.access, "token");
        assert_eq!(loaded.account_id.as_deref(), Some("acct_1"));
    }
}

//! The Codex model catalog: which Codex models exist, which lane each uses,
//! and which the proxy lists.
//!
//! Sources, in order: the proxy's own catalog file (refreshed from the Codex
//! backend's `/models` endpoint), the Codex CLI's `models_cache.json` as a
//! read-only seed, and the static table below when neither exists.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use serde_json::{Map, Value, json};

use super::auth::constants::{CODEX_API_ENDPOINT, RESPONSES_LITE_ORIGINATOR};
use super::auth::manager::CodexAuthManager;
use super::auth::token_store::{DefaultCodexAuthStore, StoredAuth, file_store};
use crate::config;
use crate::logging::create_logger;
use crate::paths::DirResolverEnv;

/// Offline fallback, used only when neither catalog file exists. The flag is
/// `use_responses_lite`.
pub const STATIC_MODELS: &[(&str, bool)] = &[
    ("gpt-5.2", false),
    ("gpt-5.3-codex", false),
    ("gpt-5.3-codex-spark", false),
    ("gpt-5.4", false),
    ("gpt-5.4-mini", false),
    ("gpt-5.5", false),
    ("gpt-5.6-luna", true),
    ("gpt-5.6-sol", true),
    ("gpt-5.6-terra", true),
    ("gpt-6-astra", true),
    ("gpt-6-luna", true),
    ("gpt-6-sol", true),
];

/// `client_version` sent to `/models` when neither `CCP_CODEX_CLIENT_VERSION`
/// nor the Codex CLI's cache names one. Value seen in a Codex CLI cache.
pub const DEFAULT_CLIENT_VERSION: &str = "0.155.1";

pub const PERIODIC_REFRESH_INTERVAL: Duration = Duration::from_secs(3 * 60 * 60);
pub const MISS_REFRESH_INTERVAL: Duration = Duration::from_secs(60);
const FETCH_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogModel {
    pub slug: String,
    /// `visibility == "list"`.
    pub listed: bool,
    pub supported_in_api: bool,
    pub use_responses_lite: bool,
    /// `context_window`, else `max_context_window`.
    pub context_window: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogSource {
    Proxy,
    CodexCliCache,
    Static,
}

impl CatalogSource {
    pub fn label(self) -> &'static str {
        match self {
            CatalogSource::Proxy => "proxy catalog",
            CatalogSource::CodexCliCache => "codex cli cache (read-only seed)",
            CatalogSource::Static => "static fallback",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CatalogSnapshot {
    pub source: CatalogSource,
    pub path: Option<PathBuf>,
    pub fetched_at: Option<String>,
    pub etag: Option<String>,
    pub client_version: Option<String>,
    pub models: Vec<CatalogModel>,
    raw_models: Vec<Value>,
}

impl CatalogSnapshot {
    pub fn static_fallback() -> Self {
        Self {
            source: CatalogSource::Static,
            path: None,
            fetched_at: None,
            etag: None,
            client_version: None,
            models: STATIC_MODELS
                .iter()
                .map(|(slug, lite)| CatalogModel {
                    slug: (*slug).to_string(),
                    listed: true,
                    supported_in_api: true,
                    use_responses_lite: *lite,
                    context_window: None,
                })
                .collect(),
            raw_models: Vec::new(),
        }
    }

    pub fn model(&self, slug: &str) -> Option<&CatalogModel> {
        self.models.iter().find(|model| model.slug == slug)
    }

    /// Whether requests for this exact slug are forwarded upstream.
    pub fn is_allowed(&self, slug: &str) -> bool {
        self.model(slug).is_some_and(|model| model.supported_in_api)
    }

    /// Whether this slug, or its base when it ends in `-fast`, is allowed.
    pub fn accepts(&self, slug: &str) -> bool {
        self.is_allowed(slug)
            || slug
                .strip_suffix("-fast")
                .is_some_and(|base| self.is_allowed(base))
    }

    pub fn uses_responses_lite(&self, slug: &str) -> bool {
        self.model(slug)
            .is_some_and(|model| model.use_responses_lite)
    }

    pub fn allowed_slugs(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .models
            .iter()
            .filter(|model| model.supported_in_api)
            .map(|model| model.slug.clone())
            .collect();
        out.sort_unstable();
        out.dedup();
        out
    }

    /// Listed models plus their `-fast` siblings.
    pub fn advertised_models(&self) -> Vec<String> {
        let mut out = Vec::new();
        for model in &self.models {
            if model.listed && model.supported_in_api {
                out.push(model.slug.clone());
                out.push(format!("{}-fast", model.slug));
            }
        }
        out.sort_unstable();
        out.dedup();
        out
    }

    fn from_file(source: CatalogSource, path: &Path) -> Option<Self> {
        let bytes = std::fs::read(path).ok()?;
        let parsed = parse_catalog_file(&bytes)?;
        if parsed.models.is_empty() {
            return None;
        }
        Some(Self {
            source,
            path: Some(path.to_path_buf()),
            fetched_at: parsed.fetched_at,
            etag: parsed.etag,
            client_version: parsed.client_version,
            models: parsed.models,
            raw_models: parsed.raw_models,
        })
    }

    fn to_file_json(&self) -> Value {
        json!({
            "fetched_at": self.fetched_at,
            "etag": self.etag,
            "client_version": self.client_version,
            "models": self.raw_models,
        })
    }
}

struct ParsedCatalog {
    fetched_at: Option<String>,
    etag: Option<String>,
    client_version: Option<String>,
    models: Vec<CatalogModel>,
    raw_models: Vec<Value>,
}

/// Parses a catalog file (the proxy's or the Codex CLI's cache). `None` when
/// the top level is not an object with a `models` array; individual malformed
/// models are skipped. Never reads `identity`.
fn parse_catalog_file(bytes: &[u8]) -> Option<ParsedCatalog> {
    let value: Value = serde_json::from_slice(bytes).ok()?;
    let object = value.as_object()?;
    let raw = object.get("models")?.as_array()?;
    let (models, raw_models) = parse_models(raw);
    let text = |key: &str| object.get(key).and_then(Value::as_str).map(str::to_string);
    Some(ParsedCatalog {
        fetched_at: text("fetched_at"),
        etag: text("etag"),
        client_version: text("client_version"),
        models,
        raw_models,
    })
}

fn parse_models(raw: &[Value]) -> (Vec<CatalogModel>, Vec<Value>) {
    let mut models = Vec::new();
    let mut kept = Vec::new();
    for value in raw {
        if let Some(model) = parse_model(value) {
            models.push(model);
            kept.push(value.clone());
        }
    }
    (models, kept)
}

fn parse_model(value: &Value) -> Option<CatalogModel> {
    let object = value.as_object()?;
    let slug = object.get("slug")?.as_str()?.trim();
    if slug.is_empty() {
        return None;
    }
    let flag =
        |key: &str, default: bool| object.get(key).and_then(Value::as_bool).unwrap_or(default);
    let number = |key: &str| object.get(key).and_then(Value::as_i64);
    Some(CatalogModel {
        slug: slug.to_string(),
        listed: object.get("visibility").and_then(Value::as_str) == Some("list"),
        supported_in_api: flag("supported_in_api", true),
        use_responses_lite: flag("use_responses_lite", false),
        context_window: number("context_window").or_else(|| number("max_context_window")),
    })
}

/// Human-readable catalog listing for `claude-code-proxy codex models`.
pub fn describe(snapshot: &CatalogSnapshot) -> String {
    use std::fmt::Write;
    let or_none = |value: &Option<String>| value.clone().unwrap_or_else(|| "-".to_string());
    let mut out = String::new();
    let _ = writeln!(out, "source: {}", snapshot.source.label());
    let _ = writeln!(
        out,
        "path: {}",
        snapshot
            .path
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "-".to_string())
    );
    let _ = writeln!(out, "fetched_at: {}", or_none(&snapshot.fetched_at));
    let _ = writeln!(out, "etag: {}", or_none(&snapshot.etag));
    let _ = writeln!(out, "client_version: {}", or_none(&snapshot.client_version));
    let width = snapshot
        .models
        .iter()
        .map(|model| model.slug.len())
        .max()
        .unwrap_or(0);
    let _ = writeln!(
        out,
        "{:width$}  {:4}  {:6}  {:9}  context",
        "model", "lane", "listed", "accepted"
    );
    for model in &snapshot.models {
        let _ = writeln!(
            out,
            "{:width$}  {:4}  {:6}  {:9}  {}",
            model.slug,
            if model.use_responses_lite {
                "lite"
            } else {
                "full"
            },
            if model.listed { "yes" } else { "no" },
            if model.supported_in_api { "yes" } else { "no" },
            model
                .context_window
                .map(|tokens| tokens.to_string())
                .unwrap_or_else(|| "-".to_string()),
        );
    }
    out
}

// ---------------------------------------------------------------------------
// Fetching
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum FetchOutcome {
    NotModified,
    Updated {
        etag: Option<String>,
        models: Vec<Value>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchError {
    /// `auth_unavailable`, `unauthorized`, `http_status`, `transport`,
    /// `invalid_body`, `no_usable_models`, or `not_configured`.
    pub reason: &'static str,
    pub detail: String,
}

impl FetchError {
    pub fn new(reason: &'static str, detail: impl Into<String>) -> Self {
        Self {
            reason,
            detail: detail.into(),
        }
    }
}

impl std::fmt::Display for FetchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.reason, self.detail)
    }
}

#[async_trait]
pub trait CatalogFetcher: Send + Sync {
    async fn fetch(
        &self,
        etag: Option<&str>,
        client_version: &str,
    ) -> Result<FetchOutcome, FetchError>;
}

/// `GET <codex api root>/models?client_version=<v>` with the Codex bearer
/// token, as the Codex CLI does. Uses the stored access token only while it
/// is unexpired and never refreshes the login: with a shared Codex CLI
/// `auth.json`, every refresh rotates the CLI's refresh token, and the catalog
/// runs on timers when nothing else is using the proxy. Requests refresh the
/// token on their own path.
pub struct HttpCatalogFetcher {
    client: reqwest::Client,
    url: String,
    auth_manager: CodexAuthManager<DefaultCodexAuthStore>,
}

impl HttpCatalogFetcher {
    pub fn new(
        client: reqwest::Client,
        url: String,
        auth_manager: CodexAuthManager<DefaultCodexAuthStore>,
    ) -> Self {
        Self {
            client,
            url,
            auth_manager,
        }
    }

    async fn send(
        &self,
        auth: &StoredAuth,
        etag: Option<&str>,
        client_version: &str,
    ) -> Result<reqwest::Response, FetchError> {
        let mut request = self
            .client
            .get(&self.url)
            .query(&[("client_version", client_version)])
            .bearer_auth(&auth.access)
            .header(http::header::ACCEPT, "application/json")
            .header(
                "originator",
                config::codex_originator(RESPONSES_LITE_ORIGINATOR),
            );
        if let Some(account_id) = auth.account_id.as_deref() {
            request = request.header("ChatGPT-Account-Id", account_id);
        }
        let user_agent = config::codex_user_agent(RESPONSES_LITE_ORIGINATOR);
        if !user_agent.is_empty() {
            request = request.header(http::header::USER_AGENT, user_agent);
        }
        if let Some(etag) = etag {
            request = request.header(http::header::IF_NONE_MATCH, etag);
        }
        request
            .timeout(FETCH_TIMEOUT)
            .send()
            .await
            .map_err(|error| FetchError::new("transport", error.to_string()))
    }

    fn unexpired_auth(&self) -> Result<StoredAuth, FetchError> {
        let auth = self
            .auth_manager
            .stored_auth()
            .map_err(|error| FetchError::new("auth_unavailable", error.to_string()))?
            .ok_or_else(|| FetchError::new("auth_unavailable", "no stored Codex login"))?;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        if auth.expires <= now_ms {
            return Err(FetchError::new(
                "auth_unavailable",
                "stored access token has expired; not refreshing it for the catalog",
            ));
        }
        Ok(auth)
    }
}

#[async_trait]
impl CatalogFetcher for HttpCatalogFetcher {
    async fn fetch(
        &self,
        etag: Option<&str>,
        client_version: &str,
    ) -> Result<FetchOutcome, FetchError> {
        let auth = self.unexpired_auth()?;
        let response = self.send(&auth, etag, client_version).await?;
        let status = response.status();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            return Err(FetchError::new(
                "unauthorized",
                "HTTP 401; not refreshing the login for the catalog",
            ));
        }
        if status == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(FetchOutcome::NotModified);
        }
        if !status.is_success() {
            return Err(FetchError::new(
                "http_status",
                format!("HTTP {}", status.as_u16()),
            ));
        }
        let new_etag = response
            .headers()
            .get(http::header::ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body: Value = response
            .json()
            .await
            .map_err(|error| FetchError::new("invalid_body", error.to_string()))?;
        let models = body
            .get("models")
            .and_then(Value::as_array)
            .cloned()
            .ok_or_else(|| FetchError::new("invalid_body", "response has no models array"))?;
        Ok(FetchOutcome::Updated {
            etag: new_etag,
            models,
        })
    }
}

/// `https://…/codex/responses` → `https://…/codex/models`.
pub fn models_endpoint(base_url: &str) -> String {
    let base_url = base_url.trim_end_matches('/');
    match base_url.strip_suffix("/responses") {
        Some(api_root) => format!("{api_root}/models"),
        None => format!("{base_url}/models"),
    }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshTrigger {
    Startup,
    Periodic,
    UnknownModel,
    Manual,
}

impl RefreshTrigger {
    fn as_str(self) -> &'static str {
        match self {
            RefreshTrigger::Startup => "startup",
            RefreshTrigger::Periodic => "periodic",
            RefreshTrigger::UnknownModel => "unknown_model",
            RefreshTrigger::Manual => "manual",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    Updated { models: usize },
    NotModified,
}

pub struct CatalogStoreConfig {
    pub proxy_path: Option<PathBuf>,
    pub codex_cli_cache_path: Option<PathBuf>,
    pub client_version_override: Option<String>,
    pub fetcher: Option<Arc<dyn CatalogFetcher>>,
    pub miss_refresh_interval: Duration,
}

pub struct CatalogStore {
    proxy_path: Option<PathBuf>,
    codex_cli_cache_path: Option<PathBuf>,
    client_version_override: Option<String>,
    fetcher: Option<Arc<dyn CatalogFetcher>>,
    miss_refresh_interval: Duration,
    snapshot: RwLock<Arc<CatalogSnapshot>>,
    refresh_lock: tokio::sync::Mutex<()>,
    last_miss_refresh: Mutex<Option<Instant>>,
    background_started: AtomicBool,
}

impl CatalogStore {
    pub fn new(config: CatalogStoreConfig) -> Self {
        let snapshot = load_snapshot(
            config.proxy_path.as_deref(),
            config.codex_cli_cache_path.as_deref(),
        );
        Self {
            proxy_path: config.proxy_path,
            codex_cli_cache_path: config.codex_cli_cache_path,
            client_version_override: config.client_version_override,
            fetcher: config.fetcher,
            miss_refresh_interval: config.miss_refresh_interval,
            snapshot: RwLock::new(Arc::new(snapshot)),
            refresh_lock: tokio::sync::Mutex::new(()),
            last_miss_refresh: Mutex::new(None),
            background_started: AtomicBool::new(false),
        }
    }

    pub fn static_only() -> Self {
        Self::new(CatalogStoreConfig {
            proxy_path: None,
            codex_cli_cache_path: None,
            client_version_override: None,
            fetcher: None,
            miss_refresh_interval: MISS_REFRESH_INTERVAL,
        })
    }

    /// The process store for a real run: files under the proxy's state dir and
    /// `$CODEX_HOME`, fetching with the Codex auth the proxy already uses.
    pub fn from_environment() -> Self {
        let deps = DirResolverEnv::default();
        let client = super::client::proxied_client_builder()
            .connect_timeout(Duration::from_secs(15))
            .build()
            .expect("failed to create Codex model catalog HTTP client");
        let fetcher = HttpCatalogFetcher::new(
            client,
            models_endpoint(&config::codex_base_url(CODEX_API_ENDPOINT)),
            CodexAuthManager::new(file_store()),
        );
        Self::new(CatalogStoreConfig {
            proxy_path: Some(proxy_catalog_path(&deps)),
            codex_cli_cache_path: Some(codex_cli_cache_path(&deps)),
            client_version_override: std::env::var("CCP_CODEX_CLIENT_VERSION")
                .ok()
                .filter(|value| !value.trim().is_empty()),
            fetcher: Some(Arc::new(fetcher)),
            miss_refresh_interval: MISS_REFRESH_INTERVAL,
        })
    }

    pub fn snapshot(&self) -> Arc<CatalogSnapshot> {
        self.snapshot
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn can_fetch(&self) -> bool {
        self.fetcher.is_some()
    }

    fn replace_snapshot(&self, snapshot: CatalogSnapshot) {
        *self
            .snapshot
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Arc::new(snapshot);
    }

    fn client_version(&self) -> String {
        if let Some(version) = self.client_version_override.as_deref() {
            return version.to_string();
        }
        self.codex_cli_cache_path
            .as_deref()
            .and_then(|path| std::fs::read(path).ok())
            .and_then(|bytes| parse_catalog_file(&bytes))
            .and_then(|parsed| parsed.client_version)
            .unwrap_or_else(|| DEFAULT_CLIENT_VERSION.to_string())
    }

    pub async fn refresh(&self, trigger: RefreshTrigger) -> Result<RefreshOutcome, FetchError> {
        let _guard = self.refresh_lock.lock().await;
        self.refresh_locked(trigger).await
    }

    async fn refresh_locked(&self, trigger: RefreshTrigger) -> Result<RefreshOutcome, FetchError> {
        let log = create_logger("codex");
        let Some(fetcher) = self.fetcher.as_ref() else {
            return Err(FetchError::new(
                "not_configured",
                "model catalog fetching is not configured",
            ));
        };
        let current = self.snapshot();
        let client_version = self.client_version();
        // The ETag describes the catalog fetched with the stored client_version;
        // after a Codex CLI upgrade, fetch unconditionally so version-gated
        // models can appear even if the backend's ETag ignores the version.
        let etag = (current.source == CatalogSource::Proxy
            && current.client_version.as_deref() == Some(client_version.as_str()))
        .then(|| current.etag.clone())
        .flatten();
        let result = fetcher.fetch(etag.as_deref(), &client_version).await;
        let now = now_rfc3339();
        match result {
            Ok(FetchOutcome::NotModified) => {
                let mut next = (*current).clone();
                next.fetched_at = Some(now);
                next.client_version = Some(client_version);
                self.persist(&next, &log);
                self.replace_snapshot(next);
                log.info(
                    "codex model catalog not modified",
                    Some(fields([
                        ("trigger", json!(trigger.as_str())),
                        ("etag", json!(etag)),
                    ])),
                );
                Ok(RefreshOutcome::NotModified)
            }
            Ok(FetchOutcome::Updated {
                etag: new_etag,
                models,
            }) => {
                let (parsed, raw_models) = parse_models(&models);
                if parsed.is_empty() {
                    let error =
                        FetchError::new("no_usable_models", "response contained no usable models");
                    log_refresh_failure(&log, trigger, &error, &current);
                    return Err(error);
                }
                let added: Vec<&str> = parsed
                    .iter()
                    .filter(|model| current.model(&model.slug).is_none())
                    .map(|model| model.slug.as_str())
                    .collect();
                let removed: Vec<&str> = current
                    .models
                    .iter()
                    .filter(|model| !parsed.iter().any(|next| next.slug == model.slug))
                    .map(|model| model.slug.as_str())
                    .collect();
                log.info(
                    "codex model catalog refreshed",
                    Some(fields([
                        ("trigger", json!(trigger.as_str())),
                        ("models", json!(parsed.len())),
                        ("added", json!(added)),
                        ("removed", json!(removed)),
                        ("previousSource", json!(current.source.label())),
                        ("etag", json!(new_etag)),
                        ("clientVersion", json!(client_version)),
                    ])),
                );
                let count = parsed.len();
                let next = CatalogSnapshot {
                    source: CatalogSource::Proxy,
                    path: self.proxy_path.clone(),
                    fetched_at: Some(now),
                    etag: new_etag,
                    client_version: Some(client_version),
                    models: parsed,
                    raw_models,
                };
                let missing = missing_hardcoded_targets(&next);
                if !missing.is_empty() {
                    log.warn(
                        "codex model catalog lacks hardcoded targets",
                        Some(fields([("missing", json!(missing))])),
                    );
                }
                self.persist(&next, &log);
                self.replace_snapshot(next);
                Ok(RefreshOutcome::Updated { models: count })
            }
            Err(error) => {
                log_refresh_failure(&log, trigger, &error, &current);
                Err(error)
            }
        }
    }

    fn persist(&self, snapshot: &CatalogSnapshot, log: &crate::logging::Logger) {
        let Some(path) = self.proxy_path.as_deref() else {
            return;
        };
        if snapshot.source != CatalogSource::Proxy {
            return;
        }
        let result = (|| -> anyhow::Result<()> {
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            let body = serde_json::to_vec_pretty(&snapshot.to_file_json())?;
            crate::auth::replace_file_atomically(path, &body)
        })();
        if let Err(error) = result {
            log.warn(
                "codex model catalog write failed",
                Some(fields([
                    ("path", json!(path.display().to_string())),
                    ("error", json!(error.to_string())),
                ])),
            );
        }
    }

    /// Called when routing finds no provider for `slug`. Waits for any
    /// in-flight refresh, then fetches at most once per miss interval.
    /// Returns whether the catalog now accepts `slug`.
    pub async fn refresh_for_unknown_model(&self, slug: &str) -> bool {
        if self.snapshot().accepts(slug) {
            return true;
        }
        if self.fetcher.is_none() {
            return false;
        }
        let _guard = self.refresh_lock.lock().await;
        if self.snapshot().accepts(slug) {
            return true;
        }
        {
            let mut last = self
                .last_miss_refresh
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if last.is_some_and(|at| at.elapsed() < self.miss_refresh_interval) {
                return false;
            }
            *last = Some(Instant::now());
        }
        let _ = self.refresh_locked(RefreshTrigger::UnknownModel).await;
        let snapshot = self.snapshot();
        let accepted = snapshot.accepts(slug);
        if accepted {
            create_logger("codex").info(
                "model accepted from catalog",
                Some(fields([
                    ("model", json!(slug)),
                    ("source", json!(snapshot.source.label())),
                ])),
            );
        }
        accepted
    }

    /// Refresh now, then every `PERIODIC_REFRESH_INTERVAL`. Runs once per
    /// store; a no-op without a fetcher. Never blocks the caller.
    pub fn spawn_background_refresh(self: &Arc<Self>) {
        if !self.can_fetch() || self.background_started.swap(true, Ordering::SeqCst) {
            return;
        }
        let store = Arc::clone(self);
        tokio::spawn(async move {
            let _ = store.refresh(RefreshTrigger::Startup).await;
            loop {
                tokio::time::sleep(PERIODIC_REFRESH_INTERVAL).await;
                let _ = store.refresh(RefreshTrigger::Periodic).await;
            }
        });
    }
}

/// Slugs the proxy names in code (alias targets, the auto-review model, the
/// web-search upgrade targets) that `snapshot` does not accept.
pub fn missing_hardcoded_targets(snapshot: &CatalogSnapshot) -> Vec<&'static str> {
    use crate::providers::codex::translate::model_allowlist::{
        LITE_ONLY_WEB_SEARCH_UPGRADES, MODEL_ALIASES,
    };
    let mut targets: Vec<&'static str> = MODEL_ALIASES
        .iter()
        .map(|(_, target)| *target)
        .chain(std::iter::once(crate::server::CODEX_AUTO_REVIEW_MODEL))
        .chain(
            LITE_ONLY_WEB_SEARCH_UPGRADES
                .iter()
                .map(|(_, full_lane)| *full_lane),
        )
        .filter(|target| !snapshot.is_allowed(target))
        .collect();
    targets.sort_unstable();
    targets.dedup();
    targets
}

fn log_refresh_failure(
    log: &crate::logging::Logger,
    trigger: RefreshTrigger,
    error: &FetchError,
    kept: &CatalogSnapshot,
) {
    log.warn(
        "codex model catalog refresh failed",
        Some(fields([
            ("trigger", json!(trigger.as_str())),
            ("reason", json!(error.reason)),
            ("error", json!(error.detail)),
            ("keptSource", json!(kept.source.label())),
            ("keptModels", json!(kept.models.len())),
        ])),
    );
}

fn fields<const N: usize>(entries: [(&str, Value); N]) -> Map<String, Value> {
    entries
        .into_iter()
        .map(|(key, value)| (key.to_string(), value))
        .collect()
}

fn now_rfc3339() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_default()
}

fn load_snapshot(
    proxy_path: Option<&Path>,
    codex_cli_cache_path: Option<&Path>,
) -> CatalogSnapshot {
    if let Some(snapshot) =
        proxy_path.and_then(|path| CatalogSnapshot::from_file(CatalogSource::Proxy, path))
    {
        return snapshot;
    }
    if let Some(snapshot) = codex_cli_cache_path
        .and_then(|path| CatalogSnapshot::from_file(CatalogSource::CodexCliCache, path))
    {
        return snapshot;
    }
    CatalogSnapshot::static_fallback()
}

pub fn proxy_catalog_path(deps: &DirResolverEnv) -> PathBuf {
    crate::paths::resolve_state_dir(deps)
        .join("codex")
        .join("models_catalog.json")
}

/// `$CODEX_HOME/models_cache.json`, else `~/.codex/models_cache.json`.
pub fn codex_cli_cache_path(deps: &DirResolverEnv) -> PathBuf {
    crate::paths::codex_cli_auth_file(deps).with_file_name("models_cache.json")
}

// ---------------------------------------------------------------------------
// Process-wide store
// ---------------------------------------------------------------------------

static INSTALLED: OnceLock<Arc<CatalogStore>> = OnceLock::new();
static STATIC_STORE: OnceLock<Arc<CatalogStore>> = OnceLock::new();

#[cfg(test)]
thread_local! {
    static TEST_STORE: std::cell::RefCell<Option<Arc<CatalogStore>>> =
        const { std::cell::RefCell::new(None) };
}

/// Installs the environment-backed store for this process. Until this runs
/// (and always in library tests), the store is the static fallback with no
/// fetching, so nothing reads `~/.codex` or the Codex credentials.
pub fn install_from_environment() -> Arc<CatalogStore> {
    INSTALLED
        .get_or_init(|| Arc::new(CatalogStore::from_environment()))
        .clone()
}

pub fn store() -> Arc<CatalogStore> {
    #[cfg(test)]
    if let Some(store) = TEST_STORE.with(|cell| cell.borrow().clone()) {
        return store;
    }
    if let Some(store) = INSTALLED.get() {
        return store.clone();
    }
    STATIC_STORE
        .get_or_init(|| Arc::new(CatalogStore::static_only()))
        .clone()
}

pub fn current() -> Arc<CatalogSnapshot> {
    store().snapshot()
}

pub async fn refresh_for_unknown_model(slug: &str) -> bool {
    store().refresh_for_unknown_model(slug).await
}

pub fn spawn_background_refresh() {
    store().spawn_background_refresh();
}

/// Uses `store` for catalog lookups on this thread until the guard drops.
#[cfg(test)]
pub(crate) fn set_test_store(store: Arc<CatalogStore>) -> TestStoreGuard {
    let previous = TEST_STORE.with(|cell| cell.borrow_mut().replace(store));
    TestStoreGuard { previous }
}

#[cfg(test)]
pub(crate) struct TestStoreGuard {
    previous: Option<Arc<CatalogStore>>,
}

#[cfg(test)]
impl Drop for TestStoreGuard {
    fn drop(&mut self) {
        let previous = self.previous.take();
        TEST_STORE.with(|cell| *cell.borrow_mut() = previous);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::providers::codex::auth::test_http::{MockServer, json_response, spawn_mock_server};
    use crate::providers::codex::translate::model_allowlist::{
        assert_allowed_model, resolve_model_request, uses_responses_lite,
    };
    use crate::providers::codex::translate::request::ServiceTier;
    use std::sync::atomic::AtomicUsize;

    /// Shape of a Codex CLI `models_cache.json`, with invented slugs.
    const CLI_CACHE_FIXTURE: &str = r#"{
        "fetched_at": "2026-09-01T00:00:00Z",
        "etag": "W/\"cli-etag\"",
        "client_version": "0.150.0",
        "identity": "private-identity-must-not-be-copied",
        "models": [
            {
                "slug": "gpt-7-test",
                "display_name": "gpt-7-test",
                "visibility": "list",
                "supported_in_api": true,
                "use_responses_lite": true,
                "context_window": 272000,
                "max_context_window": 872000,
                "supports_search_tool": true,
                "default_reasoning_level": "medium",
                "supported_reasoning_levels": [{"effort": "low", "description": "fast"}],
                "service_tiers": [{"id": "priority", "name": "Fast", "description": "1.5x speed"}],
                "additional_speed_tiers": ["fast"],
                "input_modalities": ["text", "image"],
                "upgrade": null,
                "priority": 0
            },
            {
                "slug": "gpt-7-full-test",
                "visibility": "list",
                "supported_in_api": true,
                "use_responses_lite": false,
                "max_context_window": 400000
            },
            {
                "slug": "gpt-7-hidden-test",
                "visibility": "hide",
                "supported_in_api": true,
                "use_responses_lite": true
            },
            {
                "slug": "gpt-7-tui-only-test",
                "visibility": "list",
                "supported_in_api": false,
                "use_responses_lite": true
            },
            {"visibility": "list"},
            "not-a-model"
        ]
    }"#;

    /// A backend `/models` body that adds `gpt-8-test`.
    const BACKEND_BODY: &str = r#"{"models": [
        {"slug": "gpt-7-test", "visibility": "list", "supported_in_api": true, "use_responses_lite": true, "context_window": 272000},
        {"slug": "gpt-7-tui-only-test", "visibility": "list", "supported_in_api": false, "use_responses_lite": true},
        {"slug": "gpt-8-test", "visibility": "list", "supported_in_api": true, "use_responses_lite": false, "context_window": 500000}
    ]}"#;

    struct Fixture {
        dir: tempfile::TempDir,
    }

    impl Fixture {
        fn new() -> Self {
            Self {
                dir: tempfile::tempdir().unwrap(),
            }
        }

        fn proxy_path(&self) -> PathBuf {
            self.dir.path().join("state/codex/models_catalog.json")
        }

        fn cli_path(&self) -> PathBuf {
            self.dir.path().join("codex-home/models_cache.json")
        }

        fn write_cli_cache(&self) {
            std::fs::create_dir_all(self.cli_path().parent().unwrap()).unwrap();
            std::fs::write(self.cli_path(), CLI_CACHE_FIXTURE).unwrap();
        }

        fn write_proxy_catalog(&self, fetched_at: &str, etag: &str, client_version: &str) {
            let models: Value = serde_json::from_str(BACKEND_BODY).unwrap();
            let file = json!({
                "fetched_at": fetched_at,
                "etag": etag,
                "client_version": client_version,
                "models": models["models"],
            });
            std::fs::create_dir_all(self.proxy_path().parent().unwrap()).unwrap();
            std::fs::write(self.proxy_path(), file.to_string()).unwrap();
        }

        fn store(&self, fetcher: Option<Arc<dyn CatalogFetcher>>) -> Arc<CatalogStore> {
            self.store_with_version(fetcher, None)
        }

        fn store_with_version(
            &self,
            fetcher: Option<Arc<dyn CatalogFetcher>>,
            client_version_override: Option<&str>,
        ) -> Arc<CatalogStore> {
            Arc::new(CatalogStore::new(CatalogStoreConfig {
                proxy_path: Some(self.proxy_path()),
                codex_cli_cache_path: Some(self.cli_path()),
                client_version_override: client_version_override.map(str::to_string),
                fetcher,
                miss_refresh_interval: MISS_REFRESH_INTERVAL,
            }))
        }
    }

    struct Backend {
        server: MockServer,
        hits: Arc<AtomicUsize>,
        last_request: Arc<Mutex<String>>,
    }

    impl Backend {
        fn start(respond: impl Fn(&str) -> String + Send + Sync + 'static) -> Self {
            let hits = Arc::new(AtomicUsize::new(0));
            let last_request = Arc::new(Mutex::new(String::new()));
            let (hits_in, last_in) = (hits.clone(), last_request.clone());
            let server = spawn_mock_server("catalog backend ready", move |request| {
                hits_in.fetch_add(1, Ordering::SeqCst);
                *last_in.lock().unwrap() = request.to_string();
                respond(request)
            });
            Self {
                server,
                hits,
                last_request,
            }
        }

        fn fetcher(&self) -> Arc<dyn CatalogFetcher> {
            self.fetcher_with(u64::MAX / 2, "http://127.0.0.1:9/oauth/token".to_string())
        }

        /// A fetcher whose stored token expires at `expires` (ms) and whose
        /// OAuth token endpoint is `token_endpoint`.
        fn fetcher_with(&self, expires: u64, token_endpoint: String) -> Arc<dyn CatalogFetcher> {
            let auth_manager =
                CodexAuthManager::new_with_token_endpoint(file_store(), token_endpoint);
            auth_manager.set_test_auth(StoredAuth {
                access: "test-access".to_string(),
                refresh: "test-refresh".to_string(),
                expires,
                account_id: Some("acct-test".to_string()),
            });
            Arc::new(HttpCatalogFetcher::new(
                reqwest::Client::new(),
                models_endpoint(&format!("{}/backend-api/codex/responses", self.server.url)),
                auth_manager,
            ))
        }

        fn hits(&self) -> usize {
            self.hits.load(Ordering::SeqCst)
        }

        fn last_request(&self) -> String {
            self.last_request.lock().unwrap().clone()
        }
    }

    fn with_etag(status_line: &str, etag: &str, body: &str) -> String {
        format!(
            "HTTP/1.1 {status_line}\r\nContent-Length: {}\r\nContent-Type: application/json\r\nETag: {etag}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
    }

    #[test]
    fn cli_cache_fixture_parses_models_and_skips_malformed_entries() {
        let parsed = parse_catalog_file(CLI_CACHE_FIXTURE.as_bytes()).unwrap();
        let slugs: Vec<&str> = parsed.models.iter().map(|m| m.slug.as_str()).collect();
        assert_eq!(
            slugs,
            [
                "gpt-7-test",
                "gpt-7-full-test",
                "gpt-7-hidden-test",
                "gpt-7-tui-only-test"
            ]
        );
        assert_eq!(parsed.models[0].context_window, Some(272000));
        assert_eq!(parsed.models[1].context_window, Some(400000));
        assert!(!parsed.models[2].listed);
        assert_eq!(parsed.client_version.as_deref(), Some("0.150.0"));
        assert!(parse_catalog_file(b"[]").is_none());
        assert!(parse_catalog_file(b"not json").is_none());
    }

    #[test]
    fn static_fallback_when_no_catalog_exists() {
        let fixture = Fixture::new();
        let snapshot = fixture.store(None).snapshot();
        assert_eq!(snapshot.source, CatalogSource::Static);
        assert!(snapshot.accepts("gpt-6-sol"));
        assert!(snapshot.accepts("gpt-6-sol-fast"));
        assert!(snapshot.uses_responses_lite("gpt-6-luna"));
        assert!(!snapshot.uses_responses_lite("gpt-5.4"));
        assert!(!snapshot.accepts("gpt-7-test"));
    }

    #[test]
    fn codex_cli_cache_seeds_the_catalog() {
        let fixture = Fixture::new();
        fixture.write_cli_cache();
        let snapshot = fixture.store(None).snapshot();
        assert_eq!(snapshot.source, CatalogSource::CodexCliCache);
        assert_eq!(snapshot.path.as_deref(), Some(fixture.cli_path().as_path()));
        assert!(snapshot.accepts("gpt-7-test"));
        assert!(snapshot.accepts("gpt-7-hidden-test"));
        assert!(!snapshot.accepts("gpt-7-tui-only-test"));
        assert!(
            !snapshot.accepts("gpt-6-sol"),
            "static list is not merged in"
        );
    }

    #[test]
    fn proxy_catalog_takes_precedence_over_cli_cache() {
        let fixture = Fixture::new();
        fixture.write_cli_cache();
        std::fs::create_dir_all(fixture.proxy_path().parent().unwrap()).unwrap();
        std::fs::write(fixture.proxy_path(), BACKEND_BODY).unwrap();
        let snapshot = fixture.store(None).snapshot();
        assert_eq!(snapshot.source, CatalogSource::Proxy);
        assert!(snapshot.accepts("gpt-8-test"));
        assert!(!snapshot.accepts("gpt-7-hidden-test"));
    }

    #[test]
    fn lane_listing_and_allowlist_follow_the_catalog() {
        let fixture = Fixture::new();
        fixture.write_cli_cache();
        let _guard = set_test_store(fixture.store(None));

        assert!(uses_responses_lite("gpt-7-test"));
        assert!(!uses_responses_lite("gpt-7-full-test"));
        assert!(assert_allowed_model("gpt-7-hidden-test").is_ok());
        assert!(assert_allowed_model("gpt-7-tui-only-test").is_err());

        let fast = resolve_model_request("gpt-7-test-fast");
        assert_eq!(fast.model, "gpt-7-test");
        assert_eq!(fast.service_tier, Some(ServiceTier::Priority));

        let provider = crate::providers::codex::CodexProvider::new();
        let listed = crate::provider::Provider::supported_models(&provider);
        assert_eq!(
            listed,
            [
                "gpt-7-full-test",
                "gpt-7-full-test-fast",
                "gpt-7-test",
                "gpt-7-test-fast"
            ]
        );
        assert!(crate::provider::Provider::accepts_model(
            &provider,
            "gpt-7-hidden-test"
        ));
        assert!(!crate::provider::Provider::accepts_model(
            &provider,
            "gpt-7-tui-only-test"
        ));
    }

    #[tokio::test]
    async fn unknown_model_triggers_one_refresh_then_is_accepted() {
        let fixture = Fixture::new();
        fixture.write_cli_cache();
        let cli_before = std::fs::read(fixture.cli_path()).unwrap();
        let backend = Backend::start(|_| with_etag("200 OK", "W/\"v2\"", BACKEND_BODY));
        let _guard = set_test_store(fixture.store(Some(backend.fetcher())));
        let registry = crate::registry::Registry::new(crate::config::AliasProvider::Codex);

        assert!(registry.provider_for_model("gpt-8-test", None).is_none());
        let provider = registry
            .provider_for_model_or_refresh("gpt-8-test", None)
            .await
            .expect("accepted after refresh");
        assert_eq!(provider.name(), "codex");
        assert_eq!(backend.hits(), 1);

        let request = backend.last_request().to_ascii_lowercase();
        assert!(request.starts_with("get /backend-api/codex/models?client_version=0.150.0 "));
        assert!(request.contains("authorization: bearer test-access"));
        assert!(request.contains("chatgpt-account-id: acct-test"));
        assert!(!request.contains("if-none-match"), "seed etag is not sent");

        // Known now: no further fetch.
        assert!(
            registry
                .provider_for_model_or_refresh("gpt-8-test-fast", None)
                .await
                .is_some()
        );
        // Still unknown, but inside the rate limit: no fetch.
        assert!(
            registry
                .provider_for_model_or_refresh("gpt-9-test", None)
                .await
                .is_none()
        );
        assert_eq!(backend.hits(), 1);

        let written = std::fs::read_to_string(fixture.proxy_path()).unwrap();
        assert!(written.contains("gpt-8-test"));
        assert!(written.contains("W/\\\"v2\\\""));
        assert_eq!(std::fs::read(fixture.cli_path()).unwrap(), cli_before);
        assert_eq!(current().source, CatalogSource::Proxy);
    }

    #[tokio::test]
    async fn concurrent_misses_for_one_model_share_one_fetch() {
        let fixture = Fixture::new();
        let backend = Backend::start(|_| json_response(200, BACKEND_BODY));
        let store = fixture.store(Some(backend.fetcher()));

        let (first, second) = tokio::join!(
            store.refresh_for_unknown_model("gpt-8-test"),
            store.refresh_for_unknown_model("gpt-8-test"),
        );
        assert!(first && second);
        assert_eq!(backend.hits(), 1);
    }

    #[tokio::test]
    async fn not_supported_in_api_stays_rejected_after_refresh() {
        let fixture = Fixture::new();
        let backend = Backend::start(|_| json_response(200, BACKEND_BODY));
        let store = fixture.store(Some(backend.fetcher()));

        assert!(!store.refresh_for_unknown_model("gpt-7-tui-only-test").await);
        assert_eq!(backend.hits(), 1);
        assert!(store.snapshot().model("gpt-7-tui-only-test").is_some());
        assert!(!store.snapshot().accepts("gpt-7-tui-only-test"));
    }

    #[tokio::test]
    async fn refresh_failure_keeps_the_last_catalog() {
        let fixture = Fixture::new();
        fixture.write_cli_cache();
        for body in [
            json_response(500, "{}"),
            json_response(200, r#"{"models": []}"#),
            json_response(200, "not json"),
        ] {
            let backend = Backend::start(move |_| body.clone());
            let store = fixture.store(Some(backend.fetcher()));
            let before = store.snapshot();
            assert!(store.refresh(RefreshTrigger::Manual).await.is_err());
            let after = store.snapshot();
            assert_eq!(after.source, CatalogSource::CodexCliCache);
            assert_eq!(after.models, before.models);
            assert!(!fixture.proxy_path().exists());
        }
    }

    #[tokio::test]
    async fn etag_not_modified_keeps_models_and_updates_fetched_at() {
        let fixture = Fixture::new();
        fixture.write_proxy_catalog("2026-01-01T00:00:00Z", "W/\"v1\"", "0.150.0");
        let backend = Backend::start(|request| {
            if request
                .to_ascii_lowercase()
                .contains("if-none-match: w/\"v1\"")
            {
                "HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            } else {
                json_response(500, "{}")
            }
        });
        let store = fixture.store_with_version(Some(backend.fetcher()), Some("0.150.0"));
        let before = store.snapshot();

        assert_eq!(
            store.refresh(RefreshTrigger::Manual).await,
            Ok(RefreshOutcome::NotModified)
        );
        assert_eq!(backend.hits(), 1);
        let after = store.snapshot();
        assert_eq!(after.models, before.models);
        assert_eq!(after.etag.as_deref(), Some("W/\"v1\""));
        assert_eq!(before.fetched_at.as_deref(), Some("2026-01-01T00:00:00Z"));
        assert_ne!(after.fetched_at, before.fetched_at);

        // The 304 rewrote the file with the new fetched_at.
        let reloaded = fixture.store(None).snapshot();
        assert_eq!(reloaded.source, CatalogSource::Proxy);
        assert_eq!(reloaded.models, before.models);
        assert_eq!(reloaded.etag.as_deref(), Some("W/\"v1\""));
        assert_eq!(reloaded.fetched_at, after.fetched_at);
    }

    #[tokio::test]
    async fn client_version_change_fetches_without_if_none_match() {
        let fixture = Fixture::new();
        fixture.write_proxy_catalog("2026-01-01T00:00:00Z", "W/\"v1\"", "0.150.0");
        let backend = Backend::start(|request| {
            if request.to_ascii_lowercase().contains("if-none-match") {
                "HTTP/1.1 304 Not Modified\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    .to_string()
            } else {
                with_etag(
                    "200 OK",
                    "W/\"v1\"",
                    r#"{"models": [{"slug": "gpt-9-gated-test", "visibility": "list", "supported_in_api": true}]}"#,
                )
            }
        });
        let store = fixture.store_with_version(Some(backend.fetcher()), Some("0.160.0"));

        assert_eq!(
            store.refresh(RefreshTrigger::Manual).await,
            Ok(RefreshOutcome::Updated { models: 1 })
        );
        let request = backend.last_request().to_ascii_lowercase();
        assert!(request.contains("client_version=0.160.0"));
        assert!(!request.contains("if-none-match"));
        let snapshot = store.snapshot();
        assert!(snapshot.accepts("gpt-9-gated-test"));
        assert_eq!(snapshot.client_version.as_deref(), Some("0.160.0"));
    }

    #[tokio::test]
    async fn unauthorized_keeps_catalog_and_never_refreshes_the_login() {
        let fixture = Fixture::new();
        fixture.write_cli_cache();
        let token_endpoint = Backend::start(|_| json_response(500, "{}"));
        let backend = Backend::start(|_| json_response(401, r#"{"error": "unauthorized"}"#));
        let store = fixture.store(Some(backend.fetcher_with(
            u64::MAX / 2,
            format!("{}/oauth/token", token_endpoint.server.url),
        )));
        let before = store.snapshot();

        let error = store.refresh(RefreshTrigger::Manual).await.unwrap_err();
        assert_eq!(error.reason, "unauthorized");
        assert_eq!(backend.hits(), 1, "no retry after 401");
        assert_eq!(token_endpoint.hits(), 0, "no token refresh");
        assert_eq!(store.snapshot().models, before.models);
        assert_eq!(store.snapshot().source, CatalogSource::CodexCliCache);
    }

    #[tokio::test]
    async fn expired_token_skips_the_fetch_and_never_refreshes_the_login() {
        let fixture = Fixture::new();
        fixture.write_cli_cache();
        let token_endpoint = Backend::start(|_| json_response(500, "{}"));
        let backend = Backend::start(|_| json_response(200, BACKEND_BODY));
        let store = fixture.store(Some(
            backend.fetcher_with(1, format!("{}/oauth/token", token_endpoint.server.url)),
        ));

        let error = store.refresh(RefreshTrigger::Manual).await.unwrap_err();
        assert_eq!(error.reason, "auth_unavailable");
        assert!(!store.refresh_for_unknown_model("gpt-8-test").await);
        assert_eq!(backend.hits(), 0);
        assert_eq!(token_endpoint.hits(), 0);
        assert_eq!(store.snapshot().source, CatalogSource::CodexCliCache);
    }

    #[tokio::test]
    async fn identity_from_seed_or_response_is_not_written() {
        let fixture = Fixture::new();
        fixture.write_cli_cache();
        let body = r#"{"identity": "private-identity-from-backend", "models": [
            {"slug": "gpt-8-test", "visibility": "list", "supported_in_api": true}
        ]}"#;
        let backend = Backend::start(move |_| json_response(200, body));
        let store = fixture.store(Some(backend.fetcher()));
        assert_eq!(store.snapshot().source, CatalogSource::CodexCliCache);

        store.refresh(RefreshTrigger::Manual).await.unwrap();
        let written = std::fs::read_to_string(fixture.proxy_path()).unwrap();
        assert!(written.contains("gpt-8-test"));
        assert!(!written.contains("identity"));
        assert!(!written.contains("private-identity"));
    }

    #[test]
    fn missing_hardcoded_targets_names_absent_alias_and_upgrade_targets() {
        assert!(missing_hardcoded_targets(&CatalogSnapshot::static_fallback()).is_empty());
        let fixture = Fixture::new();
        fixture.write_cli_cache();
        assert_eq!(
            missing_hardcoded_targets(&fixture.store(None).snapshot()),
            ["gpt-5.6-sol", "gpt-5.6-terra", "gpt-6-luna", "gpt-6-sol"]
        );
    }

    #[test]
    fn models_endpoint_replaces_the_responses_path() {
        assert_eq!(
            models_endpoint("https://chatgpt.com/backend-api/codex/responses"),
            "https://chatgpt.com/backend-api/codex/models"
        );
        assert_eq!(
            models_endpoint("http://127.0.0.1:9/codex/"),
            "http://127.0.0.1:9/codex/models"
        );
    }

    #[test]
    fn describe_shows_source_fetch_time_and_lane() {
        let fixture = Fixture::new();
        fixture.write_cli_cache();
        let text = describe(&fixture.store(None).snapshot());
        assert!(text.contains("source: codex cli cache (read-only seed)"));
        assert!(text.contains("fetched_at: 2026-09-01T00:00:00Z"));
        let line = text
            .lines()
            .find(|line| line.starts_with("gpt-7-full-test "))
            .unwrap();
        assert!(line.contains("full"));
        assert!(!text.contains("private-identity"));
    }
}

//! The Codex CLI's `auth.json` (`$CODEX_HOME/auth.json`) as a Codex
//! credential store, so ccp and the Codex CLI share one ChatGPT login.
//!
//! The Codex CLI owns the file: ccp never writes a login into it or deletes
//! it. The one write is a token refresh, which updates the token fields and
//! `last_refresh` in place and keeps every other key.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use super::jwt::{account_id_from_jwt, jwt_expiry_ms};
use super::token_store::{CodexAuthStorage, StoredAuth};
use crate::auth::{AuthStorage, replace_file_atomically};
use crate::logging::create_logger;

type FileWriter = fn(&Path, &[u8]) -> anyhow::Result<()>;

pub struct CodexCliAuthStore {
    path: PathBuf,
    replace_atomically: FileWriter,
    overwrite_in_place: FileWriter,
}

impl CodexCliAuthStore {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            replace_atomically: replace_file_atomically,
            overwrite_in_place: overwrite_file_in_place,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_writers(
        path: PathBuf,
        replace_atomically: FileWriter,
        overwrite_in_place: FileWriter,
    ) -> Self {
        Self {
            path,
            replace_atomically,
            overwrite_in_place,
        }
    }

    /// Persist refreshed tokens. By now the token endpoint has rotated the
    /// refresh token, and the file's old one may stop working for both ccp
    /// and the Codex CLI, so an atomic replace that fails (a rename onto a
    /// single-file bind mount returns EBUSY) falls back to overwriting in
    /// place, which is how the Codex CLI itself writes the file.
    fn write_back(&self, target: &Path, contents: &[u8]) -> anyhow::Result<&'static str> {
        let atomic_err = match (self.replace_atomically)(target, contents) {
            Ok(()) => return Ok("atomic_replace"),
            Err(err) => err,
        };
        match (self.overwrite_in_place)(target, contents) {
            Ok(()) => Ok("in_place_after_atomic_replace_failed"),
            Err(in_place_err) => Err(anyhow::anyhow!(
                "refreshed Codex tokens could not be saved to {} (atomic replace: {atomic_err}; \
                 in-place write: {in_place_err}); the refresh token in that file may stop \
                 working for ccp and the Codex CLI, and a `codex login` may be needed",
                self.path.display()
            )),
        }
    }

    fn read_value(&self) -> anyhow::Result<Value> {
        let raw = fs::read_to_string(&self.path).map_err(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                anyhow::anyhow!(
                    "Codex CLI auth file {} not found; ccp needs the Codex CLI to keep its \
                     login in this file rather than the OS keyring. Sign in with `codex login`",
                    self.path.display()
                )
            } else {
                anyhow::anyhow!(
                    "failed to read Codex CLI auth file {}: {err}",
                    self.path.display()
                )
            }
        })?;
        serde_json::from_str(&raw).map_err(|err| {
            anyhow::anyhow!(
                "failed to parse Codex CLI auth file {}: {err}",
                self.path.display()
            )
        })
    }

    fn refuse(&self, action: &str) -> anyhow::Error {
        anyhow::anyhow!(
            "ccp does not {action} the Codex CLI's login in {}; use `codex login` / `codex logout`, \
             or unset codex.authFile / CCP_CODEX_AUTH_FILE to use ccp's own login",
            self.path.display()
        )
    }
}

/// Map a Codex CLI `auth.json` document to ccp's token shape.
pub(crate) fn stored_auth_from_codex_cli(value: &Value, path: &Path) -> anyhow::Result<StoredAuth> {
    let Some(tokens) = value.get("tokens").filter(|tokens| !tokens.is_null()) else {
        if value
            .get("OPENAI_API_KEY")
            .and_then(Value::as_str)
            .is_some_and(|key| !key.is_empty())
        {
            anyhow::bail!(
                "Codex CLI auth file {} holds an API key (OPENAI_API_KEY) but no ChatGPT login; \
                 ccp needs a ChatGPT login: run `codex login`",
                path.display()
            );
        }
        anyhow::bail!(
            "Codex CLI auth file {} has no ChatGPT tokens; run `codex login`",
            path.display()
        );
    };
    let field = |name: &str| {
        tokens
            .get(name)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
    };
    let missing = |name: &str| {
        anyhow::anyhow!(
            "Codex CLI auth file {} has no tokens.{name}; run `codex login`",
            path.display()
        )
    };
    let access = field("access_token").ok_or_else(|| missing("access_token"))?;
    let refresh = field("refresh_token").ok_or_else(|| missing("refresh_token"))?;
    let account_id = field("account_id")
        .map(str::to_string)
        .or_else(|| field("id_token").and_then(account_id_from_jwt))
        .or_else(|| account_id_from_jwt(access));
    Ok(StoredAuth {
        access: access.to_string(),
        refresh: refresh.to_string(),
        // No `exp` claim: refresh only when the backend rejects the token.
        expires: jwt_expiry_ms(access).unwrap_or(u64::MAX),
        account_id,
    })
}

/// Write refreshed tokens into a Codex CLI `auth.json` document, leaving
/// every other key as it was.
pub(crate) fn apply_refreshed_tokens(
    value: &mut Value,
    next: &StoredAuth,
    id_token: Option<&str>,
    last_refresh: &str,
) -> anyhow::Result<()> {
    let doc = value
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Codex CLI auth file is not a JSON object"))?;
    let tokens = doc
        .entry("tokens")
        .or_insert_with(|| Value::Object(Map::new()));
    if tokens.is_null() {
        *tokens = Value::Object(Map::new());
    }
    let tokens = tokens
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("Codex CLI auth file `tokens` is not a JSON object"))?;
    tokens.insert("access_token".to_string(), json!(next.access));
    tokens.insert("refresh_token".to_string(), json!(next.refresh));
    if let Some(id_token) = id_token {
        tokens.insert("id_token".to_string(), json!(id_token));
    }
    doc.insert("last_refresh".to_string(), json!(last_refresh));
    Ok(())
}

fn overwrite_file_in_place(path: &Path, contents: &[u8]) -> anyhow::Result<()> {
    overwrite_in_place_with(path, contents, |file, bytes| {
        use std::io::Write;
        file.write_all(bytes)
    })
}

/// Overwrite `path` without truncating first: write `contents` from the start,
/// fsync, then cut the file to length. If any step fails, write the original
/// bytes back, so the file holds either the old or the new document, never a
/// truncated or mixed one (unless that restore fails too, which is reported).
fn overwrite_in_place_with(
    path: &Path,
    contents: &[u8],
    write: impl Fn(&mut fs::File, &[u8]) -> io::Result<()>,
) -> anyhow::Result<()> {
    use std::io::{Read, Seek, SeekFrom};
    let mut file = fs::OpenOptions::new().read(true).write(true).open(path)?;
    let mut original = Vec::new();
    file.read_to_end(&mut original)?;

    let attempt = |file: &mut fs::File, bytes: &[u8]| -> io::Result<()> {
        file.seek(SeekFrom::Start(0))?;
        write(file, bytes)?;
        file.sync_all()?;
        file.set_len(bytes.len() as u64)?;
        file.sync_all()
    };
    let Err(write_err) = attempt(&mut file, contents) else {
        return Ok(());
    };
    let restored = (|| -> io::Result<()> {
        use std::io::Write;
        file.seek(SeekFrom::Start(0))?;
        file.write_all(&original)?;
        file.set_len(original.len() as u64)?;
        file.sync_all()
    })();
    match restored {
        Ok(()) => Err(write_err.into()),
        Err(restore_err) => Err(anyhow::anyhow!(
            "{write_err}; restoring the previous contents also failed: {restore_err}"
        )),
    }
}

fn now_rfc3339() -> anyhow::Result<String> {
    Ok(time::OffsetDateTime::now_utc().format(&time::format_description::well_known::Rfc3339)?)
}

impl AuthStorage<StoredAuth> for CodexCliAuthStore {
    fn load(&self) -> anyhow::Result<Option<StoredAuth>> {
        let value = self.read_value()?;
        stored_auth_from_codex_cli(&value, &self.path).map(Some)
    }

    fn save(&self, _value: StoredAuth) -> anyhow::Result<()> {
        Err(self.refuse("write a new login into"))
    }

    fn clear(&self) -> anyhow::Result<()> {
        Err(self.refuse("delete"))
    }

    fn path(&self) -> String {
        self.path.display().to_string()
    }
}

impl CodexAuthStorage for CodexCliAuthStore {
    fn refresh_lock_path(&self) -> Option<PathBuf> {
        let mut lock = self.path.clone().into_os_string();
        lock.push(".ccp-lock");
        Some(PathBuf::from(lock))
    }

    fn save_refreshed(
        &self,
        previous: &StoredAuth,
        next: StoredAuth,
        id_token: Option<&str>,
    ) -> anyhow::Result<StoredAuth> {
        let log = create_logger("codex");
        let path = self.path.display().to_string();
        // The Codex CLI does not take our lock, so re-read: if it rotated the
        // tokens while our refresh was in flight, keep its tokens.
        let skip_write_back = |reason: String| {
            log.warn(
                "codex_auth_write_back_skipped",
                Some(Map::from_iter([
                    ("path".to_string(), json!(path)),
                    ("reason".to_string(), json!(reason)),
                ])),
            );
        };
        let mut value = match self.read_value() {
            Ok(value) => value,
            Err(err) => {
                skip_write_back(err.to_string());
                return Ok(next);
            }
        };
        match stored_auth_from_codex_cli(&value, &self.path) {
            Ok(on_disk)
                if on_disk.access != previous.access || on_disk.refresh != previous.refresh =>
            {
                log.info(
                    "codex_auth_adopted",
                    Some(Map::from_iter([
                        ("path".to_string(), json!(path)),
                        ("reason".to_string(), json!("file_changed_during_refresh")),
                    ])),
                );
                return Ok(on_disk);
            }
            Ok(_) => {}
            Err(err) => {
                skip_write_back(err.to_string());
                return Ok(next);
            }
        }
        apply_refreshed_tokens(&mut value, &next, id_token, &now_rfc3339()?)?;
        // Replace the target of a symlinked auth.json, not the link.
        let target = fs::canonicalize(&self.path).unwrap_or_else(|_| self.path.clone());
        let method = self.write_back(&target, serde_json::to_string_pretty(&value)?.as_bytes())?;
        log.info(
            "codex_auth_written_back",
            Some(Map::from_iter([
                ("path".to_string(), json!(path)),
                ("method".to_string(), json!(method)),
            ])),
        );
        Ok(next)
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use base64::Engine;
    use serde_json::Value;
    use std::path::Path;

    pub(crate) fn fail_atomic_replace(_: &Path, _: &[u8]) -> anyhow::Result<()> {
        Err(std::io::Error::new(
            std::io::ErrorKind::ResourceBusy,
            "simulated rename onto a single-file bind mount",
        )
        .into())
    }

    pub(crate) fn fail_in_place_write(_: &Path, _: &[u8]) -> anyhow::Result<()> {
        Err(std::io::Error::new(std::io::ErrorKind::StorageFull, "simulated full disk").into())
    }

    /// An unsigned JWT carrying `claims`; ccp only decodes the payload.
    pub(crate) fn jwt(claims: Value) -> String {
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        format!("e30.{payload}.sig")
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::jwt;
    use super::*;

    fn write(dir: &tempfile::TempDir, value: &Value) -> PathBuf {
        let path = dir.path().join("auth.json");
        fs::write(&path, serde_json::to_string_pretty(value).unwrap()).unwrap();
        path
    }

    fn read(path: &Path) -> Value {
        serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap()
    }

    fn cli_file(access: &str, refresh: &str) -> Value {
        json!({
            "auth_mode": "chatgpt",
            "OPENAI_API_KEY": null,
            "tokens": {
                "id_token": jwt(json!({"chatgpt_account_id": "acct_from_id"})),
                "access_token": access,
                "refresh_token": refresh,
                "account_id": "acct_1",
                "future_token_field": {"kept": true}
            },
            "last_refresh": "2026-01-01T00:00:00Z",
            "agent_identity": "kept-unknown-to-ccp"
        })
    }

    #[test]
    fn load_maps_codex_cli_schema() {
        let dir = tempfile::TempDir::new().unwrap();
        let access = jwt(json!({"exp": 4_102_444_800u64}));
        let path = write(&dir, &cli_file(&access, "refresh-1"));
        let auth = CodexCliAuthStore::new(path).load().unwrap().unwrap();
        assert_eq!(
            auth,
            StoredAuth {
                access,
                refresh: "refresh-1".into(),
                expires: 4_102_444_800_000,
                account_id: Some("acct_1".into()),
            }
        );
    }

    #[test]
    fn load_takes_account_id_from_id_token_when_file_has_none() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut value = cli_file("access", "refresh");
        value["tokens"]["account_id"] = Value::Null;
        let path = write(&dir, &value);
        let auth = CodexCliAuthStore::new(path).load().unwrap().unwrap();
        assert_eq!(auth.account_id.as_deref(), Some("acct_from_id"));

        value["tokens"]
            .as_object_mut()
            .unwrap()
            .remove("account_id");
        let path = write(&dir, &value);
        let auth = CodexCliAuthStore::new(path).load().unwrap().unwrap();
        assert_eq!(auth.account_id.as_deref(), Some("acct_from_id"));
    }

    #[test]
    fn load_without_exp_claim_never_expires_proactively() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = write(&dir, &cli_file("opaque-access", "refresh"));
        let auth = CodexCliAuthStore::new(path).load().unwrap().unwrap();
        assert_eq!(auth.expires, u64::MAX);
    }

    #[test]
    fn load_rejects_api_key_only_file_naming_it() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = write(&dir, &json!({"OPENAI_API_KEY": "sk-test"}));
        let err = CodexCliAuthStore::new(path.clone())
            .load()
            .unwrap_err()
            .to_string();
        assert!(err.contains(&path.display().to_string()), "{err}");
        assert!(err.contains("OPENAI_API_KEY"), "{err}");
        assert!(!err.contains("sk-test"), "{err}");
    }

    #[test]
    fn load_reports_missing_file_by_name() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("auth.json");
        let err = CodexCliAuthStore::new(path.clone())
            .load()
            .unwrap_err()
            .to_string();
        assert!(err.contains(&path.display().to_string()), "{err}");
        assert!(err.contains("codex login"), "{err}");
    }

    #[test]
    fn save_and_clear_refuse_and_leave_file_alone() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = write(&dir, &cli_file("access", "refresh"));
        let before = fs::read(&path).unwrap();
        let store = CodexCliAuthStore::new(path.clone());
        let auth = store.load().unwrap().unwrap();
        assert!(store.save(auth).is_err());
        assert!(store.clear().is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn apply_refreshed_tokens_updates_tokens_and_keeps_other_fields() {
        let mut value = cli_file("old-access", "old-refresh");
        value["OPENAI_API_KEY"] = json!("sk-kept");
        let next = StoredAuth {
            access: "new-access".into(),
            refresh: "new-refresh".into(),
            expires: 1,
            account_id: Some("ignored".into()),
        };
        apply_refreshed_tokens(&mut value, &next, Some("new-id"), "2026-09-26T00:00:00Z").unwrap();

        let mut expected = cli_file("new-access", "new-refresh");
        expected["OPENAI_API_KEY"] = json!("sk-kept");
        expected["tokens"]["id_token"] = json!("new-id");
        expected["last_refresh"] = json!("2026-09-26T00:00:00Z");
        assert_eq!(value, expected);
    }

    #[test]
    fn apply_refreshed_tokens_without_id_token_keeps_the_old_one() {
        let mut value = cli_file("old-access", "old-refresh");
        let old_id = value["tokens"]["id_token"].clone();
        let next = StoredAuth {
            access: "new-access".into(),
            refresh: "new-refresh".into(),
            expires: 1,
            account_id: None,
        };
        apply_refreshed_tokens(&mut value, &next, None, "2026-09-26T00:00:00Z").unwrap();
        assert_eq!(value["tokens"]["id_token"], old_id);
        assert_eq!(value["tokens"]["account_id"], "acct_1");
    }

    #[test]
    fn save_refreshed_writes_back_when_file_unchanged() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = write(&dir, &cli_file("old-access", "old-refresh"));
        let store = CodexCliAuthStore::new(path.clone());
        let previous = store.load().unwrap().unwrap();
        let next = StoredAuth {
            access: "new-access".into(),
            refresh: "new-refresh".into(),
            expires: 42,
            account_id: previous.account_id.clone(),
        };

        let stored = store
            .save_refreshed(&previous, next.clone(), Some("new-id"))
            .unwrap();
        assert_eq!(stored, next);

        let on_disk = read(&path);
        assert_eq!(on_disk["tokens"]["access_token"], "new-access");
        assert_eq!(on_disk["tokens"]["refresh_token"], "new-refresh");
        assert_eq!(on_disk["tokens"]["id_token"], "new-id");
        assert_eq!(
            on_disk["tokens"]["future_token_field"],
            json!({"kept": true})
        );
        assert_eq!(on_disk["agent_identity"], "kept-unknown-to-ccp");
        assert_eq!(on_disk["auth_mode"], "chatgpt");
        assert!(on_disk["OPENAI_API_KEY"].is_null());
        let last_refresh = on_disk["last_refresh"].as_str().unwrap();
        assert_ne!(last_refresh, "2026-01-01T00:00:00Z");
        time::OffsetDateTime::parse(last_refresh, &time::format_description::well_known::Rfc3339)
            .unwrap();
        let leftovers: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name != "auth.json")
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn save_refreshed_adopts_tokens_changed_underneath() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = write(&dir, &cli_file("old-access", "old-refresh"));
        let store = CodexCliAuthStore::new(path.clone());
        let previous = store.load().unwrap().unwrap();
        // The Codex CLI refreshes while ccp's refresh is in flight.
        write(&dir, &cli_file("cli-access", "cli-refresh"));
        let before = fs::read(&path).unwrap();

        let stored = store
            .save_refreshed(
                &previous,
                StoredAuth {
                    access: "ccp-access".into(),
                    refresh: "ccp-refresh".into(),
                    expires: 42,
                    account_id: None,
                },
                Some("ccp-id"),
            )
            .unwrap();
        assert_eq!(stored.access, "cli-access");
        assert_eq!(stored.refresh, "cli-refresh");
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[cfg(unix)]
    #[test]
    fn save_refreshed_replaces_symlink_target() {
        let dir = tempfile::TempDir::new().unwrap();
        let target = write(&dir, &cli_file("old-access", "old-refresh"));
        let link = dir.path().join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let store = CodexCliAuthStore::new(link.clone());
        let previous = store.load().unwrap().unwrap();
        store
            .save_refreshed(
                &previous,
                StoredAuth {
                    access: "new-access".into(),
                    refresh: "new-refresh".into(),
                    expires: 42,
                    account_id: None,
                },
                None,
            )
            .unwrap();
        assert!(
            fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(read(&target)["tokens"]["access_token"], "new-access");
    }

    fn refreshed() -> StoredAuth {
        StoredAuth {
            access: "new-access".into(),
            refresh: "new-refresh".into(),
            expires: 42,
            account_id: Some("acct_1".into()),
        }
    }

    #[test]
    fn save_refreshed_falls_back_to_in_place_write_when_atomic_replace_fails() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = write(&dir, &cli_file("old-access", "old-refresh"));
        let store = CodexCliAuthStore::with_writers(
            path.clone(),
            test_support::fail_atomic_replace,
            overwrite_file_in_place,
        );
        let previous = store.load().unwrap().unwrap();

        let stored = store
            .save_refreshed(&previous, refreshed(), Some("new-id"))
            .unwrap();
        assert_eq!(stored, refreshed());
        let on_disk = read(&path);
        assert_eq!(on_disk["tokens"]["access_token"], "new-access");
        assert_eq!(on_disk["tokens"]["refresh_token"], "new-refresh");
        assert_eq!(on_disk["tokens"]["id_token"], "new-id");
        assert_eq!(on_disk["agent_identity"], "kept-unknown-to-ccp");
        assert_eq!(
            on_disk["tokens"]["future_token_field"],
            json!({"kept": true})
        );
    }

    #[test]
    fn save_refreshed_reports_unsaved_tokens_when_both_writes_fail() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = write(&dir, &cli_file("old-access", "old-refresh"));
        let before = fs::read(&path).unwrap();
        let store = CodexCliAuthStore::with_writers(
            path.clone(),
            test_support::fail_atomic_replace,
            test_support::fail_in_place_write,
        );
        let previous = store.load().unwrap().unwrap();

        let err = store
            .save_refreshed(&previous, refreshed(), None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("could not be saved"), "{err}");
        assert!(err.contains(&path.display().to_string()), "{err}");
        assert!(
            err.contains("simulated rename onto a single-file bind mount"),
            "{err}"
        );
        assert!(err.contains("simulated full disk"), "{err}");
        assert!(err.contains("codex login"), "{err}");
        assert!(!err.contains("new-refresh"), "{err}");
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    #[test]
    fn save_refreshed_skips_write_back_when_file_is_mid_write() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = write(&dir, &cli_file("old-access", "old-refresh"));
        let store = CodexCliAuthStore::new(path.clone());
        let previous = store.load().unwrap().unwrap();
        // The Codex CLI truncates and rewrites in place; a read can land
        // between the truncate and the write.
        fs::write(&path, "{\"tokens\": {").unwrap();

        let stored = store
            .save_refreshed(&previous, refreshed(), Some("new-id"))
            .unwrap();
        assert_eq!(stored, refreshed());
        assert_eq!(fs::read_to_string(&path).unwrap(), "{\"tokens\": {");
    }

    #[test]
    fn save_refreshed_skips_write_back_when_tokens_are_gone() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = write(&dir, &cli_file("old-access", "old-refresh"));
        let store = CodexCliAuthStore::new(path.clone());
        let previous = store.load().unwrap().unwrap();
        // Switched to API-key auth while the refresh was in flight.
        write(&dir, &json!({"OPENAI_API_KEY": "sk-test"}));
        let before = fs::read(&path).unwrap();

        let stored = store.save_refreshed(&previous, refreshed(), None).unwrap();
        assert_eq!(stored, refreshed());
        assert_eq!(fs::read(&path).unwrap(), before);
    }

    /// Writes the first half of the bytes, then fails like a full disk.
    fn write_half_then_fail(file: &mut fs::File, bytes: &[u8]) -> io::Result<()> {
        use std::io::Write;
        file.write_all(&bytes[..bytes.len() / 2])?;
        Err(io::Error::new(
            io::ErrorKind::StorageFull,
            "simulated full disk mid-write",
        ))
    }

    #[test]
    fn in_place_write_failure_leaves_original_bytes() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = write(&dir, &cli_file("old-access", "old-refresh"));
        let original = fs::read(&path).unwrap();
        for new_len in [original.len() / 3, original.len() * 3] {
            let replacement = vec![b'x'; new_len];
            let err = overwrite_in_place_with(&path, &replacement, write_half_then_fail)
                .unwrap_err()
                .to_string();
            assert!(err.contains("simulated full disk mid-write"), "{err}");
            assert_eq!(fs::read(&path).unwrap(), original, "new_len {new_len}");
        }
    }

    #[test]
    fn in_place_write_replaces_longer_and_shorter_documents() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("auth.json");
        fs::write(&path, "0123456789").unwrap();
        overwrite_file_in_place(&path, b"abc").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"abc");
        overwrite_file_in_place(&path, b"a much longer document").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"a much longer document");
    }
}

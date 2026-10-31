//! `cargo test` must not write into the developer's real state directory:
//! `.cargo/config.toml` sets `CCP_STATE_DIR` for every process cargo starts,
//! and the proxy's state must resolve under it.

use assert_cmd::Command;
use claude_code_proxy::paths;
use std::collections::HashMap;
use std::path::PathBuf;
use tempfile::TempDir;

#[test]
fn test_processes_resolve_state_under_ccp_state_dir() {
    let state_dir = PathBuf::from(
        std::env::var_os("CCP_STATE_DIR")
            .expect("CCP_STATE_DIR should be set for test processes (see .cargo/config.toml)"),
    );
    assert_eq!(paths::state_dir(), state_dir);
    assert_eq!(paths::log_file(), state_dir.join("proxy.log"));

    let mut env_without_override: HashMap<String, String> = std::env::vars().collect();
    env_without_override.remove("CCP_STATE_DIR");
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .unwrap_or_else(|_| "/".to_string());
    assert_ne!(
        state_dir,
        paths::resolve_state_dir_for_env(std::env::consts::OS, &home, &env_without_override),
        "CCP_STATE_DIR points at the default state dir, so tests would write to the real proxy.log"
    );
}

#[test]
fn binary_logs_under_ccp_state_dir_not_xdg_state_home() {
    let temp = TempDir::new().unwrap();
    let ccp_state = temp.path().join("ccp-state");
    let xdg_state = temp.path().join("xdg-state");
    std::fs::create_dir_all(&xdg_state).unwrap();

    Command::cargo_bin("claude-code-proxy")
        .unwrap()
        .args(["codex", "auth", "status"])
        .env("HOME", temp.path().join("home"))
        .env("CCP_CONFIG_DIR", temp.path().join("config"))
        .env("CODEX_HOME", temp.path().join("codex-home"))
        .env_remove("CCP_CODEX_AUTH_FILE")
        .env("CCP_STATE_DIR", &ccp_state)
        .env("XDG_STATE_HOME", &xdg_state)
        .output()
        .unwrap();

    assert!(ccp_state.join("proxy.log").is_file());
    assert_eq!(std::fs::read_dir(&xdg_state).unwrap().count(), 0);
}

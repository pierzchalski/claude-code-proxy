//! `cargo test` must not write into the developer's real state directory:
//! `.cargo/config.toml` sets `CCP_STATE_DIR` for every process cargo starts,
//! and the proxy's log file must resolve under it.

use claude_code_proxy::paths;
use std::path::PathBuf;

#[test]
fn test_processes_resolve_state_under_ccp_state_dir() {
    let state_dir = PathBuf::from(
        std::env::var_os("CCP_STATE_DIR")
            .expect("CCP_STATE_DIR should be set for test processes (see .cargo/config.toml)"),
    );
    assert_eq!(paths::state_dir(), state_dir);
    assert_eq!(paths::log_file(), state_dir.join("proxy.log"));
}

use assert_cmd::Command;
use tempfile::TempDir;

/// Run a codex auth command with a temp config dir that isolates
/// from the real user config. Overrides HOME so the legacy config
/// fallback also resolves within the temp dir.
fn codex_cmd() -> (Command, TempDir) {
    let temp = TempDir::new().unwrap();
    let mut cmd = Command::cargo_bin("claude-code-proxy").unwrap();
    cmd.args(["codex", "auth", "status"]);
    cmd.env("CCP_CONFIG_DIR", temp.path());
    cmd.env("HOME", temp.path());
    (cmd, temp)
}

#[test]
fn codex_auth_status_reads_stored_auth() -> Result<(), Box<dyn std::error::Error>> {
    let (mut cmd, temp) = codex_cmd();
    let auth_dir = temp.path().join("codex");
    std::fs::create_dir_all(&auth_dir)?;
    std::fs::write(
        auth_dir.join("auth.json"),
        r#"{"access":"a","refresh":"r","expires":4102444800000,"accountId":"acct_1"}"#,
    )?;
    let output = cmd.assert().success().get_output().stdout.clone();
    let out = String::from_utf8(output)?;
    let lines: Vec<_> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{out}");
    assert_eq!(lines[0], "Account: acct_1");
    assert!(
        lines[1].starts_with("Expires: 2100-01-01T00:00:00.000Z (in "),
        "{out}"
    );
    assert!(lines[1].ends_with("s)"), "{out}");
    assert!(lines[2].starts_with("Storage: "), "{out}");
    assert!(!out.contains("Auth path:"));
    assert!(!out.contains("Authenticated: true"));
    Ok(())
}

#[test]
fn codex_auth_status_reads_legacy_account_id_key() -> Result<(), Box<dyn std::error::Error>> {
    let (mut cmd, temp) = codex_cmd();
    let auth_dir = temp.path().join("codex");
    std::fs::create_dir_all(&auth_dir)?;
    std::fs::write(
        auth_dir.join("auth.json"),
        r#"{"access":"a","refresh":"r","expires":4102444800000,"account_id":"acct_2"}"#,
    )?;
    let output = cmd.assert().success().get_output().stdout.clone();
    let out = String::from_utf8(output)?;
    let lines: Vec<_> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{out}");
    assert_eq!(lines[0], "Account: acct_2");
    Ok(())
}

#[test]
fn codex_auth_status_no_auth() -> Result<(), Box<dyn std::error::Error>> {
    let (mut cmd, _temp) = codex_cmd();
    let output = cmd.output()?;
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(String::from_utf8(output.stdout)?, "Not authenticated\n");
    Ok(())
}

#[test]
fn codex_auth_status_shows_storage_path() -> Result<(), Box<dyn std::error::Error>> {
    let (mut cmd, temp) = codex_cmd();
    let auth_dir = temp.path().join("codex");
    std::fs::create_dir_all(&auth_dir)?;
    std::fs::write(
        auth_dir.join("auth.json"),
        r#"{"access":"a","refresh":"r","expires":4102444800000,"accountId":"acct_3"}"#,
    )?;
    let output = cmd.assert().success().get_output().stdout.clone();
    let out = String::from_utf8(output)?;
    assert!(out.contains("Storage:"), "{out}");
    assert!(!out.contains("Auth path:"), "{out}");
    Ok(())
}

#[test]
fn codex_auth_status_no_account_id_shows_none() -> Result<(), Box<dyn std::error::Error>> {
    let (mut cmd, temp) = codex_cmd();
    let auth_dir = temp.path().join("codex");
    std::fs::create_dir_all(&auth_dir)?;
    std::fs::write(
        auth_dir.join("auth.json"),
        r#"{"access":"a","refresh":"r","expires":4102444800000}"#,
    )?;
    let output = cmd.output()?;
    let out = String::from_utf8(output.stdout)?;
    assert!(output.status.success());
    assert!(out.contains("Account: (none)"), "{out}");
    assert!(!out.contains("Auth path:"), "{out}");
    assert!(!out.contains("Authenticated: true"), "{out}");
    Ok(())
}

#[test]
fn codex_auth_status_expired_auth_shows_negative_seconds() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut cmd, temp) = codex_cmd();
    let auth_dir = temp.path().join("codex");
    std::fs::create_dir_all(&auth_dir)?;
    std::fs::write(
        auth_dir.join("auth.json"),
        r#"{"access":"a","refresh":"r","expires":946684800000,"accountId":"acct_1"}"#,
    )?;
    let output = cmd.assert().success().get_output().stdout.clone();
    let out = String::from_utf8(output)?;
    let lines: Vec<_> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{out}");
    assert!(lines[0].starts_with("Account:"));
    assert!(
        lines[1].starts_with("Expires: 2000-01-01T00:00:00.000Z (in -"),
        "{out}"
    );
    assert!(lines[2].starts_with("Storage: "), "{out}");
    Ok(())
}

/// A Codex CLI `auth.json` under `$CODEX_HOME`, selected with
/// `CCP_CODEX_AUTH_FILE=codex-cli`. The access token is an unsigned JWT
/// whose `exp` is 2100-01-01T00:00:00Z.
fn codex_cli_cmd(args: &[&str], auth_json: &str) -> (Command, TempDir, std::path::PathBuf) {
    let temp = TempDir::new().unwrap();
    let codex_home = temp.path().join("codex-home");
    std::fs::create_dir_all(&codex_home).unwrap();
    let auth_file = codex_home.join("auth.json");
    std::fs::write(&auth_file, auth_json).unwrap();
    let mut cmd = Command::cargo_bin("claude-code-proxy").unwrap();
    cmd.args(args);
    cmd.env("CCP_CONFIG_DIR", temp.path().join("ccp-config"));
    cmd.env("HOME", temp.path());
    cmd.env("CODEX_HOME", &codex_home);
    cmd.env("CCP_CODEX_AUTH_FILE", "codex-cli");
    (cmd, temp, auth_file)
}

const CODEX_CLI_AUTH_JSON: &str = r#"{
  "OPENAI_API_KEY": null,
  "tokens": {
    "id_token": "e30.e30.sig",
    "access_token": "e30.eyJleHAiOjQxMDI0NDQ4MDB9.sig",
    "refresh_token": "r",
    "account_id": "acct_cli"
  },
  "last_refresh": "2026-01-01T00:00:00Z"
}"#;

#[test]
fn codex_auth_status_reads_codex_cli_file() -> Result<(), Box<dyn std::error::Error>> {
    let (mut cmd, _temp, auth_file) =
        codex_cli_cmd(&["codex", "auth", "status"], CODEX_CLI_AUTH_JSON);
    let output = cmd.assert().success().get_output().stdout.clone();
    let out = String::from_utf8(output)?;
    let lines: Vec<_> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{out}");
    assert_eq!(lines[0], "Account: acct_cli");
    assert!(
        lines[1].starts_with("Expires: 2100-01-01T00:00:00.000Z (in "),
        "{out}"
    );
    assert_eq!(
        lines[2],
        format!(
            "Storage: {} (Codex CLI login, via codex.authFile / CCP_CODEX_AUTH_FILE)",
            auth_file.display()
        )
    );
    Ok(())
}

#[test]
fn codex_auth_status_rejects_api_key_only_codex_cli_file() -> Result<(), Box<dyn std::error::Error>>
{
    let (mut cmd, _temp, auth_file) = codex_cli_cmd(
        &["codex", "auth", "status"],
        r#"{"OPENAI_API_KEY":"sk-test"}"#,
    );
    let output = cmd.output()?;
    assert!(!output.status.success());
    let text = format!(
        "{}{}",
        String::from_utf8(output.stdout)?,
        String::from_utf8(output.stderr)?
    );
    assert!(text.contains(&auth_file.display().to_string()), "{text}");
    assert!(text.contains("OPENAI_API_KEY"), "{text}");
    assert!(!text.contains("sk-test"), "{text}");
    Ok(())
}

#[test]
fn codex_auth_login_logout_refuse_to_touch_codex_cli_file() -> Result<(), Box<dyn std::error::Error>>
{
    for command in ["login", "device", "logout"] {
        let (mut cmd, _temp, auth_file) =
            codex_cli_cmd(&["codex", "auth", command], CODEX_CLI_AUTH_JSON);
        let output = cmd.timeout(std::time::Duration::from_secs(20)).output()?;
        assert!(!output.status.success(), "{command} succeeded");
        let text = format!(
            "{}{}",
            String::from_utf8(output.stdout)?,
            String::from_utf8(output.stderr)?
        );
        assert!(
            text.contains(&auth_file.display().to_string()),
            "{command}: {text}"
        );
        assert!(text.contains("codex login"), "{command}: {text}");
        assert_eq!(std::fs::read_to_string(&auth_file)?, CODEX_CLI_AUTH_JSON);
    }
    Ok(())
}

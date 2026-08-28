use std::time::Duration;

use anyhow::{Context, Result};
use tempfile::tempdir;
use tokio::process::Command;

#[cfg(unix)]
fn install_blocking_dotenv(path: &std::path::Path) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes()).context("dotenv path contains NUL")?;
    // SAFETY: `path` is a valid, NUL-terminated C string and the mode is a
    // valid POSIX permission mask. The return value is checked immediately.
    let result = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()).context("create blocking .env FIFO")
    }
}

#[tokio::test]
async fn docs_export_runs_before_dotenv_secret_file_or_network_startup() -> Result<()> {
    let workspace = tempdir().context("create isolated export directory")?;
    // Reading this FIFO blocks until a writer connects. The bounded export
    // therefore proves the internal dispatch happens before dotenv access.
    #[cfg(unix)]
    install_blocking_dotenv(&workspace.path().join(".env"))?;
    let marker = "SECRET_VALUE_MUST_NOT_APPEAR";
    let mut command = Command::new(env!("CARGO_BIN_EXE_ngit-grasp"));
    command
        .arg("__docs-export")
        .current_dir(workspace.path())
        .env_clear()
        .env("NGIT_RELAY_OWNER_NSEC", marker)
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "socks5://127.0.0.1:9")
        .kill_on_drop(true);

    let output = tokio::time::timeout(Duration::from_secs(3), command.output())
        .await
        .context("docs export exceeded its startup deadline")??;
    assert!(
        output.status.success(),
        "docs export failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).context("export must be UTF-8")?;
    let export: serde_json::Value = serde_json::from_str(&stdout).context("parse exported JSON")?;
    assert_eq!(export["schema_version"], 1);
    assert_eq!(export["product"]["id"], "ngit-grasp");
    assert!(
        !stdout.contains(marker),
        "secret values must never be exported"
    );
    assert!(
        !workspace.path().join(".relay-owner.nsec").exists(),
        "docs export must not load or generate the relay-owner key"
    );
    assert!(
        !workspace.path().join("data").exists(),
        "docs export must not initialize relay data"
    );
    Ok(())
}

use std::process::Command;

fn run_invalid_audit(args: &[&str]) -> serde_json::Value {
    let output = Command::new(env!("CARGO_BIN_EXE_grasp-audit"))
        .args(args)
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(
        output.stderr.is_empty(),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout.lines().count(), 1);
    serde_json::from_str(&stdout).unwrap()
}

#[test]
fn missing_required_argument_uses_audit_json_schema() {
    let report = run_invalid_audit(&["audit", "--json"]);

    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["outcome"], "error");
    assert_eq!(report["relay_url"], "");
    assert_eq!(report["specs"], serde_json::json!([]));
    assert!(report["error"]
        .as_str()
        .unwrap()
        .contains("MissingRequiredArgument"));
}

#[test]
fn unknown_argument_uses_audit_json_schema() {
    let report = run_invalid_audit(&[
        "audit",
        "--json",
        "--relay",
        "wss://relay.example",
        "--unknown",
    ]);

    assert_eq!(report["outcome"], "error");
    assert_eq!(report["relay_url"], "wss://relay.example");
    assert!(report["error"]
        .as_str()
        .unwrap()
        .contains("UnknownArgument"));
}

#[test]
fn invalid_audit_spec_uses_audit_json_schema() {
    let report = run_invalid_audit(&[
        "audit",
        "--json",
        "--relay",
        "wss://relay.example",
        "--spec",
        "not-an-audit",
    ]);

    assert_eq!(report["outcome"], "error");
    assert!(report["error"].as_str().unwrap().contains("InvalidValue"));
}

#[test]
fn invalid_mode_uses_audit_json_schema_without_connecting() {
    let report = run_invalid_audit(&[
        "audit",
        "--json",
        "--relay",
        "wss://relay.example",
        "--mode",
        "invalid",
    ]);

    assert_eq!(report["outcome"], "error");
    assert_eq!(report["relay_url"], "wss://relay.example");
    assert!(report["error"].as_str().unwrap().contains("Invalid mode"));
}

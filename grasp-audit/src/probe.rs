//! Probe/smoke-test logic for GRASP relay health checks
//!
//! The probe runs a series of checks against a relay and reports results in
//! human-readable or JSON format. It is designed to be fast and non-destructive
//! when run in read-only mode.

use crate::audit::AuditConfig;
use crate::client::AuditClient;
use crate::fixtures::{create_commit, init_local_repo, try_push};
use nostr_sdk::prelude::*;
use std::time::{Duration, Instant};

// ============================================================
// Result types
// ============================================================

/// Result of a single probe check
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProbeCheck {
    pub name: &'static str,
    pub passed: bool,
    pub skipped: bool,
    pub duration_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Full probe report containing all check results
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProbeReport {
    pub relay_url: String,
    pub timestamp: String,
    pub all_passed: bool,
    pub total_duration_ms: u64,
    pub checks: Vec<ProbeCheck>,
}

impl ProbeReport {
    /// Print a human-readable report with ANSI colours
    pub fn print_human(&self) {
        let green = "\x1b[1;92m";
        let red = "\x1b[1;91m";
        let yellow = "\x1b[33m";
        let bold = "\x1b[1m";
        let reset = "\x1b[0m";
        let sep = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";

        println!(
            "{}GRASP Probe{} — {}  [{}]",
            bold, reset, self.relay_url, self.timestamp
        );
        println!("{}", sep);

        for check in &self.checks {
            if check.skipped {
                // Don't list checks skipped due to read-only mode — they are
                // not applicable, not failures.  Only show skips caused by
                // earlier check failures so the user can see the causal chain.
                if check.error.as_deref() == Some("read-only mode") {
                    continue;
                }
                let reason = check.error.as_deref().unwrap_or("skipped");
                println!(
                    "{}→{}  {:<28} skipped  {}({}){} ",
                    yellow, reset, check.name, yellow, reason, reset
                );
            } else if check.passed {
                let detail_str = check
                    .detail
                    .as_deref()
                    .map(|d| format!("  {}", d))
                    .unwrap_or_default();
                println!(
                    "{}✓{}  {:<28} {}ms{}",
                    green, reset, check.name, check.duration_ms, detail_str
                );
            } else {
                let detail_str = check
                    .detail
                    .as_deref()
                    .map(|d| format!("  {}", d))
                    .unwrap_or_default();
                println!(
                    "{}✗{}  {:<28} {}ms{}",
                    red, reset, check.name, check.duration_ms, detail_str
                );
                if let Some(ref err) = check.error {
                    println!("     {}↳ {}{}", red, err, reset);
                }
            }
        }

        println!("{}", sep);

        if self.all_passed {
            println!(
                "{}All checks passed{}  total: {}ms",
                green, reset, self.total_duration_ms
            );
        } else {
            println!(
                "{}Some checks failed{}  total: {}ms",
                red, reset, self.total_duration_ms
            );
        }
    }

    /// Print machine-readable JSON
    pub fn print_json(&self) {
        // Exclude checks skipped due to read-only mode — they are not
        // applicable and would clutter automated consumers.
        let filtered = ProbeReport {
            checks: self
                .checks
                .iter()
                .filter(|c| !(c.skipped && c.error.as_deref() == Some("read-only mode")))
                .cloned()
                .collect(),
            ..self.clone()
        };
        println!("{}", serde_json::to_string(&filtered).unwrap());
    }
}

// ============================================================
// Helpers
// ============================================================

/// Build a skipped ProbeCheck
fn skipped(name: &'static str, reason: &str) -> ProbeCheck {
    ProbeCheck {
        name,
        passed: false,
        skipped: true,
        duration_ms: 0,
        detail: None,
        error: Some(reason.to_string()),
    }
}

/// Format current time as ISO 8601 UTC (YYYY-MM-DDTHH:MM:SSZ)
fn now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Integer arithmetic to decompose Unix timestamp into date/time components
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400; // days since 1970-01-01

    // Compute year, month, day from days since epoch
    // Using the algorithm from https://howardhinnant.github.io/date_algorithms.html
    let z = days as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097; // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // year of era [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // day of year [0, 365]
    let mp = (5 * doy + 2) / 153; // month of year [0, 11] (March=0)
    let d = doy - (153 * mp + 2) / 5 + 1; // day [1, 31]
    let mo = if mp < 10 { mp + 3 } else { mp - 9 }; // month [1, 12]
    let yr = if mo <= 2 { y + 1 } else { y };

    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", yr, mo, d, h, m, s)
}

// ============================================================
// Main probe function
// ============================================================

/// All check names in the order they may appear, used to fill skipped entries
/// when the overall deadline fires.
const ALL_CHECK_NAMES: &[&str] = &[
    "connect_websocket",
    "nip11_fetch",
    "publish_events",
    "git_repo_initialised",
    "git_push",
    "serves_latest_announcement",
    "git_fetch_refs",
    "git_refs_match_state",
];

/// Run a probe against a GRASP relay and return a full report.
///
/// # Arguments
/// * `relay_url` - WebSocket URL of the relay (e.g. `ws://localhost:7000`)
/// * `keys` - Optional keypair to use; `None` generates fresh keys
/// * `read_only` - When `true`, skip write steps and only check existing repos
/// * `timeout_secs` - Per-step timeout in seconds
/// * `overall_secs` - Hard cap on total probe duration; remaining checks are
///   marked skipped with reason "overall timeout" if the deadline fires
pub async fn run_probe(
    relay_url: &str,
    keys: Option<Keys>,
    read_only: bool,
    timeout_secs: u64,
    overall_secs: u64,
) -> ProbeReport {
    let total_start = Instant::now();
    let deadline = total_start + Duration::from_secs(overall_secs);
    let timestamp = now_iso8601();
    let mut checks: Vec<ProbeCheck> = Vec::new();

    /// Fill all check names not yet present in `checks` as skipped with the
    /// given reason, then return a finished ProbeReport.
    ///
    /// The deadline fired before `$timed_out_name` could start.  Diagnose
    /// whether a single prior check dominated the budget (>50%) or whether
    /// the relay was generally slow across multiple steps.
    macro_rules! deadline_return {
        ($relay_url:expr, $timestamp:expr, $total_start:expr, $overall_secs:expr, $checks:expr, $timed_out_name:expr) => {{
            let total_ms = $total_start.elapsed().as_millis() as u64;
            let budget_ms = ($overall_secs as u64) * 1000;

            // Find the single check that consumed the most time, if it took
            // more than half the overall budget it is the likely culprit.
            let slowest = $checks
                .iter()
                .filter(|c| !c.skipped)
                .max_by_key(|c| c.duration_ms);

            let error_msg = match slowest {
                Some(c) if c.duration_ms > budget_ms / 2 => {
                    format!("overall timeout (likely caused by slow {})", c.name)
                }
                _ => "overall timeout (cumulative slowness across checks)".to_string(),
            };

            // The step that couldn't start due to the deadline
            $checks.push(ProbeCheck {
                name: $timed_out_name,
                passed: false,
                skipped: false,
                duration_ms: 0,
                detail: None,
                error: Some(error_msg),
            });
            // Skip all subsequent checks
            let already: std::collections::HashSet<&str> = $checks.iter().map(|c| c.name).collect();
            for name in ALL_CHECK_NAMES {
                if !already.contains(name) {
                    $checks.push(skipped(name, "overall timeout"));
                }
            }
            let all_passed = $checks.iter().all(|c| c.passed || c.skipped);
            return ProbeReport {
                relay_url: $relay_url.to_string(),
                timestamp: $timestamp,
                all_passed,
                total_duration_ms: total_ms,
                checks: $checks,
            };
        }};
    }

    // ============================================================
    // PREPARE (offline)
    // ============================================================
    let keys = keys.unwrap_or_else(Keys::generate);
    let npub = match keys.public_key().to_bech32() {
        Ok(n) => n,
        Err(e) => {
            // Can't proceed without npub
            return ProbeReport {
                relay_url: relay_url.to_string(),
                timestamp,
                all_passed: false,
                total_duration_ms: total_start.elapsed().as_millis() as u64,
                checks: vec![ProbeCheck {
                    name: "prepare",
                    passed: false,
                    skipped: false,
                    duration_ms: 0,
                    detail: None,
                    error: Some(format!("Failed to derive npub: {}", e)),
                }],
            };
        }
    };

    let repo_id = format!("probe-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let _relay_domain = relay_url
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .trim_end_matches('/')
        .to_string();
    let http_base = relay_url
        .replace("ws://", "http://")
        .replace("wss://", "https://")
        .trim_end_matches('/')
        .to_string();
    let clone_url = format!("{}/{}/{}.git", http_base, npub, repo_id);

    // Create temp dir for local repo
    let local_repo_path =
        std::env::temp_dir().join(format!("grasp-probe-{}", uuid::Uuid::new_v4()));

    // Initialise local repo (offline)
    let init_result = init_local_repo(&local_repo_path, &clone_url);
    let commit_hash = if init_result.is_ok() {
        create_commit(&local_repo_path, "GRASP probe commit").ok()
    } else {
        None
    };

    // Build announcement and state events (not sent yet)
    let config = AuditConfig::probe();
    let announcement_event_opt: Option<Event>;
    let state_event_opt: Option<Event>;

    {
        use nostr_sdk::prelude::*;

        let ann_result = crate::audit::AuditEventBuilder::new(
            Kind::GitRepoAnnouncement,
            "GRASP probe repository",
            config.clone(),
        )
        .tag(Tag::identifier(&repo_id))
        .tag(Tag::custom("name", vec!["GRASP Probe Repository"]))
        .tag(Tag::custom("clone", vec![clone_url.clone()]))
        .tag(Tag::custom("relays", vec![relay_url.to_string()]))
        .build(&keys);

        announcement_event_opt = ann_result.ok();

        let state_result = if let Some(ref ch) = commit_hash {
            crate::audit::AuditEventBuilder::new(Kind::RepoState, "", config.clone())
                .tag(Tag::identifier(&repo_id))
                .tag(Tag::custom("refs/heads/main", vec![ch.clone()]))
                .tag(Tag::custom(
                    "HEAD",
                    vec!["ref: refs/heads/main".to_string()],
                ))
                .build(&keys)
                .ok()
        } else {
            None
        };

        state_event_opt = state_result;
    }

    // ============================================================
    // Step 1: connect_websocket
    // ============================================================
    if Instant::now() >= deadline {
        deadline_return!(
            relay_url,
            timestamp,
            total_start,
            overall_secs,
            checks,
            "connect_websocket"
        );
    }
    let step1_start = Instant::now();
    let client_result = tokio::time::timeout(
        deadline.saturating_duration_since(Instant::now()),
        AuditClient::new_with_keys(relay_url, config.clone(), keys.clone()),
    )
    .await
    .unwrap_or_else(|_| Err(anyhow::anyhow!("overall timeout")));
    let step1_ms = step1_start.elapsed().as_millis() as u64;

    let client = match client_result {
        Ok(c) => {
            checks.push(ProbeCheck {
                name: "connect_websocket",
                passed: true,
                skipped: false,
                duration_ms: step1_ms,
                detail: None,
                error: None,
            });
            c
        }
        Err(e) => {
            checks.push(ProbeCheck {
                name: "connect_websocket",
                passed: false,
                skipped: false,
                duration_ms: step1_ms,
                detail: None,
                error: Some(e.to_string()),
            });
            // Skip all remaining steps
            for name in &[
                "nip11_fetch",
                "publish_events",
                "git_repo_initialised",
                "git_push",
                "git_fetch_refs",
            ] {
                checks.push(skipped(name, "connect_websocket failed"));
            }
            let _ = std::fs::remove_dir_all(&local_repo_path);
            return ProbeReport {
                relay_url: relay_url.to_string(),
                timestamp,
                all_passed: false,
                total_duration_ms: total_start.elapsed().as_millis() as u64,
                checks,
            };
        }
    };

    // ============================================================
    // Step 2: nip11_fetch (independent — always runs if step 1 passed)
    // ============================================================
    {
        if Instant::now() >= deadline {
            deadline_return!(
                relay_url,
                timestamp,
                total_start,
                overall_secs,
                checks,
                "nip11_fetch"
            );
        }
        let step2_start = Instant::now();
        let http_client = reqwest::Client::new();
        let nip11_result = tokio::time::timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(timeout_secs)),
            http_client
                .get(&http_base)
                .header("Accept", "application/nostr+json")
                .send(),
        )
        .await;

        let step2_ms = step2_start.elapsed().as_millis() as u64;

        match nip11_result {
            Ok(Ok(resp)) if resp.status().is_success() => {
                let detail = resp.json::<serde_json::Value>().await.ok().map(|v| {
                    let name = v.get("name").and_then(|n| n.as_str()).unwrap_or("unknown");
                    // software is typically a repo URL; take the last path segment
                    let software = v
                        .get("software")
                        .and_then(|s| s.as_str())
                        .map(|s| s.trim_end_matches('/').rsplit('/').next().unwrap_or(s))
                        .unwrap_or("unknown");
                    let version = v
                        .get("version")
                        .and_then(|ver| ver.as_str())
                        .unwrap_or("unknown");
                    format!("{} ({} v{})", name, software, version)
                });
                checks.push(ProbeCheck {
                    name: "nip11_fetch",
                    passed: true,
                    skipped: false,
                    duration_ms: step2_ms,
                    detail,
                    error: None,
                });
            }
            Ok(Ok(resp)) => {
                checks.push(ProbeCheck {
                    name: "nip11_fetch",
                    passed: false,
                    skipped: false,
                    duration_ms: step2_ms,
                    detail: None,
                    error: Some(format!("HTTP {}", resp.status())),
                });
            }
            Ok(Err(e)) => {
                checks.push(ProbeCheck {
                    name: "nip11_fetch",
                    passed: false,
                    skipped: false,
                    duration_ms: step2_ms,
                    detail: None,
                    error: Some(e.to_string()),
                });
            }
            Err(_) => {
                checks.push(ProbeCheck {
                    name: "nip11_fetch",
                    passed: false,
                    skipped: false,
                    duration_ms: step2_ms,
                    detail: None,
                    error: Some("timeout".to_string()),
                });
            }
        }
    }

    // ============================================================
    // Step 3: publish_events (requires step 1; skipped in read_only)
    // ============================================================
    let mut write_succeeded = false;

    if Instant::now() >= deadline {
        deadline_return!(
            relay_url,
            timestamp,
            total_start,
            overall_secs,
            checks,
            "publish_events"
        );
    }

    if read_only {
        checks.push(skipped("publish_events", "read-only mode"));
        checks.push(skipped("git_repo_initialised", "read-only mode"));
        checks.push(skipped("git_push", "read-only mode"));
    } else {
        let step3_start = Instant::now();

        let send_result = match (&announcement_event_opt, &state_event_opt) {
            (Some(ann), Some(state)) => {
                let r1 = client.send_event(ann.clone()).await;
                let r2 = if r1.is_ok() {
                    client.send_event(state.clone()).await
                } else {
                    r1.map(|_| EventId::all_zeros())
                };
                r2
            }
            _ => Err(anyhow::anyhow!(
                "Events could not be built (local repo init failed)"
            )),
        };

        let step3_ms = step3_start.elapsed().as_millis() as u64;

        match send_result {
            Ok(_) => {
                checks.push(ProbeCheck {
                    name: "publish_events",
                    passed: true,
                    skipped: false,
                    duration_ms: step3_ms,
                    detail: None,
                    error: None,
                });
                write_succeeded = true;
            }
            Err(e) => {
                checks.push(ProbeCheck {
                    name: "publish_events",
                    passed: false,
                    skipped: false,
                    duration_ms: step3_ms,
                    detail: None,
                    error: Some(e.to_string()),
                });
                // Skip steps 4 and 5; step 6 will use fallback
                checks.push(skipped("git_repo_initialised", "publish_events failed"));
                checks.push(skipped("git_push", "publish_events failed"));
            }
        }

        // ============================================================
        // Step 4: git_repo_initialised (requires step 3)
        // ============================================================
        if write_succeeded {
            if Instant::now() >= deadline {
                deadline_return!(
                    relay_url,
                    timestamp,
                    total_start,
                    overall_secs,
                    checks,
                    "git_repo_initialised"
                );
            }
            let step4_start = Instant::now();
            let poll_url = format!("{}/info/refs?service=git-upload-pack", clone_url);
            let http_client = reqwest::Client::new();
            // Cap the poll deadline at both 15s and the overall deadline
            let poll_deadline = (Instant::now() + Duration::from_secs(15)).min(deadline);
            let mut repo_ready = false;

            loop {
                if Instant::now() >= poll_deadline {
                    break;
                }
                match http_client.get(&poll_url).send().await {
                    Ok(resp) if resp.status().as_u16() != 404 => {
                        repo_ready = true;
                        break;
                    }
                    _ => {}
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }

            let step4_ms = step4_start.elapsed().as_millis() as u64;

            if repo_ready {
                checks.push(ProbeCheck {
                    name: "git_repo_initialised",
                    passed: true,
                    skipped: false,
                    duration_ms: step4_ms,
                    detail: None,
                    error: None,
                });
            } else {
                checks.push(ProbeCheck {
                    name: "git_repo_initialised",
                    passed: false,
                    skipped: false,
                    duration_ms: step4_ms,
                    detail: None,
                    error: Some("timeout waiting for repo to be initialised (15s)".to_string()),
                });
                write_succeeded = false;
                checks.push(skipped("git_push", "git_repo_initialised timed out"));
            }
        }

        // ============================================================
        // Step 5: git_push (requires step 4)
        // ============================================================
        if write_succeeded {
            if Instant::now() >= deadline {
                deadline_return!(
                    relay_url,
                    timestamp,
                    total_start,
                    overall_secs,
                    checks,
                    "git_push"
                );
            }
            let step5_start = Instant::now();
            let push_result = try_push(&local_repo_path);
            let step5_ms = step5_start.elapsed().as_millis() as u64;

            match push_result {
                Ok(true) => {
                    checks.push(ProbeCheck {
                        name: "git_push",
                        passed: true,
                        skipped: false,
                        duration_ms: step5_ms,
                        detail: None,
                        error: None,
                    });
                }
                Ok(false) => {
                    checks.push(ProbeCheck {
                        name: "git_push",
                        passed: false,
                        skipped: false,
                        duration_ms: step5_ms,
                        detail: None,
                        error: Some("push rejected by relay".to_string()),
                    });
                    write_succeeded = false;
                }
                Err(e) => {
                    checks.push(ProbeCheck {
                        name: "git_push",
                        passed: false,
                        skipped: false,
                        duration_ms: step5_ms,
                        detail: None,
                        error: Some(e),
                    });
                    write_succeeded = false;
                }
            }
        }
    }

    // ============================================================
    // Step 6: git_fetch_refs
    // ============================================================
    // Two paths:
    //   write_succeeded=true  → check our own repo; compare refs against our state event
    //   write_succeeded=false → find any existing kind 30617; just verify refs are readable
    //
    // In read-only mode we also run a find_announcement check first.

    // Helper: parse pkt-line body into a map of refname -> commit hash,
    // excluding refs/nostr/* entries (only branches and tags).
    fn parse_refs(body: &str) -> Vec<(String, String)> {
        let mut refs = Vec::new();
        for line in body.lines() {
            // pkt-line: 4-hex-char length prefix, then "<hash> <refname>\0<caps>" or "<hash> <refname>"
            let content = if line.len() > 4 { &line[4..] } else { continue };
            // Strip NUL and everything after (capabilities on first line)
            let content = content.split('\0').next().unwrap_or(content).trim();
            // Skip flush packets and service lines
            if content.starts_with('#') || content.is_empty() || content == "0000" {
                continue;
            }
            let mut parts = content.splitn(2, ' ');
            let hash = match parts.next() {
                Some(h) if h.len() == 40 => h,
                _ => continue,
            };
            let refname = match parts.next() {
                Some(r) => r.trim(),
                None => continue,
            };
            // Skip refs/nostr/* — only branches (refs/heads/*) and tags (refs/tags/*)
            if refname.starts_with("refs/nostr/") {
                continue;
            }
            refs.push((refname.to_string(), hash.to_string()));
        }
        refs
    }

    if write_succeeded {
        // ---- Write path ----
        // Step 6a: git_fetch_refs — just verify the endpoint returns 200
        if Instant::now() >= deadline {
            deadline_return!(
                relay_url,
                timestamp,
                total_start,
                overall_secs,
                checks,
                "git_fetch_refs"
            );
        }
        let refs_url = format!("{}/info/refs?service=git-upload-pack", clone_url);
        let http_client = reqwest::Client::new();

        let step6_start = Instant::now();
        let refs_result = tokio::time::timeout(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_secs(timeout_secs)),
            http_client.get(&refs_url).send(),
        )
        .await;
        let step6_ms = step6_start.elapsed().as_millis() as u64;

        // Capture body for the next check; only proceed to match check if fetch succeeded
        let refs_body: Option<String> = match refs_result {
            Ok(Ok(resp)) if resp.status().is_success() => {
                let body = resp.text().await.unwrap_or_default();
                checks.push(ProbeCheck {
                    name: "git_fetch_refs",
                    passed: true,
                    skipped: false,
                    duration_ms: step6_ms,
                    detail: None,
                    error: None,
                });
                Some(body)
            }
            Ok(Ok(resp)) => {
                checks.push(ProbeCheck {
                    name: "git_fetch_refs",
                    passed: false,
                    skipped: false,
                    duration_ms: step6_ms,
                    detail: None,
                    error: Some(format!("HTTP {}", resp.status())),
                });
                None
            }
            Ok(Err(e)) => {
                checks.push(ProbeCheck {
                    name: "git_fetch_refs",
                    passed: false,
                    skipped: false,
                    duration_ms: step6_ms,
                    detail: None,
                    error: Some(e.to_string()),
                });
                None
            }
            Err(_) => {
                checks.push(ProbeCheck {
                    name: "git_fetch_refs",
                    passed: false,
                    skipped: false,
                    duration_ms: step6_ms,
                    detail: None,
                    error: Some("timeout".to_string()),
                });
                None
            }
        };

        // Step 6b: git_refs_match_state — compare fetched refs against our state event
        match refs_body {
            None => {
                checks.push(skipped("git_refs_match_state", "git_fetch_refs failed"));
            }
            Some(body) => {
                let fetched_refs = parse_refs(&body);
                let mut mismatches: Vec<String> = Vec::new();

                if let Some(ref state_ev) = state_event_opt {
                    for tag in state_ev.tags.iter() {
                        let kind_str = tag.kind().to_string();
                        // Only check refs/heads/* and refs/tags/*, skip HEAD and refs/nostr/*
                        if !kind_str.starts_with("refs/heads/")
                            && !kind_str.starts_with("refs/tags/")
                        {
                            continue;
                        }
                        let expected_hash = match tag.content() {
                            Some(h) => h.to_string(),
                            None => continue,
                        };
                        let found = fetched_refs.iter().find(|(r, _)| r == &kind_str);
                        match found {
                            Some((_, actual_hash)) if actual_hash == &expected_hash => {}
                            Some((_, actual_hash)) => {
                                mismatches.push(format!(
                                    "{}: expected {} got {}",
                                    kind_str,
                                    &expected_hash[..8.min(expected_hash.len())],
                                    &actual_hash[..8.min(actual_hash.len())]
                                ));
                            }
                            None => {
                                mismatches.push(format!(
                                    "{}: expected {} not found in refs",
                                    kind_str,
                                    &expected_hash[..8.min(expected_hash.len())]
                                ));
                            }
                        }
                    }
                }

                checks.push(ProbeCheck {
                    name: "git_refs_match_state",
                    passed: mismatches.is_empty(),
                    skipped: false,
                    duration_ms: 0, // no extra network call; cost already in git_fetch_refs
                    detail: None,
                    error: if mismatches.is_empty() {
                        None
                    } else {
                        Some(mismatches.join("; "))
                    },
                });
            }
        }
    } else {
        // ---- Fallback path: find any existing kind 30617, check refs readable ----

        // In read-only mode: first check that at least one announcement exists
        if Instant::now() >= deadline {
            deadline_return!(
                relay_url,
                timestamp,
                total_start,
                overall_secs,
                checks,
                "serves_latest_announcement"
            );
        }
        let filter = Filter::new().kind(Kind::GitRepoAnnouncement).limit(1);
        let existing = client
            .client()
            .fetch_events(filter)
            .timeout(
                deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_secs(5)),
            )
            .await
            .unwrap_or_default();

        let found_event = existing.into_iter().next();

        if read_only {
            // Explicit check: was an announcement found?
            match &found_event {
                Some(ev) => {
                    let ann_npub = ev.pubkey.to_bech32().unwrap_or_else(|_| ev.pubkey.to_hex());
                    let ann_id = ev
                        .tags
                        .iter()
                        .find(|t| t.kind() == "d")
                        .and_then(|t| t.content())
                        .unwrap_or("unknown")
                        .to_string();
                    checks.push(ProbeCheck {
                        name: "serves_latest_announcement",
                        passed: true,
                        skipped: false,
                        duration_ms: 0,
                        detail: Some(format!("{}/{}", ann_npub, ann_id)),
                        error: None,
                    });
                }
                None => {
                    checks.push(ProbeCheck {
                        name: "serves_latest_announcement",
                        passed: false,
                        skipped: false,
                        duration_ms: 0,
                        detail: None,
                        error: Some("no kind:30617 announcements found on relay".to_string()),
                    });
                    let _ = std::fs::remove_dir_all(&local_repo_path);
                    let all_passed = checks.iter().all(|c| c.passed || c.skipped);
                    return ProbeReport {
                        relay_url: relay_url.to_string(),
                        timestamp,
                        all_passed,
                        total_duration_ms: total_start.elapsed().as_millis() as u64,
                        checks,
                    };
                }
            }
        }

        // Now fetch refs from the found repo
        match found_event {
            Some(ev) => {
                let ann_npub = ev.pubkey.to_bech32().unwrap_or_else(|_| ev.pubkey.to_hex());
                let ann_id = ev
                    .tags
                    .iter()
                    .find(|t| t.kind() == "d")
                    .and_then(|t| t.content())
                    .unwrap_or("unknown")
                    .to_string();

                // Prefer the clone tag URL; fall back to constructing from relay
                let fetch_url = ev
                    .tags
                    .iter()
                    .find(|t| t.kind() == "clone")
                    .and_then(|t| t.content())
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| format!("{}/{}/{}.git", http_base, ann_npub, ann_id));

                if Instant::now() >= deadline {
                    deadline_return!(
                        relay_url,
                        timestamp,
                        total_start,
                        overall_secs,
                        checks,
                        "git_fetch_refs"
                    );
                }
                let step6_start = Instant::now();
                let refs_url = format!("{}/info/refs?service=git-upload-pack", fetch_url);
                let http_client = reqwest::Client::new();
                let refs_result = tokio::time::timeout(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(Duration::from_secs(timeout_secs)),
                    http_client.get(&refs_url).send(),
                )
                .await;
                let step6_ms = step6_start.elapsed().as_millis() as u64;

                // Capture body for git_refs_match_state if fetch succeeds
                let refs_body_fallback: Option<String> = match refs_result {
                    Ok(Ok(resp)) if resp.status().is_success() => {
                        let body = resp.text().await.unwrap_or_default();
                        checks.push(ProbeCheck {
                            name: "git_fetch_refs",
                            passed: true,
                            skipped: false,
                            duration_ms: step6_ms,
                            detail: None,
                            error: None,
                        });
                        Some(body)
                    }
                    Ok(Ok(resp)) => {
                        checks.push(ProbeCheck {
                            name: "git_fetch_refs",
                            passed: false,
                            skipped: false,
                            duration_ms: step6_ms,
                            detail: None,
                            error: Some(format!("HTTP {}", resp.status())),
                        });
                        None
                    }
                    Ok(Err(e)) => {
                        checks.push(ProbeCheck {
                            name: "git_fetch_refs",
                            passed: false,
                            skipped: false,
                            duration_ms: step6_ms,
                            detail: None,
                            error: Some(e.to_string()),
                        });
                        None
                    }
                    Err(_) => {
                        checks.push(ProbeCheck {
                            name: "git_fetch_refs",
                            passed: false,
                            skipped: false,
                            duration_ms: step6_ms,
                            detail: None,
                            error: Some("timeout".to_string()),
                        });
                        None
                    }
                };

                // git_refs_match_state: fetch all served kind 30618 state events for this
                // repo (by #d tag), derive expected refs (latest timestamp wins per ref
                // across all authorized state events — relay already validated auth,
                // including recursive maintainer chains), then compare against git refs.
                match refs_body_fallback {
                    None => {
                        checks.push(skipped("git_refs_match_state", "git_fetch_refs failed"));
                    }
                    Some(body) => {
                        let fetched_refs = parse_refs(&body);

                        // Fetch all state events for this repo_id from the relay.
                        // The relay only serves authorized state events (owner + full
                        // recursive maintainer chain already resolved by the relay).
                        let state_filter = Filter::new().kind(Kind::RepoState).custom_tag(
                            nostr_sdk::prelude::SingleLetterTag::lowercase(
                                nostr_sdk::prelude::Alphabet::D,
                            ),
                            ann_id.clone(),
                        );
                        let state_events = client
                            .client()
                            .fetch_events(state_filter)
                            .timeout(
                                deadline
                                    .saturating_duration_since(Instant::now())
                                    .min(Duration::from_secs(5)),
                            )
                            .await
                            .unwrap_or_default();

                        if state_events.is_empty() {
                            checks.push(ProbeCheck {
                                name: "git_refs_match_state",
                                passed: false,
                                skipped: false,
                                duration_ms: 0,
                                detail: None,
                                error: Some(
                                    "no kind:30618 state events found for this repo".to_string(),
                                ),
                            });
                        } else {
                            // Build expected refs: for each ref name, the state event with
                            // the highest created_at timestamp wins (mirrors relay behaviour).
                            // This correctly handles recursive maintainership — any authorized
                            // party's state event may be the most recent for a given ref.
                            let mut expected: std::collections::HashMap<String, String> =
                                std::collections::HashMap::new();
                            let mut latest_ts: std::collections::HashMap<String, u64> =
                                std::collections::HashMap::new();

                            for state_ev in state_events.iter() {
                                let ts = state_ev.created_at.as_secs();
                                for tag in state_ev.tags.iter() {
                                    let kind_str = tag.kind().to_string();
                                    if !kind_str.starts_with("refs/heads/")
                                        && !kind_str.starts_with("refs/tags/")
                                    {
                                        continue;
                                    }
                                    let hash = match tag.content() {
                                        Some(h) => h.to_string(),
                                        None => continue,
                                    };
                                    let prev_ts =
                                        latest_ts.get(kind_str.as_str()).copied().unwrap_or(0);
                                    if ts >= prev_ts {
                                        expected.insert(kind_str.to_string(), hash);
                                        latest_ts.insert(kind_str.to_string(), ts);
                                    }
                                }
                            }

                            let mut mismatches: Vec<String> = Vec::new();
                            for (refname, expected_hash) in &expected {
                                let found = fetched_refs.iter().find(|(r, _)| r == refname);
                                match found {
                                    Some((_, actual_hash)) if actual_hash == expected_hash => {}
                                    Some((_, actual_hash)) => {
                                        mismatches.push(format!(
                                            "{}: expected {} got {}",
                                            refname,
                                            &expected_hash[..8.min(expected_hash.len())],
                                            &actual_hash[..8.min(actual_hash.len())]
                                        ));
                                    }
                                    None => {
                                        mismatches.push(format!(
                                            "{}: expected {} not found in refs",
                                            refname,
                                            &expected_hash[..8.min(expected_hash.len())]
                                        ));
                                    }
                                }
                            }

                            checks.push(ProbeCheck {
                                name: "git_refs_match_state",
                                passed: mismatches.is_empty(),
                                skipped: false,
                                duration_ms: 0,
                                detail: None,
                                error: if mismatches.is_empty() {
                                    None
                                } else {
                                    Some(mismatches.join("; "))
                                },
                            });
                        }
                    }
                }
            }
            None => {
                // Not read-only (already handled above) but no repo found
                checks.push(ProbeCheck {
                    name: "git_fetch_refs",
                    passed: false,
                    skipped: false,
                    duration_ms: 0,
                    detail: None,
                    error: Some("no repositories found on relay".to_string()),
                });
                checks.push(skipped("git_refs_match_state", "no announcement found"));
            }
        }
    }

    // ============================================================
    // CLEANUP
    // ============================================================
    let _ = std::fs::remove_dir_all(&local_repo_path);

    let all_passed = checks.iter().all(|c| c.passed || c.skipped);
    ProbeReport {
        relay_url: relay_url.to_string(),
        timestamp,
        all_passed,
        total_duration_ms: total_start.elapsed().as_millis() as u64,
        checks,
    }
}

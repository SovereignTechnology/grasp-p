use http_body_util::BodyExt;
use hyper::body::Bytes;
use ngit_grasp::{
    git::{
        handlers::handle_receive_pack,
        storage::{FamilyKey, LocalGitStorage},
    },
    nostr::SharedDatabase,
    purgatory::Purgatory,
};
use nostr_sdk::prelude::*;
use std::{path::Path, process::Command, sync::Arc, time::Duration};

fn git(path: &Path, args: &[&str]) -> Vec<u8> {
    let result = Command::new("git")
        .current_dir(path)
        .args(["-c", "user.name=Test", "-c", "user.email=test@example.com"])
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    result.stdout
}

fn push(repo: &Path, old: &str, new: &str) -> Bytes {
    let command = format!("{old} {new} refs/heads/main\0report-status\n");
    let mut bytes = format!("{:04x}{command}0000", command.len() + 4).into_bytes();
    bytes.extend(git(repo, &["pack-objects", "--stdout"]));
    bytes.into()
}

#[tokio::test]
async fn state_promoted_after_advertisement_does_not_reject_an_already_applied_push() {
    promoted_push(false, None).await;
}

#[tokio::test]
async fn already_applied_branch_does_not_require_state_for_a_pr_ref() {
    promoted_push(true, None).await;
}

#[tokio::test]
async fn already_applied_deletion_is_a_verified_noop() {
    promoted_push(false, Some("report-status")).await;
}

#[tokio::test]
async fn already_applied_deletion_supports_sideband_status_v2() {
    promoted_push(false, Some("report-status-v2 side-band-64k")).await;
}

async fn promoted_push(with_pr: bool, deletion_caps: Option<&str>) {
    let dir = tempfile::tempdir().unwrap();
    let owner = Keys::generate();
    let identifier = "promotion-race";
    let repo = dir
        .path()
        .join(owner.public_key().to_bech32().unwrap())
        .join("promotion-race.git");
    let storage = LocalGitStorage::new(dir.path());
    storage
        .create_thin_view(&FamilyKey::sha1(identifier).unwrap(), &repo)
        .unwrap();
    let family = storage
        .ensure_family(&FamilyKey::sha1(identifier).unwrap())
        .unwrap();
    let tree = String::from_utf8(git(&family, &["mktree"]))
        .unwrap()
        .trim()
        .to_owned();
    let commit = String::from_utf8(git(
        &family,
        &["commit-tree", &tree, "-m", "already promoted"],
    ))
    .unwrap()
    .trim()
    .to_owned();
    git(&repo, &["update-ref", "refs/heads/main", &commit]);
    let db: SharedDatabase = Arc::new(nostr_memory::MemoryDatabase::unbounded());
    let ann = EventBuilder::new(Kind::GitRepoAnnouncement, "")
        .tags([
            Tag::identifier(identifier),
            Tag::custom("clone", ["https://service.example/promotion-race.git"]),
        ])
        .finalize(&owner)
        .unwrap();
    let state = EventBuilder::new(Kind::RepoState, "")
        .tags([
            Tag::identifier(identifier),
            Tag::custom("refs/heads/main", [&commit]),
        ])
        .finalize(&owner)
        .unwrap();
    db.save_event(&ann).await.unwrap();
    db.save_event(&state).await.unwrap();
    let purgatory = Arc::new(Purgatory::new(dir.path().to_path_buf()));
    let relay = LocalRelayBuilder::default().database(db.clone()).build();

    // The client saw an absent branch; background promotion installed it
    // before its upload arrived and removed the state from purgatory.
    let request = if let Some(caps) = deletion_caps {
        let branch = format!("{} {commit} refs/heads/main\0{caps}\n", "0".repeat(40));
        let deletion = format!("{commit} {} refs/heads/gone\n", "0".repeat(40));
        Bytes::from(format!(
            "{:04x}{branch}{:04x}{deletion}0000",
            branch.len() + 4,
            deletion.len() + 4
        ))
    } else if with_pr {
        let command = format!(
            "{} {commit} refs/heads/main\0report-status\n",
            "0".repeat(40)
        );
        let pr = format!(
            "{} {commit} refs/nostr/{}\n",
            "0".repeat(40),
            "a".repeat(64)
        );
        let mut raw = format!(
            "{:04x}{command}{:04x}{pr}0000",
            command.len() + 4,
            pr.len() + 4
        )
        .into_bytes();
        raw.extend(git(&repo, &["pack-objects", "--stdout"]));
        Bytes::from(raw)
    } else {
        push(&repo, &"0".repeat(40), &commit)
    };
    let response = tokio::time::timeout(
        Duration::from_secs(10),
        handle_receive_pack(
            repo.clone(),
            request,
            db.clone(),
            relay.clone(),
            identifier,
            &owner.public_key().to_hex(),
            purgatory.clone(),
            dir.path().to_str().unwrap(),
            None,
            None,
            None,
            None,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let body = tokio::time::timeout(Duration::from_secs(10), response.into_body().collect())
        .await
        .unwrap()
        .unwrap()
        .to_bytes();
    let result = String::from_utf8_lossy(&body);
    assert!(
        result.contains("unpack ok") && result.contains("ok refs/heads/main"),
        "{result}"
    );

    if deletion_caps.is_some() {
        assert!(result.contains("ok refs/heads/gone"), "{result}");
        assert!(
            !String::from_utf8(git(&repo, &["for-each-ref", "refs/heads/gone"]))
                .unwrap()
                .contains("refs/heads/gone")
        );
    }
    if with_pr {
        assert!(
            result.contains(&format!("ok refs/nostr/{}", "a".repeat(64))),
            "{result}"
        );
        assert_eq!(
            String::from_utf8(git(
                &repo,
                &["rev-parse", &format!("refs/nostr/{}", "a".repeat(64))]
            ))
            .unwrap()
            .trim(),
            commit
        );
    }

    // Existing objects are not authority to change a ref: a different target
    // still needs an authorizing state in purgatory.
    let other = String::from_utf8(git(
        &family,
        &["commit-tree", &tree, "-m", "not authorized"],
    ))
    .unwrap()
    .trim()
    .to_owned();
    let response = handle_receive_pack(
        repo.clone(),
        push(&repo, &commit, &other),
        db,
        relay.clone(),
        identifier,
        &owner.public_key().to_hex(),
        purgatory,
        dir.path().to_str().unwrap(),
        None,
        None,
        None,
        None,
    )
    .await
    .unwrap();
    let body = tokio::time::timeout(Duration::from_secs(10), response.into_body().collect())
        .await
        .unwrap()
        .unwrap()
        .to_bytes();
    assert!(String::from_utf8_lossy(&body).contains("authorisation failed"));
    assert_eq!(
        String::from_utf8(git(&repo, &["rev-parse", "refs/heads/main"]))
            .unwrap()
            .trim(),
        commit
    );
    relay.shutdown();
}

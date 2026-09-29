//! Restore unsigned-upload expiry independently of the purgatory checkpoint.
use std::path::Path;
use std::time::SystemTime;

use anyhow::{ensure, Context, Result};
use nostr_sdk::prelude::{EventId, FromBech32, PublicKey};

use super::{registry_dir, PendingUpload, Record, Tip, View};
use crate::git::storage::LocalGitStorage;
use crate::nostr::SharedDatabase;
use crate::purgatory::Purgatory;

/// Called during startup before background writers and request handling.
/// Only surviving refs without a known signed event become placeholders.
/// Legacy records get one persisted grace period, never a fresh one per boot.
pub async fn recover_placeholders(
    storage: &LocalGitStorage,
    purgatory: &Purgatory,
    database: &SharedDatabase,
) -> Result<()> {
    let entries = match std::fs::read_dir(registry_dir(storage)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let path = match entry {
            Ok(entry) => entry.path(),
            Err(error) => {
                tracing::error!(%error, "Cannot read staging registry entry; skipping expiry recovery for it");
                continue;
            }
        };
        if path.extension().is_none_or(|ext| ext != "json") {
            continue;
        }
        if let Err(error) = recover_record(&path, storage, purgatory, database).await {
            tracing::error!(record = %path.display(), error = %format!("{error:#}"),
                "Cannot recover staged upload expiry; leaving record and data for inspection");
        }
    }
    Ok(())
}

// Failure is local to this record: without a recovered placeholder, its live
// refs remain protected by compaction. Do not delete or rename suspect metadata.
async fn recover_record(
    path: &Path,
    storage: &LocalGitStorage,
    purgatory: &Purgatory,
    database: &SharedDatabase,
) -> Result<()> {
    let mut record: Record = serde_json::from_slice(&std::fs::read(path)?)?;
    ensure!(
        !record.view.as_os_str().is_empty()
            && record
                .view
                .components()
                .all(|part| matches!(part, std::path::Component::Normal(_))),
        "invalid staging view path"
    );
    let view_path = storage.git_data_path().join(&record.view);
    if !view_path.try_exists()? {
        return Ok(());
    }
    let view = View::resolve(&view_path)?.context("staged view has no family")?;
    ensure!(
        view.record == std::fs::canonicalize(path)?,
        "staging registry path does not match view"
    );
    let parts: Vec<_> = record
        .view
        .iter()
        .map(|part| part.to_str().context("non-UTF-8 view path"))
        .collect::<Result<_>>()?;
    let (owner, prs) = match parts.as_slice() {
        [owner, _] => (PublicKey::from_bech32(owner)?, false),
        ["prs", owner, _] => (PublicKey::from_hex(owner)?, true),
        _ => anyhow::bail!("unsupported staged view path"),
    };
    let refs = crate::git::list_refs(&view.path).map_err(anyhow::Error::msg)?;
    for (reference, oid) in refs {
        let Some(id) = reference.strip_prefix("refs/nostr/") else {
            continue;
        };
        let Ok(event_id) = EventId::from_hex(id) else {
            continue;
        };
        if database.event_by_id(&event_id).await?.is_some()
            || purgatory
                .find_pr(id)
                .is_some_and(|entry| entry.event.is_some())
        {
            continue;
        }
        let tip = Tip::new(&reference, &oid);
        let expires_at =
            if let Some(pending) = record.pending.iter().find(|pending| pending.tip == tip) {
                pending.expires_at
            } else {
                // Older registry versions recorded only the view and owed tips.
                let expires_at = SystemTime::now() + crate::purgatory::DEFAULT_EXPIRY;
                record
                    .pending
                    .retain(|pending| pending.tip.reference != reference);
                record.pending.push(PendingUpload { tip, expires_at });
                view.save(&record)?;
                expires_at
            };
        purgatory.recover_upload_placeholder(
            id.to_owned(),
            oid,
            (owner, view.key.identifier.clone()),
            prs,
            expires_at,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::super::tests::{commit, reference, Fixture, PENDING};
    use super::super::{compact, object_exists, stage, stage_upload};
    use super::*;
    use nostr_sdk::prelude::*;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    fn database() -> SharedDatabase {
        Arc::new(nostr_memory::MemoryDatabase::unbounded())
    }

    fn fixture(prs: bool) -> (Fixture, PublicKey, String) {
        let owner = Keys::generate().public_key();
        let parent = if prs {
            format!("prs/{}", owner.to_hex())
        } else {
            owner.to_bech32().unwrap()
        };
        let fixture = Fixture::with_view(&parent);
        stage(&fixture.view, &[]).unwrap();
        let oid = commit(&fixture.view, "pending", None);
        stage_upload(&fixture.view, &[], &[Tip::new(PENDING, &oid)]).unwrap();
        reference(&fixture.view, PENDING, &oid);
        (fixture, owner, oid)
    }

    #[tokio::test]
    async fn bad_records_do_not_block_healthy_recovery_or_delete_data() {
        for corrupt in [true, false] {
            let (fixture, _, _) = fixture(false);
            let bad_path = fixture
                .storage
                .git_data_path()
                .join("unexpected/nested/owner/repo.git");
            std::fs::create_dir_all(bad_path.parent().unwrap()).unwrap();
            fixture
                .storage
                .create_thin_view(&fixture.key, &bad_path)
                .unwrap();
            stage(&bad_path, &[]).unwrap();
            let oid = commit(&bad_path, "bad record upload", None);
            let bad_ref = super::super::tests::ABANDONED;
            stage_upload(&bad_path, &[], &[Tip::new(bad_ref, &oid)]).unwrap();
            reference(&bad_path, bad_ref, &oid);
            let record_path = View::resolve(&bad_path).unwrap().unwrap().record;
            if corrupt {
                std::fs::write(&record_path, b"{broken json").unwrap();
            }
            let before = std::fs::read(&record_path).unwrap();
            let purgatory = Purgatory::new(fixture.storage.git_data_path());
            recover_placeholders(&fixture.storage, &purgatory, &database())
                .await
                .unwrap();
            assert!(purgatory
                .find_pr(PENDING.trim_start_matches("refs/nostr/"))
                .is_some());
            assert!(purgatory
                .find_pr(bad_ref.trim_start_matches("refs/nostr/"))
                .is_none());
            assert_eq!(
                crate::git::get_ref_commit(&bad_path, bad_ref),
                Some(oid.clone())
            );
            assert!(object_exists(&bad_path, &oid).unwrap());
            assert_eq!(std::fs::read(&record_path).unwrap(), before);
        }
    }

    #[tokio::test]
    async fn uncheckpointed_uploads_recover_original_expiry_and_are_reclaimed() {
        for prs in [false, true] {
            let (fixture, owner, oid) = fixture(prs);
            let view = View::resolve(&fixture.view).unwrap().unwrap();
            let mut record = view.load().unwrap().unwrap();
            // Inject an elapsed deadline rather than waiting thirty minutes.
            record.pending[0].expires_at = SystemTime::UNIX_EPOCH;
            view.save(&record).unwrap();
            let db = database();
            // Repeated recovery must not refresh the durable deadline.
            for _ in 0..2 {
                let purgatory = Purgatory::new(fixture.storage.git_data_path());
                recover_placeholders(&fixture.storage, &purgatory, &db)
                    .await
                    .unwrap();
                let entry = purgatory
                    .find_pr(PENDING.trim_start_matches("refs/nostr/"))
                    .unwrap();
                assert!(entry.expires_at <= Instant::now());
                assert_eq!(entry.commit, oid);
                if prs {
                    assert_eq!(entry.prs_scope.unwrap().submitter, owner);
                } else {
                    assert_eq!(entry.standard_refs[0].owner, owner);
                }
            }
            let purgatory = Purgatory::new(fixture.storage.git_data_path());
            purgatory.set_prs_cleanup_ctx(crate::purgatory::PrsCleanupCtx {
                git_data_path: fixture.storage.git_data_path().to_owned(),
                repo_init_locks: Default::default(),
            });
            recover_placeholders(&fixture.storage, &purgatory, &db)
                .await
                .unwrap();
            purgatory
                .cleanup_standard_pr_refs(
                    &crate::nostr::lifecycle::RepositoryLifecycle::in_memory(),
                    &db,
                )
                .await;
            purgatory.cleanup();
            if prs {
                assert!(!fixture.view.exists());
            } else {
                compact(&fixture.view).unwrap();
                assert!(!object_exists(&fixture.view, &oid).unwrap());
            }
        }
    }

    #[tokio::test]
    async fn legacy_registry_gets_only_one_persisted_grace_period() {
        let (fixture, _, _) = fixture(false);
        let view = View::resolve(&fixture.view).unwrap().unwrap();
        let mut record = view.load().unwrap().unwrap();
        record.pending.clear();
        view.save(&record).unwrap();
        let db = database();
        let purgatory = Purgatory::new(fixture.storage.git_data_path());
        recover_placeholders(&fixture.storage, &purgatory, &db)
            .await
            .unwrap();
        let deadline = view.load().unwrap().unwrap().pending[0].expires_at;
        assert!(deadline > SystemTime::now());
        let restarted = Purgatory::new(fixture.storage.git_data_path());
        recover_placeholders(&fixture.storage, &restarted, &db)
            .await
            .unwrap();
        assert_eq!(
            view.load().unwrap().unwrap().pending[0].expires_at,
            deadline
        );
    }

    #[tokio::test]
    async fn recovery_preserves_signed_events_and_ignores_failed_ref_updates() {
        let (fixture, _, oid) = fixture(false);
        let keys = Keys::generate();
        let event = EventBuilder::new(Kind::GitPullRequest, "signed")
            .tags([Tag::custom("c", [&oid])])
            .finalize(&keys)
            .unwrap();
        let reference_name = format!("refs/nostr/{}", event.id);
        stage_upload(&fixture.view, &[], &[Tip::new(&reference_name, &oid)]).unwrap();
        reference(&fixture.view, &reference_name, &oid);
        let db = database();
        let purgatory = Purgatory::new(fixture.storage.git_data_path());
        purgatory.add_pr(event.clone(), event.id.to_hex(), oid.clone(), false);
        recover_placeholders(&fixture.storage, &purgatory, &db)
            .await
            .unwrap();
        assert_eq!(
            purgatory.find_pr(&event.id.to_hex()).unwrap().event,
            Some(event.clone())
        );
        db.save_event(&event).await.unwrap();
        let restarted = Purgatory::new(fixture.storage.git_data_path());
        recover_placeholders(&fixture.storage, &restarted, &db)
            .await
            .unwrap();
        assert!(restarted.find_pr(&event.id.to_hex()).is_none());
        assert!(object_exists(&fixture.view, &oid).unwrap());
        // Intent was persisted but receive-pack never installed this ref.
        let failed = format!("refs/nostr/{}", "ab".repeat(32));
        stage_upload(&fixture.view, &[], &[Tip::new(&failed, &oid)]).unwrap();
        recover_placeholders(&fixture.storage, &restarted, &db)
            .await
            .unwrap();
        assert!(restarted
            .find_pr(failed.trim_start_matches("refs/nostr/"))
            .is_none());
    }

    #[tokio::test]
    async fn recovery_preserves_a_newer_checkpoint_deadline() {
        let (fixture, owner, oid) = fixture(false);
        let purgatory = Purgatory::new(fixture.storage.git_data_path());
        let id = PENDING.trim_start_matches("refs/nostr/");
        purgatory.recover_upload_placeholder(
            id.into(),
            oid,
            (owner, "repo".into()),
            false,
            SystemTime::now() + Duration::from_secs(3600),
        );
        let deadline = purgatory.find_pr(id).unwrap().expires_at;
        recover_placeholders(&fixture.storage, &purgatory, &database())
            .await
            .unwrap();
        assert_eq!(purgatory.find_pr(id).unwrap().expires_at, deadline);
    }
}

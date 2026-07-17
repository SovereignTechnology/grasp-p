use anyhow::Result;
use nostr_relay_builder::prelude::{Filter, Kind, Timestamp};

use crate::nostr::lifecycle::RequestLifecycleRecord;

use super::DeletionService;

/// Result counters for one bounded deletion-request retention pass.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RequestCleanupStats {
    pub canonical_records_examined: usize,
    pub main_payloads_removed: usize,
    pub tombstone_payloads_removed: usize,
    pub metadata_rows_removed: usize,
    pub indefinitely_retained_disrespector_requests: usize,
    pub stale_or_concurrent_records_skipped: usize,
    pub failures: usize,
}

impl DeletionService {
    /// Reconcile served copies and permanently expire elapsed request lifecycles.
    /// The supplied time makes every retention boundary deterministic in tests.
    pub(crate) async fn cleanup_expired_requests(
        &self,
        now: Timestamp,
    ) -> Result<RequestCleanupStats> {
        let records = self.ctx.tombstones().lifecycle_records_result().await?;
        let mut stats = RequestCleanupStats {
            canonical_records_examined: records.len(),
            ..Default::default()
        };

        for selected in records {
            if let Err(error) = self.cleanup_one_request(&selected, now, &mut stats).await {
                stats.failures += 1;
                tracing::warn!(request_id = %selected.request.id, error = %error, "Deletion-request cleanup failed for record");
            }
        }

        match self.ctx.tombstones().remove_orphan_metadata().await {
            Ok(removed) => stats.metadata_rows_removed += removed,
            Err(error) => {
                stats.failures += 1;
                tracing::warn!(error = %error, "Deletion-request cleanup failed to remove orphan metadata");
            }
        }
        Ok(stats)
    }

    async fn cleanup_one_request(
        &self,
        selected: &RequestLifecycleRecord,
        now: Timestamp,
        stats: &mut RequestCleanupStats,
    ) -> Result<()> {
        let tombstones = self.ctx.tombstones();
        let _guard = tombstones.lock_lifecycle().await;
        let Some(current) = tombstones
            .lifecycle_for_request_result(&selected.request.id)
            .await?
        else {
            stats.stale_or_concurrent_records_skipped += 1;
            return Ok(());
        };
        // A mark-used/reclassification replacement between enumeration and this
        // lock acquisition means this pass must not act on its stale decision.
        if current != *selected {
            stats.stale_or_concurrent_records_skipped += 1;
            return Ok(());
        }

        let targeting = current.request.kind == Kind::EventDeletion
            || self.vanish_targets_this_relay(&current.request);
        if self.ctx.config.deletion_request_disrespector
            && targeting
            && current.last_used_at.is_some()
        {
            stats.indefinitely_retained_disrespector_requests += 1;
            return Ok(());
        }

        if self.request_is_served(&current, now)? {
            return Ok(());
        }

        // Main must be removed before Tombstones. Holding the same lifecycle
        // lock as gate attribution prevents stale cleanup from unserving a
        // request that an admission just promoted and marked used.
        if self
            .ctx
            .database()
            .event_by_id(&current.request.id)
            .await?
            .is_some()
        {
            self.ctx
                .database()
                .delete(Filter::new().ids(vec![current.request.id]))
                .await?;
            stats.main_payloads_removed += 1;
        }

        if !self.request_is_expired(&current, now)? {
            return Ok(());
        }
        let removed = tombstones
            .permanently_delete_request_locked(&current.request.id)
            .await?;
        stats.tombstone_payloads_removed += removed.payloads_deleted;
        stats.metadata_rows_removed += removed.metadata_deleted;
        Ok(())
    }

    pub(crate) fn request_is_served(
        &self,
        record: &RequestLifecycleRecord,
        now: Timestamp,
    ) -> Result<bool> {
        let (anchor, duration) = match record.last_used_at {
            Some(used) => (
                used,
                self.ctx
                    .config
                    .deletion_request_retention_used_served_after_last_used(),
            ),
            None => (
                record.first_seen_at,
                self.ctx.config.deletion_request_retention_unused_served(),
            ),
        };
        let deadline = anchor
            .as_secs()
            .checked_add(duration.as_secs())
            .ok_or_else(|| {
                anyhow::anyhow!("deletion-request served retention deadline overflow")
            })?;
        Ok(now.as_secs() < deadline)
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::sync::Arc;

    use nostr_relay_builder::prelude::{Event, EventBuilder, EventId, FinalizeEvent, Keys, Tag};

    use super::*;
    use crate::grasp06::receive::new_repo_init_locks;
    use crate::nostr::lifecycle::{
        HoldingStore, ReplaceableHistoryStore, RepositoryLifecycle, RequestClassification,
        Tombstones,
    };
    use crate::purgatory::Purgatory;

    fn service(disrespector: bool) -> DeletionService {
        let db = Arc::new(nostr_memory::MemoryDatabase::unbounded());
        let config = crate::config::Config {
            deletion_request_disrespector: disrespector,
            deletion_request_retention_unused_served_secs: 10,
            deletion_request_retention_unused_unserved_gating_additional_secs: 5,
            deletion_request_retention_used_served_after_last_used_secs: 20,
            deletion_request_retention_used_unserved_gating_additional_secs: 5,
            ..crate::config::Config::for_testing()
        };
        DeletionService::new(super::super::DeletionContext::new(
            "test.example.com",
            db,
            Tombstones::in_memory(),
            HoldingStore::in_memory(),
            RepositoryLifecycle::in_memory(),
            ReplaceableHistoryStore::in_memory(),
            PathBuf::new(),
            Arc::new(Purgatory::new(PathBuf::new())),
            config,
            new_repo_init_locks(),
        ))
    }

    fn deletion() -> Event {
        EventBuilder::new(Kind::EventDeletion, "")
            .tags(vec![Tag::event(EventId::all_zeros())])
            .finalize(&Keys::generate())
            .unwrap()
    }

    fn non_targeting_vanish() -> Event {
        EventBuilder::new(Kind::RequestToVanish, "")
            .tags(vec![Tag::custom(
                "relay",
                vec!["wss://elsewhere.example".to_owned()],
            )])
            .finalize(&Keys::generate())
            .unwrap()
    }

    async fn retained(service: &DeletionService, request: &Event, first_seen: u64) {
        service
            .ctx
            .tombstones()
            .record_request(
                request,
                Timestamp::from_secs(first_seen),
                RequestClassification::LocallyActionable,
            )
            .await
            .unwrap();
        service.ctx.database().save_event(request).await.unwrap();
    }

    async fn main_has(service: &DeletionService, request: &Event) -> bool {
        service
            .ctx
            .database()
            .event_by_id(&request.id)
            .await
            .unwrap()
            .is_some()
    }

    #[tokio::test]
    async fn unused_boundaries_keep_gate_then_permanently_expire() {
        let service = service(false);
        let request = deletion();
        retained(&service, &request, 0).await;
        assert_eq!(
            service
                .cleanup_expired_requests(Timestamp::from_secs(9))
                .await
                .unwrap()
                .main_payloads_removed,
            0
        );
        assert!(main_has(&service, &request).await);

        let stats = service
            .cleanup_expired_requests(Timestamp::from_secs(10))
            .await
            .unwrap();
        assert_eq!(stats.main_payloads_removed, 1);
        assert!(!main_has(&service, &request).await);
        assert!(service
            .ctx
            .tombstones()
            .lifecycle_for_request_result(&request.id)
            .await
            .unwrap()
            .is_some());
        assert_eq!(
            service
                .ctx
                .tombstones()
                .event_deletion_candidates(&EventId::all_zeros(), &request.pubkey)
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            service
                .ctx
                .tombstones()
                .lifecycle_records_result()
                .await
                .unwrap()
                .len(),
            1
        );

        let stats = service
            .cleanup_expired_requests(Timestamp::from_secs(15))
            .await
            .unwrap();
        assert_eq!(stats.tombstone_payloads_removed, 1);
        assert!(service
            .ctx
            .tombstones()
            .lifecycle_for_request_result(&request.id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn used_boundaries_and_reuse_reset_the_lifecycle() {
        let service = service(false);
        let request = deletion();
        retained(&service, &request, 0).await;
        service
            .ctx
            .tombstones()
            .mark_request_used(&request.id, Timestamp::from_secs(20))
            .await
            .unwrap();
        assert!(
            service
                .cleanup_expired_requests(Timestamp::from_secs(39))
                .await
                .unwrap()
                .main_payloads_removed
                == 0
        );
        service
            .ctx
            .tombstones()
            .mark_request_used(&request.id, Timestamp::from_secs(39))
            .await
            .unwrap();
        assert!(
            service
                .cleanup_expired_requests(Timestamp::from_secs(40))
                .await
                .unwrap()
                .main_payloads_removed
                == 0
        );
        let stats = service
            .cleanup_expired_requests(Timestamp::from_secs(59))
            .await
            .unwrap();
        assert_eq!(stats.main_payloads_removed, 1);
        assert!(service
            .ctx
            .tombstones()
            .lifecycle_for_request_result(&request.id)
            .await
            .unwrap()
            .is_some());
        let stats = service
            .cleanup_expired_requests(Timestamp::from_secs(64))
            .await
            .unwrap();
        assert_eq!(stats.tombstone_payloads_removed, 1);
    }

    #[tokio::test]
    async fn disrespector_only_retains_used_targeting_requests_indefinitely() {
        let service = service(true);
        let used = deletion();
        retained(&service, &used, 0).await;
        service
            .ctx
            .tombstones()
            .mark_request_used(&used.id, Timestamp::from_secs(1))
            .await
            .unwrap();
        let stats = service
            .cleanup_expired_requests(Timestamp::from_secs(10_000))
            .await
            .unwrap();
        assert_eq!(stats.indefinitely_retained_disrespector_requests, 1);
        assert!(main_has(&service, &used).await);

        let unused = deletion();
        retained(&service, &unused, 0).await;
        service
            .cleanup_expired_requests(Timestamp::from_secs(15))
            .await
            .unwrap();
        assert!(service
            .ctx
            .tombstones()
            .lifecycle_for_request_result(&unused.id)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn non_targeting_nip62_expires_and_cleanup_is_idempotent() {
        let service = service(false);
        let request = non_targeting_vanish();
        retained(&service, &request, 0).await;
        assert!(
            service
                .cleanup_expired_requests(Timestamp::from_secs(15))
                .await
                .unwrap()
                .tombstone_payloads_removed
                == 1
        );
        let rerun = service
            .cleanup_expired_requests(Timestamp::from_secs(15))
            .await
            .unwrap();
        assert_eq!(
            rerun.main_payloads_removed
                + rerun.tombstone_payloads_removed
                + rerun.metadata_rows_removed,
            0
        );
    }

    #[tokio::test]
    async fn stale_cleanup_snapshot_cannot_unserve_a_marked_used_request() {
        let service = service(false);
        let request = deletion();
        retained(&service, &request, 0).await;
        let selected = service
            .ctx
            .tombstones()
            .lifecycle_for_request_result(&request.id)
            .await
            .unwrap()
            .unwrap();
        // This models admission's metadata update and Main promotion happening
        // after enumeration but before cleanup acquires the shared lock.
        service
            .ctx
            .tombstones()
            .mark_request_used(&request.id, Timestamp::from_secs(14))
            .await
            .unwrap();
        let mut stats = RequestCleanupStats::default();
        service
            .cleanup_one_request(&selected, Timestamp::from_secs(15), &mut stats)
            .await
            .unwrap();
        assert_eq!(stats.stale_or_concurrent_records_skipped, 1);
        assert!(main_has(&service, &request).await);
    }

    #[tokio::test]
    async fn cleanup_repairs_orphan_metadata_idempotently_after_partial_removal() {
        let service = service(false);
        let request = deletion();
        service
            .ctx
            .tombstones()
            .record_request(
                &request,
                Timestamp::from_secs(0),
                RequestClassification::LocallyActionable,
            )
            .await
            .unwrap();
        service
            .ctx
            .tombstones()
            .remove_request_payload_without_metadata(request.id)
            .await
            .unwrap();

        let first = service
            .cleanup_expired_requests(Timestamp::from_secs(15))
            .await
            .unwrap();
        assert_eq!(first.canonical_records_examined, 0);
        assert_eq!(first.metadata_rows_removed, 1);
        let rerun = service
            .cleanup_expired_requests(Timestamp::from_secs(15))
            .await
            .unwrap();
        assert_eq!(rerun.metadata_rows_removed, 0);
        assert_eq!(rerun.failures, 0);
    }

    #[tokio::test]
    async fn startup_reconciliation_and_periodic_cleanup_share_serving_boundary() {
        let startup = service(false);
        let periodic = service(false);
        let startup_request = deletion();
        let periodic_request = deletion();
        retained(&startup, &startup_request, 0).await;
        retained(&periodic, &periodic_request, 0).await;

        startup
            .run_request_lifecycle_startup_reconciliation(Timestamp::from_secs(10))
            .await
            .unwrap();
        periodic
            .cleanup_expired_requests(Timestamp::from_secs(10))
            .await
            .unwrap();
        assert!(!main_has(&startup, &startup_request).await);
        assert!(!main_has(&periodic, &periodic_request).await);
        assert!(startup
            .ctx
            .tombstones()
            .lifecycle_for_request_result(&startup_request.id)
            .await
            .unwrap()
            .is_some());
        assert!(periodic
            .ctx
            .tombstones()
            .lifecycle_for_request_result(&periodic_request.id)
            .await
            .unwrap()
            .is_some());
    }
}

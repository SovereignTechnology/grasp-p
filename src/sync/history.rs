//! Historic admission runs outside the sync actor. The actor owns lifecycle
//! transitions; workers only register wire IDs and start bounded, paced queries.
use super::*;

const MAX_ACTIVE_HISTORY_JOBS: usize = 8;

pub(super) struct HistoryResult {
    pub relay_url: String,
    pub batch_id: u64,
    pub barrier: SubscriptionId,
    pub outcome: Result<(), String>,
}

struct Task {
    relay_url: String,
    batch_id: u64,
    gate: Arc<Semaphore>,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for Task {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

pub(super) struct HistoryTasks {
    tasks: HashMap<SubscriptionId, Task>,
    capacity: Arc<Semaphore>,
}

impl Default for HistoryTasks {
    fn default() -> Self {
        Self {
            tasks: HashMap::new(),
            capacity: Arc::new(Semaphore::new(MAX_ACTIVE_HISTORY_JOBS)),
        }
    }
}

impl HistoryTasks {
    pub fn spawn(&mut self, job: HistoryJob, tx: tokio::sync::mpsc::Sender<HistoryResult>) {
        let gate = self
            .tasks
            .values()
            .find(|task| task.relay_url == job.relay_url)
            .map(|task| task.gate.clone())
            .unwrap_or_else(|| Arc::new(Semaphore::new(1)));
        let task_gate = gate.clone();
        let capacity = self.capacity.clone();
        let relay_url = job.relay_url.clone();
        let batch_id = job.batch_id;
        let barrier = job.barrier.clone();
        let handle = tokio::spawn(async move {
            // Acquire the relay gate first so a busy relay cannot occupy all
            // global slots with its queued batches.
            let relay_permit = task_gate.acquire().await.unwrap();
            let outcome = loop {
                // A paused peer retains its per-relay order, but must not
                // occupy a global slot during a minute/day-long cooldown.
                if job.wait_for_cooldown {
                    while let Some(remaining) = job.remaining_pause() {
                        tokio::time::sleep(remaining + Duration::from_millis(10)).await;
                    }
                }
                let global_permit = capacity.acquire().await.unwrap();
                let outcome = job.run().await;
                drop(global_permit);
                if outcome.is_err()
                    && job.wait_for_cooldown
                    && job.health.is_subscription_paused(&job.relay_url)
                {
                    continue;
                }
                break outcome;
            };
            drop(relay_permit);
            let _ = tx
                .send(HistoryResult {
                    relay_url: job.relay_url,
                    batch_id: job.batch_id,
                    barrier: job.barrier,
                    outcome,
                })
                .await;
        });
        self.tasks.insert(
            barrier,
            Task {
                batch_id,
                relay_url,
                gate,
                handle,
            },
        );
    }

    pub fn finish(&mut self, batch_id: u64) {
        self.tasks.retain(|_, task| task.batch_id != batch_id);
    }

    pub fn complete(&mut self, barrier: &SubscriptionId) {
        self.tasks.remove(barrier);
    }

    pub fn cancel_relay(&mut self, relay_url: &str) {
        self.tasks.retain(|_, task| task.relay_url != relay_url);
    }

    pub fn clear(&mut self) {
        self.tasks.clear();
    }
}

/// Retire partially admitted requests even if a disconnect, daily reset, or
/// CLOSED cancels the worker while it waits for the next pacing/ledger permit.
struct AdmissionCleanup {
    connection: RelayConnection,
    ids: Vec<SubscriptionId>,
}

impl Drop for AdmissionCleanup {
    fn drop(&mut self) {
        if self.ids.is_empty() {
            return;
        }
        let connection = self.connection.clone();
        let ids = std::mem::take(&mut self.ids);
        tokio::spawn(async move {
            for id in ids {
                connection.retire_subscription(&id).await;
            }
        });
    }
}

pub(super) struct HistoryJob {
    pub relay_url: String,
    pub batch_id: u64,
    pub barrier: SubscriptionId,
    pub connection: RelayConnection,
    pub filters: Vec<Filter>,
    pub allow_negentropy: bool,
    pub prepared: Option<Vec<(SubscriptionId, Vec<Filter>, TransientRequestClass)>>,
    pub wait_for_cooldown: bool,
    pub health: Arc<RelayHealthTracker>,
    pub pending: PendingSyncIndex,
    pub purgatory: Arc<crate::purgatory::Purgatory>,
    pub rejected: Arc<rejected_index::RejectedEventsIndex>,
}

impl HistoryJob {
    fn remaining_pause(&self) -> Option<Duration> {
        let health = self.health.get_health(&self.relay_url)?;
        // Policy refusals have a separate deadline from connection/rate
        // backoff. Both must be observed before borrowing a global slot.
        [
            health.remaining_backoff(),
            health
                .policy_retry_at
                .and_then(|deadline| deadline.checked_duration_since(Instant::now())),
        ]
        .into_iter()
        .flatten()
        .max()
    }

    async fn run(&self) -> Result<(), String> {
        if let Some(planned) = &self.prepared {
            return self.admit(planned.clone()).await;
        }
        // Registration precedes the first wire request. The admission barrier
        // stays outstanding until the actor processes our completion message.
        let use_negentropy = self.allow_negentropy && self.connection.supports_negentropy().await;
        let mut remote_ids = HashSet::new();
        let mut reconciled = use_negentropy;
        if use_negentropy {
            // Bound allocations and active reconciliation futures as well as
            // the connection's own NIP-77 admission limit.
            use futures_util::StreamExt;
            let results = futures_util::stream::iter(self.filters.iter().cloned())
                .map(|filter| self.connection.negentropy_sync_diff(filter))
                .buffer_unordered(4);
            tokio::pin!(results);
            while let Some(result) = results.next().await {
                match result {
                    Ok(diff) => remote_ids.extend(diff.remote.keys().copied()),
                    Err(error) => {
                        tracing::debug!(relay = %self.relay_url, %error,
                            "Historic reconciliation failed; falling back to REQ+EOSE");
                        reconciled = false;
                    }
                }
            }
        }
        let (groups, class) = if reconciled {
            let purgatory = self.purgatory.event_ids();
            let rejected = self.rejected.get_all_event_ids();
            remote_ids.retain(|id| !purgatory.contains(id) && !rejected.contains(id));
            let ids: Vec<_> = remote_ids.iter().copied().collect();
            (
                ids.chunks(300)
                    .map(|chunk| vec![Filter::new().ids(chunk.iter().copied())])
                    .collect::<Vec<_>>(),
                TransientRequestClass::NegentropyHydration,
            )
        } else {
            (
                group_filters_for_req_with_max(
                    &self.filters,
                    self.connection.max_filters_per_req(),
                ),
                TransientRequestClass::HistoricPage,
            )
        };
        let planned: Vec<_> = groups
            .into_iter()
            .map(|filters| (SubscriptionId::generate(), filters))
            .collect();
        {
            let mut pending = self.pending.write().await;
            let batch = pending
                .get_mut(&self.relay_url)
                .and_then(|batches| batches.iter_mut().find(|b| b.batch_id == self.batch_id))
                .ok_or("Historic batch retired before admission")?;
            if reconciled {
                batch.sync_method = SyncMethod::Negentropy;
                register_negentropy_hydration_attempt(
                    batch,
                    planned.iter().map(|(id, _)| id.clone()),
                    remote_ids,
                    false,
                );
            } else {
                for (id, filters) in &planned {
                    batch.outstanding_subs.insert(id.clone());
                    batch
                        .pagination_state
                        .insert(id.clone(), PaginationState::new(filters.clone()));
                }
            }
        }
        self.admit(
            planned
                .into_iter()
                .map(|(id, filters)| (id, filters, class))
                .collect(),
        )
        .await
    }

    async fn admit(
        &self,
        planned: Vec<(SubscriptionId, Vec<Filter>, TransientRequestClass)>,
    ) -> Result<(), String> {
        let mut cleanup = AdmissionCleanup {
            connection: self.connection.clone(),
            ids: planned.iter().map(|(id, _, _)| id.clone()).collect(),
        };
        for (id, filters, class) in planned {
            if let Err(error) = self
                .connection
                .subscribe_filters_with_id(filters, class, id)
                .await
            {
                // Finish retirement before retrying a prepared page with the
                // same wire ID. The drop guard covers cancellation mid-close.
                for id in &cleanup.ids {
                    self.connection.retire_subscription(id).await;
                }
                cleanup.ids.clear();
                return Err(error);
            }
        }
        cleanup.ids.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn policy_paused_pages_leave_global_capacity_for_healthy_relays() {
        let directory = tempfile::tempdir().unwrap();
        let purgatory = Arc::new(crate::purgatory::Purgatory::new(
            directory.path().to_owned(),
        ));
        let rejected = Arc::new(rejected_index::RejectedEventsIndex::new(
            Duration::from_secs(120),
            Duration::from_secs(86400),
        ));
        let health = Arc::new(RelayHealthTracker::with_defaults());
        let mut tasks = HistoryTasks::default();
        let (tx, mut rx) = tokio::sync::mpsc::channel(16);
        for number in 0..=MAX_ACTIVE_HISTORY_JOBS {
            let relay_url = format!("wss://relay{number}.example");
            let paused = number < MAX_ACTIVE_HISTORY_JOBS;
            if paused {
                health.record_policy_refusal(&relay_url);
            }
            tasks.spawn(
                HistoryJob {
                    connection: RelayConnection::new(
                        relay_url.clone(),
                        None,
                        RelayTargetSource::OperatorConfigured,
                        OutboundTargetPolicy::default(),
                    )
                    .with_health_tracker(health.clone()),
                    relay_url,
                    batch_id: number as u64,
                    barrier: SubscriptionId::generate(),
                    filters: Vec::new(),
                    allow_negentropy: false,
                    // Empty admission is valid for an already-up-to-date batch.
                    prepared: Some(Vec::new()),
                    wait_for_cooldown: true,
                    health: health.clone(),
                    pending: Arc::new(RwLock::new(HashMap::new())),
                    purgatory: purgatory.clone(),
                    rejected: rejected.clone(),
                },
                tx.clone(),
            );
        }
        let result = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("eight paused peers must not starve an unpaused history job")
            .unwrap();
        assert_eq!(result.batch_id, MAX_ACTIVE_HISTORY_JOBS as u64);
        assert!(result.outcome.is_ok());
        tasks.complete(&result.barrier);
        tokio::time::timeout(Duration::from_secs(2), async {
            while tasks
                .tasks
                .values()
                .any(|task| task.gate.available_permits() != 0)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(tasks.capacity.available_permits(), MAX_ACTIVE_HISTORY_JOBS);
        let gates: Vec<_> = tasks.tasks.values().map(|task| task.gate.clone()).collect();
        tasks.clear();
        tokio::time::timeout(Duration::from_secs(2), async {
            while gates.iter().any(|gate| gate.available_permits() != 1) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelling sleeping workers releases relay gates promptly");
        assert!(
            rx.try_recv().is_err(),
            "cancelled pages must not report stale completions"
        );
    }
}

//! Serialized blocking checkpoints with an explicit shutdown barrier.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::watch;
use tokio::task::JoinHandle;

pub(crate) struct CheckpointTask {
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}

impl CheckpointTask {
    pub(crate) fn start(interval: Duration, save: impl Fn() + Send + Sync + 'static) -> Self {
        let (stop, mut stopped) = watch::channel(false);
        let save = Arc::new(save);
        let task = tokio::spawn(async move {
            loop {
                // Schedule from completion: slow storage must not accumulate
                // overdue checkpoints or start overlapping snapshots.
                tokio::select! {
                    biased;
                    _ = stopped.changed() => break,
                    _ = tokio::time::sleep(interval) => {}
                }
                let save = save.clone();
                // Do not race shutdown against this join. Blocking tasks
                // cannot be aborted after they start, and an old snapshot
                // must never overwrite the final shutdown snapshot.
                if let Err(error) = tokio::task::spawn_blocking(move || save()).await {
                    tracing::error!(%error, "Checkpoint worker failed");
                }
            }
        });
        Self { stop, task }
    }

    pub(crate) async fn shutdown(self) {
        let _ = self.stop.send(true);
        let _ = self.task.await;
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{mpsc, Mutex};

    use futures_util::FutureExt;
    use tokio::sync::oneshot;

    use super::*;

    #[tokio::test]
    async fn blocking_checkpoint_yields_runtime_and_shutdown_joins_it() {
        let (started_tx, started_rx) = oneshot::channel();
        let started_tx = Mutex::new(Some(started_tx));
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Mutex::new(release_rx);
        let (finished_tx, finished_rx) = oneshot::channel();
        let finished_tx = Mutex::new(Some(finished_tx));
        let checkpoint = CheckpointTask::start(Duration::from_millis(1), move || {
            started_tx.lock().unwrap().take().unwrap().send(()).unwrap();
            // A bounded blocking I/O surrogate. The sole runtime thread must
            // remain free to send release; an inline checkpoint fails here.
            release_rx
                .lock()
                .unwrap()
                .recv_timeout(Duration::from_secs(5))
                .unwrap();
            finished_tx
                .lock()
                .unwrap()
                .take()
                .unwrap()
                .send(())
                .unwrap();
        });

        tokio::time::timeout(Duration::from_secs(5), started_rx)
            .await
            .unwrap()
            .unwrap();
        let shutdown = checkpoint.shutdown();
        tokio::pin!(shutdown);
        assert!(
            shutdown.as_mut().now_or_never().is_none(),
            "shutdown must join the active snapshot"
        );
        release_tx.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), shutdown)
            .await
            .unwrap();
        assert!(finished_rx.now_or_never().unwrap().is_ok());
    }

    #[tokio::test(start_paused = true)]
    async fn shutdown_cancels_a_checkpoint_that_has_not_started() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let saves = Arc::new(AtomicUsize::new(0));
        let worker_saves = saves.clone();
        let checkpoint = CheckpointTask::start(Duration::from_secs(60), move || {
            worker_saves.fetch_add(1, Ordering::SeqCst);
        });
        checkpoint.shutdown().await;
        tokio::time::advance(Duration::from_secs(120)).await;
        assert_eq!(saves.load(Ordering::SeqCst), 0);
    }
}

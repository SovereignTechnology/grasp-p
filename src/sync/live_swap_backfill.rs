//! The backfill after a minimum-churn swap of live coverage.
//!
//! Live filters carry `limit(0)` (`live_filter_groups`), so a live REQ
//! returns only what the relay stores after it reads that REQ. When coverage
//! grows, `RelayConnection::extend_live_filter_groups_minimally` CLOSEs the
//! groups it repacks and only then opens their replacement. An event the
//! relay stores between the two matches no subscription of ours, and the
//! callers of `sync_live` backfill only the coverage that is new, so such an
//! event waited for a reconnect or the daily full sync.
//!
//! [`SyncManager::backfill_live_groups_closed_by_swap`] therefore sends the
//! filters of every group a swap closed through upstream's own historic sync,
//! from shortly before the swap to shortly after it, with REQ+EOSE forced as
//! upstream's descendant baseline and fallback force it: the connection's
//! subscription ledger, its pacing and transient REQ cap, and the id and
//! signature check every synced event passes. The backfill opens no live
//! subscription and adds no filter, and a swap closes groups only when new
//! filters arrive, so there is never more than one backfill per swap.

use super::*;

/// How far before the swap the backfill reaches, in seconds.
///
/// `since` is compared with `created_at`, which the author's clock set before
/// the event reached the relay. The margin covers that delay and the
/// difference between the author's clock and ours. The same margin after the
/// swap bounds the window above, so events dated ahead of the clock are not
/// fetched again by every swap. Two minutes holds both with a wide margin
/// between synchronised clocks and keeps each backfill to a few minutes of
/// events, where swaps can follow each other every few seconds. An older
/// event that lands in the gap is still left to a reconnect or the daily sync.
const LIVE_SWAP_BACKFILL_OVERLAP_SECS: u64 = 120;

impl SyncManager {
    /// Backfill the core live groups that a swap on `connection` closed.
    ///
    /// `held_before` is the connection's live set read before the swap and
    /// `swap_started` the clock read just before it, so no CLOSE of the swap
    /// is earlier. A group was closed when its id is no longer held: a group
    /// the swap reopened with the same filters, or restored after a failure,
    /// has a new id and missed what arrived in between all the same.
    /// Descendant coverage (`protected`) takes no part in a swap and has a
    /// baseline of its own.
    pub(super) async fn backfill_live_groups_closed_by_swap(
        &mut self,
        relay_url: &str,
        connection: &RelayConnection,
        held_before: Vec<(SubscriptionId, Vec<Filter>)>,
        protected: &[SubscriptionId],
        swap_started: Timestamp,
    ) {
        let filters = closed_group_filters(held_before, protected, |id| {
            connection.holds_subscription_permit(id)
        });
        if filters.is_empty() {
            return;
        }
        let since = Timestamp::from(
            swap_started
                .as_secs()
                .saturating_sub(LIVE_SWAP_BACKFILL_OVERLAP_SECS),
        );
        // The swap is over, so what slipped through its gap reached the relay
        // about now at the latest; the same margin covers that delay and the
        // author's clock. Left open, every backfill would fetch again whatever
        // is dated ahead of the clock.
        let until = Timestamp::from(
            Timestamp::now()
                .as_secs()
                .saturating_add(LIVE_SWAP_BACKFILL_OVERLAP_SECS),
        );
        let filters: Vec<Filter> = filters
            .into_iter()
            .map(|filter| filter.until(until))
            .collect();
        tracing::info!(
            relay = %relay_url,
            filter_count = filters.len(),
            since = since.as_secs(),
            until = until.as_secs(),
            "Backfilling live coverage closed by a minimum-churn swap"
        );
        // A few minutes hold few events: about one paced REQ per closed group
        // costs the relay's query budget less than a NIP-77 round per filter,
        // which would also hold the relay's history order ahead of the
        // caller's own sync. Upstream's descendant baseline forces REQ+EOSE
        // the same way.
        self.historic_sync_with_options(
            relay_url,
            filters,
            PendingItems::default(),
            Some(since),
            PendingBatchPurpose::Core,
            true,
        )
        .await;
    }
}

/// The filters of the groups in `held_before` that are no longer open, once
/// each, without the live `limit(0)` and in a stable order.
fn closed_group_filters(
    held_before: Vec<(SubscriptionId, Vec<Filter>)>,
    protected: &[SubscriptionId],
    still_open: impl Fn(&SubscriptionId) -> bool,
) -> Vec<Filter> {
    let mut seen = HashSet::new();
    let mut filters: Vec<Filter> = held_before
        .into_iter()
        .filter(|(id, _)| !protected.contains(id) && !still_open(id))
        .flat_map(|(_, filters)| filters)
        .map(Filter::remove_limit)
        .filter(|filter| seen.insert(filter.as_json()))
        .collect();
    filters.sort_by_cached_key(|filter| filter.as_json());
    filters
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn closed_groups_are_found_by_id_and_lose_the_live_limit() {
        let first = Filter::new().kind(Kind::Custom(4_101));
        let second = Filter::new().kind(Kind::Custom(4_102));
        let kept = Filter::new().kind(Kind::Custom(4_103));
        let descendant = Filter::new().kind(Kind::Custom(4_104));
        let open = SubscriptionId::new("open");
        let auxiliary = SubscriptionId::new("auxiliary");
        let held_before = vec![
            (
                SubscriptionId::new("closed"),
                vec![second.clone().limit(0), first.clone().limit(0)],
            ),
            // The swap may reopen a group with exactly these filters, under a
            // new id: it was closed all the same, so content cannot tell.
            (
                SubscriptionId::new("reopened"),
                vec![first.clone().limit(0)],
            ),
            (open.clone(), vec![kept.limit(0)]),
            (auxiliary.clone(), vec![descendant.limit(0)]),
        ];

        let filters = closed_group_filters(held_before, &[auxiliary], |id| *id == open);

        let mut expected = [first, second];
        expected.sort_unstable_by_key(|filter| filter.as_json());
        assert_eq!(filters, expected);
    }

    #[derive(Debug)]
    enum Frame {
        Req { id: String, filters: Vec<Filter> },
        Close { id: String, stored: Option<EventId> },
        NegOpen,
    }

    /// A swap that CLOSEs a group and then opens its replacement, with the
    /// relay storing an event the group covered in between. Without the
    /// backfill only `limit(0)` REQs follow the CLOSE and the event is never
    /// sent, which is how an upstream live-sync test lost its third issue on
    /// a loaded runner.
    #[tokio::test]
    async fn event_stored_between_the_swaps_close_and_its_replacement_is_delivered() {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        fn opens_live(filters: &[Filter]) -> bool {
            filters.iter().all(|filter| filter.limit == Some(0))
        }

        let directory = tempfile::tempdir().unwrap();
        let mut config = Config::for_testing();
        config.git_data_path = directory.path().join("git").to_string_lossy().into_owned();
        config.relay_data_path = directory
            .path()
            .join("relay")
            .to_string_lossy()
            .into_owned();
        let git_path = PathBuf::from(&config.git_data_path);
        let purgatory = Arc::new(crate::purgatory::Purgatory::new(git_path.clone()));
        let runtime = crate::nostr::builder::create_relay(
            &config,
            purgatory,
            crate::grasp06::receive::RepoInitLocks::default(),
            None,
        )
        .await
        .unwrap();
        let mut manager = SyncManager::new(
            None,
            "service.example".into(),
            runtime.stores.database.clone(),
            runtime.write_policy,
            runtime.relay,
            &config,
            git_path,
            None,
            None,
            None,
        );
        let (history_tx, _history_rx) = tokio::sync::mpsc::channel(8);
        manager.history_result_tx = Some(history_tx);

        // A relay that keeps every REQ open until its CLOSE, answers stored
        // events matching a REQ without `limit(0)`, and pushes an event it
        // stores to the open subscriptions it matches. It reports each frame
        // before answering it, so the report is in when the answer arrives.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("ws://{}", listener.local_addr().unwrap());
        let (frames_tx, mut frames_rx) = tokio::sync::mpsc::unbounded_channel();
        let author = Keys::generate();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(socket).await.unwrap();
            let mut stored: Vec<Event> = Vec::new();
            let mut open: HashMap<String, (Vec<Filter>, bool)> = HashMap::new();
            let mut gap_filled = false;
            while let Some(Ok(frame)) = ws.next().await {
                if !frame.is_text() {
                    continue;
                }
                let message: serde_json::Value =
                    serde_json::from_str(frame.to_text().unwrap()).unwrap();
                let id = message[1].as_str().unwrap_or_default().to_owned();
                match message[0].as_str() {
                    Some("REQ") => {
                        let filters: Vec<Filter> = message.as_array().unwrap()[2..]
                            .iter()
                            .map(|filter| serde_json::from_value(filter.clone()).unwrap())
                            .collect();
                        let live = filters.iter().any(|filter| filter.limit == Some(0));
                        let _ = frames_tx.send(Frame::Req {
                            id: id.clone(),
                            filters: filters.clone(),
                        });
                        if !live {
                            for event in stored.iter().filter(|event| {
                                filters.iter().any(|filter| {
                                    filter.match_event(event, MatchEventOptions::new())
                                })
                            }) {
                                ws.send(Message::Text(
                                    serde_json::json!(["EVENT", id, event]).to_string().into(),
                                ))
                                .await
                                .unwrap();
                            }
                        }
                        ws.send(Message::Text(
                            serde_json::json!(["EOSE", id]).to_string().into(),
                        ))
                        .await
                        .unwrap();
                        open.insert(id, (filters, live));
                    }
                    Some("CLOSE") => {
                        let closed_live = open.remove(&id).is_some_and(|(_, live)| live);
                        if !closed_live || gap_filled {
                            let _ = frames_tx.send(Frame::Close { id, stored: None });
                            continue;
                        }
                        // Stored before the relay reads the next frame, the
                        // replacement REQ. Its filter was the closed group's.
                        gap_filled = true;
                        let event = EventBuilder::new(
                            Kind::Custom(4_001),
                            "stored while the swap was open",
                        )
                        .finalize(&author)
                        .unwrap();
                        let _ = frames_tx.send(Frame::Close {
                            id,
                            stored: Some(event.id),
                        });
                        for (subscription, (filters, _)) in &open {
                            if filters
                                .iter()
                                .any(|filter| filter.match_event(&event, MatchEventOptions::new()))
                            {
                                ws.send(Message::Text(
                                    serde_json::json!(["EVENT", subscription, event])
                                        .to_string()
                                        .into(),
                                ))
                                .await
                                .unwrap();
                            }
                        }
                        stored.push(event);
                    }
                    Some("NEG-OPEN") => {
                        let _ = frames_tx.send(Frame::NegOpen);
                    }
                    _ => {}
                }
            }
        });

        let connection = RelayConnection::new(
            url.clone(),
            None,
            RelayTargetSource::OperatorConfigured,
            OutboundTargetPolicy::default(),
        )
        .with_health_tracker(manager.health_tracker.clone());
        connection.connect(3).await.unwrap();
        connection.reset_subscription_budget(Some(8));
        let (events_tx, mut events_rx) = tokio::sync::mpsc::channel(100);
        let event_loop = tokio::spawn(connection.clone().run_event_loop(events_tx));
        manager.connections.insert(url.clone(), connection.clone());

        // One live group, then new coverage that the swap packs into it.
        let covered = Filter::new().kind(Kind::Custom(4_001));
        let added = Filter::new().kind(Kind::Custom(4_002));
        manager
            .sync_live(&url, std::slice::from_ref(&covered))
            .await
            .unwrap();
        let before_swap = Timestamp::now();
        manager
            .sync_live(&url, std::slice::from_ref(&added))
            .await
            .unwrap();
        let after_swap = Timestamp::now();

        let (delivered, delivered_on) = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                match events_rx.recv().await {
                    Some(RelayEvent::Event(event, subscription_id, _))
                        if event.kind == Kind::Custom(4_001) =>
                    {
                        break (*event, subscription_id);
                    }
                    Some(_) => {}
                    None => panic!("the connection's event loop ended"),
                }
            }
        })
        .await
        .expect("an event stored between the swap's CLOSE and its replacement must be delivered");

        let mut frames = Vec::new();
        while let Ok(frame) = frames_rx.try_recv() {
            frames.push(frame);
        }
        let (closed_at, closed_id, gap_event_id) = frames
            .iter()
            .enumerate()
            .find_map(|(index, frame)| match frame {
                Frame::Close {
                    id,
                    stored: Some(event_id),
                } => Some((index, id.clone(), *event_id)),
                _ => None,
            })
            .expect("the swap closed a live group");
        assert!(
            matches!(&frames[0], Frame::Req { id, filters }
                if *id == closed_id && *filters == [covered.clone().limit(0)]),
            "the swap closed the covered group: {frames:?}"
        );
        assert_eq!(delivered.id, gap_event_id);
        let replaced_at = frames
            .iter()
            .position(|frame| {
                matches!(frame, Frame::Req { filters, .. }
                    if opens_live(filters) && filters.len() == 2)
            })
            .expect("the swap opened a replacement carrying both filters");
        assert!(
            closed_at < replaced_at,
            "the gap needs the CLOSE first: {frames:?}"
        );

        // One bounded backfill of the closed group's filter, and nothing of
        // the new one: covering that is the caller's own historic sync.
        let backfills: Vec<_> = frames
            .iter()
            .filter_map(|frame| match frame {
                Frame::Req { id, filters } if !opens_live(filters) => Some((id, filters)),
                _ => None,
            })
            .collect();
        assert_eq!(backfills.len(), 1, "{frames:?}");
        assert!(
            !frames.iter().any(|frame| matches!(frame, Frame::NegOpen)),
            "the backfill is a paged REQ, not a NIP-77 round per filter: {frames:?}"
        );
        let (backfill_id, backfill) = backfills[0];
        assert_eq!(delivered_on, SubscriptionId::new(backfill_id));
        let since = backfill
            .first()
            .and_then(|filter| filter.since)
            .expect("the backfill is bounded below");
        let until = backfill
            .first()
            .and_then(|filter| filter.until)
            .expect("the backfill is bounded above");
        assert_eq!(*backfill, [covered.since(since).until(until)]);
        let earliest = before_swap
            .as_secs()
            .saturating_sub(LIVE_SWAP_BACKFILL_OVERLAP_SECS);
        let latest = after_swap
            .as_secs()
            .saturating_sub(LIVE_SWAP_BACKFILL_OVERLAP_SECS);
        assert!(
            (earliest..=latest).contains(&since.as_secs()),
            "since {} is not the swap minus the overlap ({earliest}..={latest})",
            since.as_secs()
        );
        let earliest_end = before_swap.as_secs() + LIVE_SWAP_BACKFILL_OVERLAP_SECS;
        let latest_end = after_swap.as_secs() + LIVE_SWAP_BACKFILL_OVERLAP_SECS;
        assert!(
            (earliest_end..=latest_end).contains(&until.as_secs()),
            "until {} is not the swap's end plus the overlap ({earliest_end}..={latest_end})",
            until.as_secs()
        );

        manager.shutdown().await;
        event_loop.abort();
        server.abort();
    }
}

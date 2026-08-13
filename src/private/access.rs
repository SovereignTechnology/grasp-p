use std::collections::HashSet;
use std::sync::{Arc, RwLock};

use nostr_sdk::prelude::PublicKey;
use tokio::sync::watch;

/// Live service-wide access list for a private GRASP instance.
///
/// The generation channel lets authenticated WebSocket sessions fail closed
/// when a later fleet/control-plane implementation changes membership.
#[derive(Clone, Debug)]
pub struct PrivateAccess {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    members: RwLock<HashSet<PublicKey>>,
    generation: watch::Sender<u64>,
}

impl PrivateAccess {
    pub fn new(members: impl IntoIterator<Item = PublicKey>) -> Self {
        let (generation, _) = watch::channel(0);
        Self {
            inner: Arc::new(Inner {
                members: RwLock::new(members.into_iter().collect()),
                generation,
            }),
        }
    }

    pub fn contains(&self, pubkey: &PublicKey) -> bool {
        self.inner
            .members
            .read()
            .expect("private access lock poisoned")
            .contains(pubkey)
    }

    pub fn len(&self) -> usize {
        self.inner
            .members
            .read()
            .expect("private access lock poisoned")
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Atomically replace membership and notify active sessions.
    pub fn replace(&self, members: impl IntoIterator<Item = PublicKey>) {
        *self
            .inner
            .members
            .write()
            .expect("private access lock poisoned") = members.into_iter().collect();
        let next = self.inner.generation.borrow().wrapping_add(1);
        self.inner.generation.send_replace(next);
    }

    pub fn subscribe(&self) -> watch::Receiver<u64> {
        self.inner.generation.subscribe()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::prelude::Keys;

    #[test]
    fn replacement_updates_membership() {
        let first = Keys::generate().public_key();
        let second = Keys::generate().public_key();
        let access = PrivateAccess::new([first]);
        let generation = access.subscribe();

        assert!(access.contains(&first));
        assert!(!access.contains(&second));

        access.replace([second]);
        assert!(!access.contains(&first));
        assert!(access.contains(&second));
        assert_eq!(*generation.borrow(), 1);
    }
}

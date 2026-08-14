//! Narrow GRASP-03 identity admission for accepted repository participants.

use std::collections::HashSet;
use std::sync::Arc;

use nostr_sdk::prelude::{Event, Kind, PublicKey};
use tokio::sync::RwLock;

pub type SharedProactiveParticipantAuthorIndex = Arc<ProactiveParticipantAuthorIndex>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdentityAdmission {
    Accept,
    IrrelevantAuthor,
    NotIdentity,
}

/// Derived admission set. Accepted repository threads remain authoritative;
/// an identity event can never add its own author here.
#[derive(Debug, Default)]
pub struct ProactiveParticipantAuthorIndex {
    authors: RwLock<HashSet<PublicKey>>,
}

impl ProactiveParticipantAuthorIndex {
    pub fn shared() -> SharedProactiveParticipantAuthorIndex {
        Arc::new(Self::default())
    }

    pub async fn replace(&self, authors: HashSet<PublicKey>) {
        *self.authors.write().await = authors;
    }

    pub async fn admit(&self, event: &Event) -> IdentityAdmission {
        if !matches!(event.kind, Kind::Metadata | Kind::RelayList) {
            return IdentityAdmission::NotIdentity;
        }
        if self.authors.read().await.contains(&event.pubkey) {
            IdentityAdmission::Accept
        } else {
            IdentityAdmission::IrrelevantAuthor
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nostr_sdk::prelude::{EventBuilder, FinalizeEvent, Keys};

    #[tokio::test]
    async fn identity_cannot_make_its_own_author_relevant() {
        let author = Keys::generate();
        let other = Keys::generate();
        let index = ProactiveParticipantAuthorIndex::shared();
        let metadata = EventBuilder::new(Kind::Metadata, "{}")
            .finalize(&author)
            .unwrap();
        assert_eq!(
            index.admit(&metadata).await,
            IdentityAdmission::IrrelevantAuthor
        );

        index.replace(HashSet::from([author.public_key()])).await;
        assert_eq!(index.admit(&metadata).await, IdentityAdmission::Accept);
        let unrelated = EventBuilder::new(Kind::RelayList, "")
            .finalize(&other)
            .unwrap();
        assert_eq!(
            index.admit(&unrelated).await,
            IdentityAdmission::IrrelevantAuthor
        );
        let note = EventBuilder::new(Kind::TextNote, "not identity")
            .finalize(&author)
            .unwrap();
        assert_eq!(index.admit(&note).await, IdentityAdmission::NotIdentity);
    }
}

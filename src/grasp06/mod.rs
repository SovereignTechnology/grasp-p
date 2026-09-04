//! GRASP-06 — Contributor Pull Request Submission.
//!
//! Spec: <https://gitworkshop.dev/danconwaydev.com/grasp/tree/master/06.md>
//! Design: `docs/explanation/grasp-06-contributor-pr-submission.md`
//!
//! This module is gated behind [`crate::config::Config::grasp06_enable`].
//! When disabled, `/prs/*` requests fall through to the standard 404 path.
//!
//! ## Current scope
//!
//! - URL parsing for `/prs/<npub>/<identifier>.git/<subpath>`.
//! - On-disk path conventions.
//! - Empty-bare-repo synthesis for `info/refs` and `git-upload-pack`.
//! - `git-receive-pack` accepting pushes to `refs/nostr/<event-id>` and
//!   rejecting any other ref namespace, with init-on-push and per-ref
//!   post-push validation against the database / purgatory.
//! - PR / PR-Update event acceptance relaxation for un-announced coords
//!   whose `clone` tag names this relay's `/prs/<signer-npub>/<d>.git`
//!   endpoint (06.md lines 19–22).
//!
//! Cross-service mirroring into matching announced repos is not yet
//! implemented.

pub mod cleanup;
pub mod endpoint;
pub mod fetch;
pub mod paths;
pub mod policy;
pub mod receive;

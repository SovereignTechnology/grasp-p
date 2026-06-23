//! Announcement cascade deletion implementation.
//!
//! `orchestration` contains the production NIP-09/blacklist/whitelist cascade
//! algorithm and the shared retention planner used by maintenance cleanup.

mod orchestration;

pub use orchestration::{plan_cascade_retention_for_deleted_announcements, CascadeRetentionPlan};

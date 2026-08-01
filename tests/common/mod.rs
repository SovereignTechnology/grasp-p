//! Common test utilities
#![allow(dead_code)] // Test helpers may not be used in all test configurations
#![allow(unused_imports)] // Re-exports may not be used in all test configurations

pub mod censoring_proxy;
pub mod git_server;
pub mod mock_relay;
pub mod nip09_helpers;
pub mod port;
pub mod purgatory_helpers;
pub mod relay;
pub mod sync_helpers;

pub use git_server::{SimpleGitServer, SmartGitServer};
pub use mock_relay::MockRelay;
pub use nip09_helpers::*;
pub use port::{reserve_port, PortReservation};
pub use purgatory_helpers::*;
pub use relay::{DeletionLifecycleOptions, TestRelay};
pub use sync_helpers::*;

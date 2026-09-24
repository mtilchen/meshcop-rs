//! Async commissioner client API.
//!
//! The public commissioner API is kept in this module while configuration,
//! public value types, event subscriptions, and the Tokio-backed session live
//! in smaller implementation modules.

mod client;
mod config;
mod events;
#[cfg(any(test, feature = "test-support"))]
pub mod harness;
mod joiner;
mod types;

pub use client::Commissioner;
pub use config::{CommissionerConfig, CommissionerConfigBuilder, KeepAlive};
pub use events::Events;
pub use joiner::{JoinerFinalizeInfo, JoinerHandler, StaticJoinerHandler, joiner_id_from_iid};
pub use types::{
    CloseReason, CommissionerDatasetFlags, CommissionerEvent, DatasetFlags, Destination,
    PetitionResponse, ResultCode, SessionStatus,
};

#[cfg(test)]
mod tests;

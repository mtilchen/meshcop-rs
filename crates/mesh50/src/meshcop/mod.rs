//! CoAP and MeshCoP message primitives.
//!
//! The network-diagnostic data model in [`diag`] is part of the public API
//! (it is surfaced through commissioner events). The CoAP codec, MeshCoP
//! request builders, response parsers, constants, and flag-mapping helpers are
//! lower-level protocol building blocks: they back the [`commissioner`] client
//! and are exported so the fuzz harnesses and advanced users can drive them
//! directly.
//!
//! [`commissioner`]: crate::commissioner

mod builders;
mod coap;
mod constants;
pub mod diag;
mod flags;
mod parsers;
mod types;
pub(crate) mod util;

pub use builders::{
    EnergyScanRequest, announce_begin_request, dataset_get_request, dataset_set_request,
    diagnostic_request, energy_scan_request, keep_alive_request, migrate_request,
    multicast_listener_request, pan_id_query_request, petition_request, relay_tx_request,
    relay_tx_request_with_kek, secure_pending_set_request, session_command_request, udp_tx_request,
};
pub use coap::{CoapCode, CoapMessage, CoapOption, CoapType};
pub use constants::*;
pub use diag::NetDiagData;
pub use flags::{
    active_dataset_tlv_types, commissioner_dataset_tlv_types, network_diag_tlv_types,
    pending_dataset_tlv_types,
};
pub use parsers::{
    UdpRx, parse_notification, parse_petition_response, parse_state, parse_state_response,
    parse_udp_rx,
};
pub use types::{
    CommissionerOperation, MeshcopNotification, MeshcopPetitionResponse, MeshcopState,
};

#[cfg(test)]
mod tests;

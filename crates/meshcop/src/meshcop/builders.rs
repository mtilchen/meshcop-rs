//! MeshCoP request builders.

use std::net::Ipv6Addr;

use crate::{
    Result,
    dataset::{ChannelMaskEntry, Dataset},
    error::Error,
};

use super::{
    coap::{CoapMessage, CoapType},
    constants::*,
    flags::network_diag_tlv_types,
    types::{CommissionerOperation, MeshcopState},
    util::{append_tlv, append_u8, append_u16, append_u32},
};

/// Creates a COMM_PET.req message.
pub fn petition_request(
    message_id: u16,
    token: impl Into<Vec<u8>>,
    commissioner_id: &str,
) -> Result<CoapMessage> {
    let mut payload = Vec::new();
    append_tlv(
        &mut payload,
        TLV_COMMISSIONER_ID,
        commissioner_id.as_bytes(),
    )?;
    CoapMessage::post_request(
        CoapType::Confirmable,
        message_id,
        token,
        uri::PETITIONING,
        payload,
    )
}

/// Creates a COMM_KA.req message.
pub fn keep_alive_request(
    message_id: u16,
    token: impl Into<Vec<u8>>,
    session_id: u16,
    keep_alive: bool,
) -> Result<CoapMessage> {
    let state = if keep_alive {
        MeshcopState::Accept
    } else {
        MeshcopState::Reject
    };
    let mut payload = Vec::new();
    append_tlv(&mut payload, TLV_STATE, &[state.to_wire()])?;
    append_u16(&mut payload, TLV_COMMISSIONER_SESSION_ID, session_id)?;
    CoapMessage::post_request(
        CoapType::Confirmable,
        message_id,
        token,
        uri::KEEP_ALIVE,
        payload,
    )
}

/// Creates a MeshCoP dataset get request.
pub fn dataset_get_request(
    operation: CommissionerOperation,
    message_id: u16,
    token: impl Into<Vec<u8>>,
    get_tlv_types: &[u8],
) -> Result<CoapMessage> {
    let mut payload = Vec::new();
    if !get_tlv_types.is_empty() {
        append_tlv(&mut payload, TLV_GET, get_tlv_types)?;
    }
    CoapMessage::post_request(
        CoapType::Confirmable,
        message_id,
        token,
        operation.uri_path(),
        payload,
    )
}

/// Creates a MeshCoP dataset set request.
pub fn dataset_set_request(
    operation: CommissionerOperation,
    message_id: u16,
    token: impl Into<Vec<u8>>,
    session_id: u16,
    dataset: &Dataset,
) -> Result<CoapMessage> {
    let mut payload = Vec::new();
    append_u16(&mut payload, TLV_COMMISSIONER_SESSION_ID, session_id)?;
    payload.extend_from_slice(&dataset.to_bytes()?);
    CoapMessage::post_request(
        CoapType::Confirmable,
        message_id,
        token,
        operation.uri_path(),
        payload,
    )
}

/// Creates an MGMT_SEC_PENDING_SET.req message.
pub fn secure_pending_set_request(
    message_id: u16,
    token: impl Into<Vec<u8>>,
    session_id: u16,
    max_retrieval_timer: u32,
    retrieval_uri: &str,
    dataset: &Dataset,
) -> Result<CoapMessage> {
    let mut secure_dissemination = Vec::new();
    if let Some(pending_timestamp) = dataset.pending_timestamp()? {
        secure_dissemination.extend_from_slice(&pending_timestamp.to_value());
    }
    secure_dissemination.extend_from_slice(&max_retrieval_timer.to_be_bytes());
    secure_dissemination.extend_from_slice(retrieval_uri.as_bytes());

    let mut payload = Vec::new();
    append_u16(&mut payload, TLV_COMMISSIONER_SESSION_ID, session_id)?;
    append_tlv(
        &mut payload,
        TLV_SECURE_DISSEMINATION,
        &secure_dissemination,
    )?;
    payload.extend_from_slice(&dataset.to_bytes()?);
    CoapMessage::post_request(
        CoapType::Confirmable,
        message_id,
        token,
        uri::MGMT_SEC_PENDING_SET,
        payload,
    )
}

/// Creates an MGMT_ANNOUNCE_BEGIN.ntf message.
pub fn announce_begin_request(
    message_id: u16,
    token: impl Into<Vec<u8>>,
    session_id: u16,
    channel_mask: u32,
    count: u8,
    period_ms: u16,
    confirmable: bool,
) -> Result<CoapMessage> {
    let mut payload = Vec::new();
    append_u16(&mut payload, TLV_COMMISSIONER_SESSION_ID, session_id)?;
    append_tlv(
        &mut payload,
        TLV_CHANNEL_MASK,
        &channel_mask_value(channel_mask)?,
    )?;
    append_u8(&mut payload, TLV_COUNT, count)?;
    append_u16(&mut payload, TLV_PERIOD, period_ms)?;
    CoapMessage::post_request(
        if confirmable {
            CoapType::Confirmable
        } else {
            CoapType::NonConfirmable
        },
        message_id,
        token,
        uri::MGMT_ANNOUNCE_BEGIN,
        payload,
    )
}

/// Creates an MGMT_PANID_QUERY.qry message.
pub fn pan_id_query_request(
    message_id: u16,
    token: impl Into<Vec<u8>>,
    session_id: u16,
    channel_mask: u32,
    pan_id: u16,
    confirmable: bool,
) -> Result<CoapMessage> {
    let mut payload = Vec::new();
    append_u16(&mut payload, TLV_COMMISSIONER_SESSION_ID, session_id)?;
    append_tlv(
        &mut payload,
        TLV_CHANNEL_MASK,
        &channel_mask_value(channel_mask)?,
    )?;
    append_u16(&mut payload, TLV_PAN_ID, pan_id)?;
    CoapMessage::post_request(
        if confirmable {
            CoapType::Confirmable
        } else {
            CoapType::NonConfirmable
        },
        message_id,
        token,
        uri::MGMT_PANID_QUERY,
        payload,
    )
}

/// Parameters for an MGMT_ED_SCAN.qry message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnergyScanRequest {
    /// Channel mask to scan.
    pub channel_mask: u32,
    /// Number of scan repetitions.
    pub count: u8,
    /// Period between scans in milliseconds.
    pub period_ms: u16,
    /// Scan duration in milliseconds.
    pub scan_duration_ms: u16,
    /// Whether to send the request as confirmable.
    pub confirmable: bool,
}

/// Creates an MGMT_ED_SCAN.qry message.
pub fn energy_scan_request(
    message_id: u16,
    token: impl Into<Vec<u8>>,
    session_id: u16,
    scan: EnergyScanRequest,
) -> Result<CoapMessage> {
    let mut payload = Vec::new();
    append_u16(&mut payload, TLV_COMMISSIONER_SESSION_ID, session_id)?;
    append_tlv(
        &mut payload,
        TLV_CHANNEL_MASK,
        &channel_mask_value(scan.channel_mask)?,
    )?;
    append_u8(&mut payload, TLV_COUNT, scan.count)?;
    append_u16(&mut payload, TLV_PERIOD, scan.period_ms)?;
    append_u16(&mut payload, TLV_SCAN_DURATION, scan.scan_duration_ms)?;
    CoapMessage::post_request(
        if scan.confirmable {
            CoapType::Confirmable
        } else {
            CoapType::NonConfirmable
        },
        message_id,
        token,
        uri::MGMT_ED_SCAN,
        payload,
    )
}

/// Creates a one-TLV session command such as reenroll or domain reset.
pub fn session_command_request(
    operation: CommissionerOperation,
    message_id: u16,
    token: impl Into<Vec<u8>>,
    session_id: u16,
    confirmable: bool,
) -> Result<CoapMessage> {
    let mut payload = Vec::new();
    append_u16(&mut payload, TLV_COMMISSIONER_SESSION_ID, session_id)?;
    CoapMessage::post_request(
        if confirmable {
            CoapType::Confirmable
        } else {
            CoapType::NonConfirmable
        },
        message_id,
        token,
        operation.uri_path(),
        payload,
    )
}

/// Creates an MGMT_NET_MIGRATE.req message.
pub fn migrate_request(
    message_id: u16,
    token: impl Into<Vec<u8>>,
    session_id: u16,
    designated_network: &str,
    confirmable: bool,
) -> Result<CoapMessage> {
    let mut payload = Vec::new();
    append_u16(&mut payload, TLV_COMMISSIONER_SESSION_ID, session_id)?;
    append_tlv(
        &mut payload,
        TLV_NETWORK_NAME,
        designated_network.as_bytes(),
    )?;
    CoapMessage::post_request(
        if confirmable {
            CoapType::Confirmable
        } else {
            CoapType::NonConfirmable
        },
        message_id,
        token,
        uri::MGMT_NET_MIGRATE,
        payload,
    )
}

/// Creates a DIAG_GET.qry or DIAG_RST.ntf message.
pub fn diagnostic_request(
    operation: CommissionerOperation,
    message_id: u16,
    token: impl Into<Vec<u8>>,
    diag_data_flags: u64,
    confirmable: bool,
) -> Result<CoapMessage> {
    let mut payload = Vec::new();
    append_tlv(
        &mut payload,
        NETWORK_DIAG_TLV_TYPE_LIST,
        &network_diag_tlv_types(diag_data_flags),
    )?;
    CoapMessage::post_request(
        if confirmable {
            CoapType::Confirmable
        } else {
            CoapType::NonConfirmable
        },
        message_id,
        token,
        operation.uri_path(),
        payload,
    )
}

/// Creates an MLR.req message.
pub fn multicast_listener_request(
    message_id: u16,
    token: impl Into<Vec<u8>>,
    session_id: u16,
    addresses: &[Ipv6Addr],
    timeout: u32,
) -> Result<CoapMessage> {
    if addresses.is_empty() {
        return Err(Error::Dataset(
            "multicast listener request needs at least one address".to_string(),
        ));
    }

    let mut raw_addresses = Vec::with_capacity(addresses.len() * 16);
    for address in addresses {
        if !address.is_multicast() {
            return Err(Error::Dataset(format!(
                "{address} is not an IPv6 multicast address"
            )));
        }
        raw_addresses.extend_from_slice(&address.octets());
    }

    let mut payload = Vec::new();
    append_u16(&mut payload, THREAD_TLV_COMMISSIONER_SESSION_ID, session_id)?;
    append_u32(&mut payload, THREAD_TLV_TIMEOUT, timeout)?;
    append_tlv(&mut payload, THREAD_TLV_IPV6_ADDRESSES, &raw_addresses)?;
    CoapMessage::post_request(CoapType::Confirmable, message_id, token, uri::MLR, payload)
}

/// Creates an RLY_TX.ntf message.
pub fn relay_tx_request(
    message_id: u16,
    token: impl Into<Vec<u8>>,
    joiner_iid: &[u8],
    joiner_udp_port: u16,
    joiner_router_locator: u16,
    payload: &[u8],
) -> Result<CoapMessage> {
    relay_tx_request_with_kek(
        message_id,
        token,
        joiner_iid,
        joiner_udp_port,
        joiner_router_locator,
        payload,
        None,
    )
}

/// Creates an RLY_TX.ntf message with an optional Joiner Router KEK TLV.
///
/// The KEK is attached to the relay transmission that carries the
/// JOIN_FIN.rsp so the joiner router can deliver JOIN_ENT.ntf security
/// material to the joiner.
pub fn relay_tx_request_with_kek(
    message_id: u16,
    token: impl Into<Vec<u8>>,
    joiner_iid: &[u8],
    joiner_udp_port: u16,
    joiner_router_locator: u16,
    payload: &[u8],
    joiner_router_kek: Option<&[u8; 16]>,
) -> Result<CoapMessage> {
    if joiner_iid.len() != 8 {
        return Err(Error::Dataset("joiner IID must be 8 bytes".to_string()));
    }
    let mut body = Vec::new();
    append_u16(&mut body, TLV_JOINER_UDP_PORT, joiner_udp_port)?;
    append_u16(&mut body, TLV_JOINER_ROUTER_LOCATOR, joiner_router_locator)?;
    append_tlv(&mut body, TLV_JOINER_IID, joiner_iid)?;
    append_tlv(&mut body, TLV_JOINER_DTLS_ENCAPSULATION, payload)?;
    if let Some(kek) = joiner_router_kek {
        append_tlv(&mut body, TLV_JOINER_ROUTER_KEK, kek)?;
    }
    CoapMessage::post_request(
        CoapType::NonConfirmable,
        message_id,
        token,
        uri::RELAY_TX,
        body,
    )
}

/// Creates a UDP_TX.ntf message encapsulating `inner` for `destination`.
///
/// The border agent forwards the encapsulated datagram from the commissioner
/// to `destination` on the Thread mesh, sourced from the Thread Management
/// port.
pub fn udp_tx_request(
    message_id: u16,
    token: impl Into<Vec<u8>>,
    destination: Ipv6Addr,
    destination_port: u16,
    inner: &[u8],
) -> Result<CoapMessage> {
    let mut encapsulation = Vec::with_capacity(4 + inner.len());
    encapsulation.extend_from_slice(&DEFAULT_MM_PORT.to_be_bytes());
    encapsulation.extend_from_slice(&destination_port.to_be_bytes());
    encapsulation.extend_from_slice(inner);

    let mut payload = Vec::new();
    append_tlv(&mut payload, TLV_IPV6_ADDRESS, &destination.octets())?;
    append_tlv(&mut payload, TLV_UDP_ENCAPSULATION, &encapsulation)?;
    CoapMessage::post_request(
        CoapType::NonConfirmable,
        message_id,
        token,
        uri::UDP_TX,
        payload,
    )
}
fn channel_mask_value(channel_mask: u32) -> Result<Vec<u8>> {
    if channel_mask == 0 {
        return Err(Error::Dataset("channel mask must not be zero".to_string()));
    }
    ChannelMaskEntry::encode_all(&[ChannelMaskEntry {
        page: 0,
        mask: channel_mask.to_be_bytes().to_vec(),
    }])
}

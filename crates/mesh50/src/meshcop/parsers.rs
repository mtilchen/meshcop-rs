//! MeshCoP response and notification parsers.

use std::net::Ipv6Addr;

use crate::{
    Result,
    dataset::ChannelMaskEntry,
    error::Error,
    tlv::{self, TlvSet},
};

use super::{
    coap::{CoapCode, CoapMessage},
    constants::*,
    diag::NetDiagData,
    types::{MeshcopNotification, MeshcopPetitionResponse, MeshcopState},
};

/// Decoded UDP_RX.ntf payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpRx {
    /// IPv6 source address of the proxied datagram.
    pub source_address: Ipv6Addr,
    /// UDP source port of the proxied datagram.
    pub source_port: u16,
    /// UDP destination port of the proxied datagram.
    pub destination_port: u16,
    /// Proxied datagram bytes.
    pub payload: Vec<u8>,
}

/// Parses a UDP_RX.ntf message, returning `None` for other resources.
pub fn parse_udp_rx(message: &CoapMessage) -> Result<Option<UdpRx>> {
    if message.uri_path()?.as_deref() != Some(uri::UDP_RX) {
        return Ok(None);
    }
    let tlvs = TlvSet::parse(&message.payload)?;
    let address = required_tlv(&tlvs, TLV_IPV6_ADDRESS, "IPv6 Address")?;
    let octets: [u8; 16] = address
        .try_into()
        .map_err(|_| Error::Dataset("IPv6 Address TLV must be 16 bytes".to_string()))?;
    let encapsulation = required_tlv(&tlvs, TLV_UDP_ENCAPSULATION, "UDP Encapsulation")?;
    if encapsulation.len() < 4 {
        return Err(Error::Dataset(
            "UDP Encapsulation TLV must carry source and destination ports".to_string(),
        ));
    }
    Ok(Some(UdpRx {
        source_address: Ipv6Addr::from(octets),
        source_port: u16::from_be_bytes([encapsulation[0], encapsulation[1]]),
        destination_port: u16::from_be_bytes([encapsulation[2], encapsulation[3]]),
        payload: encapsulation[4..].to_vec(),
    }))
}

/// Parses the State TLV in a MeshCoP response payload.
pub fn parse_state(payload: &[u8]) -> Result<Option<MeshcopState>> {
    let tlvs = TlvSet::parse(payload)?;
    tlvs.last_value(TLV_STATE)
        .map(|value| {
            if value.len() != 1 {
                return Err(Error::Dataset("State TLV must be 1 byte".to_string()));
            }
            MeshcopState::from_wire(value[0])
        })
        .transpose()
}

/// Checks a CoAP Changed response and parses an optional State TLV.
pub fn parse_state_response(
    response: &CoapMessage,
    state_mandatory: bool,
) -> Result<Option<MeshcopState>> {
    if response.code != CoapCode::CHANGED {
        return Err(Error::Dataset(format!(
            "expected CoAP Changed response, got 0x{:02x}",
            response.code.0
        )));
    }
    let state = parse_state(&response.payload)?;
    if state_mandatory && state.is_none() {
        return Err(Error::Dataset("missing MeshCoP State TLV".to_string()));
    }
    Ok(state)
}

/// Parses a COMM_PET.rsp payload.
pub fn parse_petition_response(response: &CoapMessage) -> Result<MeshcopPetitionResponse> {
    parse_state_response(response, true)?;
    let tlvs = TlvSet::parse(&response.payload)?;
    let state = parse_state(&response.payload)?
        .ok_or_else(|| Error::Dataset("missing petition State TLV".to_string()))?;
    let session_id = tlvs
        .last_value(TLV_COMMISSIONER_SESSION_ID)
        .map(tlv::read_u16)
        .transpose()?;
    let existing_commissioner_id = tlvs
        .last_value(TLV_COMMISSIONER_ID)
        .map(|value| {
            core::str::from_utf8(value)
                .map(str::to_owned)
                .map_err(|_| Error::Dataset("Commissioner ID TLV is not UTF-8".to_string()))
        })
        .transpose()?;

    Ok(MeshcopPetitionResponse {
        state,
        session_id,
        existing_commissioner_id,
    })
}

/// Parses a received request into a commissioner notification, when recognized.
pub fn parse_notification(message: &CoapMessage) -> Result<Option<MeshcopNotification>> {
    let Some(uri_path) = message.uri_path()? else {
        return Ok(None);
    };

    match uri_path.as_str() {
        uri::MGMT_DATASET_CHANGED => Ok(Some(MeshcopNotification::DatasetChanged)),
        uri::MGMT_PANID_CONFLICT => {
            let tlvs = TlvSet::parse(&message.payload)?;
            let channel_mask =
                channel_mask_from_value(required_tlv(&tlvs, TLV_CHANNEL_MASK, "Channel Mask")?)?;
            let pan_id = tlv::read_u16(required_tlv(&tlvs, TLV_PAN_ID, "PAN ID")?)?;
            Ok(Some(MeshcopNotification::PanIdConflict {
                channel_mask,
                pan_id,
            }))
        }
        uri::MGMT_ED_REPORT => {
            let tlvs = TlvSet::parse(&message.payload)?;
            let channel_mask = tlvs
                .last_value(TLV_CHANNEL_MASK)
                .map(channel_mask_from_value)
                .transpose()?
                .unwrap_or(0);
            let energy_list = tlvs
                .last_value(TLV_ENERGY_LIST)
                .unwrap_or_default()
                .to_vec();
            Ok(Some(MeshcopNotification::EnergyReport {
                channel_mask,
                energy_list,
            }))
        }
        uri::DIAG_GET_ANSWER => {
            let data = NetDiagData::decode(&message.payload)?;
            Ok(Some(MeshcopNotification::DiagGetAnswer {
                data: Box::new(data),
            }))
        }
        uri::RELAY_RX => {
            let tlvs = TlvSet::parse(&message.payload)?;
            let joiner_udp_port =
                tlv::read_u16(required_tlv(&tlvs, TLV_JOINER_UDP_PORT, "Joiner UDP Port")?)?;
            let joiner_router_locator = tlv::read_u16(required_tlv(
                &tlvs,
                TLV_JOINER_ROUTER_LOCATOR,
                "Joiner Router Locator",
            )?)?;
            let joiner_iid = read_array_8(required_tlv(&tlvs, TLV_JOINER_IID, "Joiner IID")?)?;
            let payload = required_tlv(
                &tlvs,
                TLV_JOINER_DTLS_ENCAPSULATION,
                "Joiner DTLS Encapsulation",
            )?
            .to_vec();
            Ok(Some(MeshcopNotification::RelayRx {
                joiner_udp_port,
                joiner_router_locator,
                joiner_iid,
                payload,
            }))
        }
        _ => Ok(None),
    }
}
fn channel_mask_from_value(value: &[u8]) -> Result<u32> {
    let entries = ChannelMaskEntry::parse_all(value)?;
    let mut page_zero_mask = None;
    for entry in entries {
        if entry.page == 0 {
            if entry.mask.len() != 4 {
                return Err(Error::Dataset(
                    "page-0 channel mask must be 4 bytes".to_string(),
                ));
            }
            let mask =
                u32::from_be_bytes([entry.mask[0], entry.mask[1], entry.mask[2], entry.mask[3]]);
            page_zero_mask = Some(page_zero_mask.unwrap_or(0) | mask);
        }
    }
    page_zero_mask.ok_or_else(|| Error::Dataset("no page-0 channel mask entry".to_string()))
}

fn required_tlv<'a>(tlvs: &'a TlvSet, ty: u8, name: &str) -> Result<&'a [u8]> {
    tlvs.last_value(ty)
        .ok_or_else(|| Error::Dataset(format!("missing {name} TLV")))
}

fn read_array_8(value: &[u8]) -> Result<[u8; 8]> {
    value
        .try_into()
        .map_err(|_| Error::Dataset(format!("expected 8 bytes, got {}", value.len())))
}

//! MeshCoP operation and response/event types.

use crate::{Result, error::Error};

use super::constants::uri;

/// MeshCoP command covered by the public commissioner API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommissionerOperation {
    /// COMM_PET.req.
    Petition,
    /// Commissioner keepalive/resign.
    KeepAlive,
    /// MGMT_COMMISSIONER_GET.req.
    GetCommissionerDataset,
    /// MGMT_COMMISSIONER_SET.req.
    SetCommissionerDataset,
    /// MGMT_ACTIVE_GET.req.
    GetActiveDataset,
    /// MGMT_ACTIVE_SET.req.
    SetActiveDataset,
    /// MGMT_PENDING_GET.req.
    GetPendingDataset,
    /// MGMT_PENDING_SET.req.
    SetPendingDataset,
    /// MGMT_SEC_PENDING_SET.req.
    SetSecurePendingDataset,
    /// MGMT_BBR_GET.req.
    GetBbrDataset,
    /// MGMT_BBR_SET.req.
    SetBbrDataset,
    /// MGMT_ANNOUNCE_BEGIN.ntf.
    AnnounceBegin,
    /// MGMT_PANID_QUERY.qry.
    PanIdQuery,
    /// MGMT_ED_SCAN.qry.
    EnergyScan,
    /// MLR.req.
    RegisterMulticastListener,
    /// MGMT_REENROLL.req.
    Reenroll,
    /// MGMT_DOMAIN_RESET.req.
    DomainReset,
    /// MGMT_NET_MIGRATE.req.
    Migrate,
    /// DIAG_GET.qry.
    DiagnosticGet,
    /// DIAG_GET.req (unicast; the response carries the diagnostic TLVs).
    DiagnosticGetUnicast,
    /// DIAG_RST.ntf.
    DiagnosticReset,
    /// Joiner relay payload.
    SendToJoiner,
}

impl CommissionerOperation {
    /// Returns the MeshCoP or Thread-management CoAP URI path for this operation.
    pub const fn uri_path(self) -> &'static str {
        match self {
            Self::Petition => uri::PETITIONING,
            Self::KeepAlive => uri::KEEP_ALIVE,
            Self::GetCommissionerDataset => uri::MGMT_COMMISSIONER_GET,
            Self::SetCommissionerDataset => uri::MGMT_COMMISSIONER_SET,
            Self::GetActiveDataset => uri::MGMT_ACTIVE_GET,
            Self::SetActiveDataset => uri::MGMT_ACTIVE_SET,
            Self::GetPendingDataset => uri::MGMT_PENDING_GET,
            Self::SetPendingDataset => uri::MGMT_PENDING_SET,
            Self::SetSecurePendingDataset => uri::MGMT_SEC_PENDING_SET,
            Self::GetBbrDataset => uri::MGMT_BBR_GET,
            Self::SetBbrDataset => uri::MGMT_BBR_SET,
            Self::AnnounceBegin => uri::MGMT_ANNOUNCE_BEGIN,
            Self::PanIdQuery => uri::MGMT_PANID_QUERY,
            Self::EnergyScan => uri::MGMT_ED_SCAN,
            Self::RegisterMulticastListener => uri::MLR,
            Self::Reenroll => uri::MGMT_REENROLL,
            Self::DomainReset => uri::MGMT_DOMAIN_RESET,
            Self::Migrate => uri::MGMT_NET_MIGRATE,
            Self::DiagnosticGet => uri::DIAG_GET_QUERY,
            Self::DiagnosticGetUnicast => uri::DIAG_GET_REQUEST,
            Self::DiagnosticReset => uri::DIAG_RESET,
            Self::SendToJoiner => uri::RELAY_TX,
        }
    }

    /// Returns the operation label used in unfinished transport errors.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Petition => "petition",
            Self::KeepAlive => "keep-alive",
            Self::GetCommissionerDataset => "get-commissioner-dataset",
            Self::SetCommissionerDataset => "set-commissioner-dataset",
            Self::GetActiveDataset => "get-active-dataset",
            Self::SetActiveDataset => "set-active-dataset",
            Self::GetPendingDataset => "get-pending-dataset",
            Self::SetPendingDataset => "set-pending-dataset",
            Self::SetSecurePendingDataset => "set-secure-pending-dataset",
            Self::GetBbrDataset => "get-bbr-dataset",
            Self::SetBbrDataset => "set-bbr-dataset",
            Self::AnnounceBegin => "announce-begin",
            Self::PanIdQuery => "pan-id-query",
            Self::EnergyScan => "energy-scan",
            Self::RegisterMulticastListener => "register-multicast-listener",
            Self::Reenroll => "command-reenroll",
            Self::DomainReset => "command-domain-reset",
            Self::Migrate => "command-migrate",
            Self::DiagnosticGet => "diagnostic-get",
            Self::DiagnosticGetUnicast => "diagnostic-get-unicast",
            Self::DiagnosticReset => "diagnostic-reset",
            Self::SendToJoiner => "send-to-joiner",
        }
    }
}

/// State value carried in a MeshCoP State TLV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeshcopState {
    /// Request rejected.
    Reject,
    /// Request pending.
    Pending,
    /// Request accepted.
    Accept,
}

impl MeshcopState {
    pub(crate) fn to_wire(self) -> u8 {
        match self {
            Self::Reject => 0xff,
            Self::Pending => 0x00,
            Self::Accept => 0x01,
        }
    }

    pub(crate) fn from_wire(value: u8) -> Result<Self> {
        match value {
            0xff => Ok(Self::Reject),
            0x00 => Ok(Self::Pending),
            0x01 => Ok(Self::Accept),
            _ => Err(Error::Dataset(
                "invalid MeshCoP State TLV value".to_string(),
            )),
        }
    }
}

/// Decoded petition response fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MeshcopPetitionResponse {
    /// Petition state.
    pub state: MeshcopState,
    /// Allocated commissioner session ID when accepted.
    pub session_id: Option<u16>,
    /// Existing commissioner ID when rejected by an active commissioner.
    pub existing_commissioner_id: Option<String>,
}

/// Unsolicited MeshCoP notification or answer that becomes a commissioner event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MeshcopNotification {
    /// MGMT_DATASET_CHANGED.ntf.
    DatasetChanged,
    /// DIAG_GET.ans.
    DiagGetAnswer {
        /// Decoded network diagnostic TLVs.
        data: Box<super::diag::NetDiagData>,
    },
    /// MGMT_PANID_CONFLICT.ans.
    PanIdConflict {
        /// 2.4 GHz page-0 channel mask.
        channel_mask: u32,
        /// Conflicting PAN ID.
        pan_id: u16,
    },
    /// MGMT_ED_REPORT.ans.
    EnergyReport {
        /// Optional 2.4 GHz page-0 channel mask; zero when absent.
        channel_mask: u32,
        /// Reported energy values.
        energy_list: Vec<u8>,
    },
    /// RLY_RX.ntf.
    RelayRx {
        /// Joiner UDP port.
        joiner_udp_port: u16,
        /// Joiner router locator.
        joiner_router_locator: u16,
        /// Joiner IID.
        joiner_iid: [u8; 8],
        /// Encapsulated DTLS records.
        payload: Vec<u8>,
    },
}

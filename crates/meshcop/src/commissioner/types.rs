//! Commissioner public types.

use crate::meshcop::NetDiagData;

/// Where a commissioner session stands.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionStatus {
    /// The DTLS session is up and the commissioner has not petitioned.
    Connected,
    /// A connect-only session was closed by the border agent. It is opened
    /// again, with a new DTLS handshake, when a request needs it.
    Idle,
    /// A petition is in flight.
    Petitioning,
    /// The petition was accepted.
    Active {
        /// Commissioner session ID allocated by the Leader.
        session_id: u16,
    },
    /// The session has ended; the handle can no longer be used.
    Closed {
        /// Why the session ended.
        reason: CloseReason,
    },
}

impl SessionStatus {
    /// Returns the commissioner session ID while the session is active.
    pub const fn session_id(&self) -> Option<u16> {
        match self {
            Self::Active { session_id } => Some(*session_id),
            _ => None,
        }
    }

    /// Returns whether the petition has been accepted and the session has not
    /// ended.
    pub const fn is_active(&self) -> bool {
        matches!(self, Self::Active { .. })
    }
}

/// Why a commissioner session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CloseReason {
    /// The application ended the session, by resigning or by dropping every
    /// [`super::Commissioner`] handle.
    Resigned,
    /// The border agent answered a keep-alive with Reject.
    KeepAliveRejected,
    /// The border agent answered a keep-alive with Pending.
    KeepAlivePending,
    /// A keep-alive exchange failed, for example by timing out.
    KeepAliveFailed {
        /// Description of the failure.
        error: String,
    },
    /// The border agent closed the DTLS session with `close_notify`.
    PeerClosed,
    /// Sending or receiving on the session failed.
    TransportFailed {
        /// Description of the failure.
        error: String,
    },
    /// The session's background task stopped without ending the session,
    /// because it panicked (for example in a [`super::JoinerHandler`]) or its
    /// runtime shut down. No [`CommissionerEvent::SessionLost`] is published
    /// for this reason; [`super::Commissioner::status`] reports it.
    TaskStopped,
}

impl core::fmt::Display for CloseReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Resigned => f.write_str("the application ended the session"),
            Self::KeepAliveRejected => f.write_str("a keep-alive was rejected"),
            Self::KeepAlivePending => f.write_str("a keep-alive was answered with Pending"),
            Self::KeepAliveFailed { error } => write!(f, "a keep-alive failed: {error}"),
            Self::PeerClosed => f.write_str("the border agent closed the DTLS session"),
            Self::TransportFailed { error } => write!(f, "the transport failed: {error}"),
            Self::TaskStopped => f.write_str("the session task stopped unexpectedly"),
        }
    }
}

/// Where a raw MeshCoP request is sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Destination {
    /// The border agent, directly over the commissioner DTLS session.
    BorderAgent,
    /// A mesh address, through the border agent's UDP_TX/UDP_RX proxy.
    Mesh {
        /// Destination IPv6 address on the Thread mesh.
        address: std::net::Ipv6Addr,
        /// Destination UDP port.
        port: u16,
    },
}

/// Events emitted by a commissioner session.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CommissionerEvent {
    /// The session ended for a reason other than the application ending it.
    SessionLost {
        /// Why the session ended.
        reason: CloseReason,
    },
    /// This subscriber fell behind and missed events.
    Lagged {
        /// Number of events that were dropped for this subscriber.
        missed: u64,
    },
    /// Keepalive response status.
    KeepAliveResponse(ResultCode),
    /// Dataset changed notification.
    DatasetChanged,
    /// PAN ID conflict report.
    PanIdConflict {
        /// Reporting peer address.
        peer_addr: String,
        /// Channel mask used for the scan.
        channel_mask: u32,
        /// Conflicting PAN ID.
        pan_id: u16,
    },
    /// Energy scan report.
    EnergyReport {
        /// Reporting peer address.
        peer_addr: String,
        /// Channel mask used for the scan.
        channel_mask: u32,
        /// Energy list in dBm.
        energy_list: Vec<u8>,
    },
    /// Raw joiner proxy payload.
    JoinerMessage {
        /// Joiner ID.
        joiner_id: Vec<u8>,
        /// Joiner UDP port.
        port: u16,
        /// Payload bytes.
        payload: Vec<u8>,
    },
    /// DIAG_GET.ans network diagnostic answer.
    DiagnosticAnswer {
        /// Reporting peer address.
        peer_addr: String,
        /// Decoded network diagnostic TLVs.
        data: Box<NetDiagData>,
    },
    /// A joiner completed its DTLS handshake with the commissioner.
    JoinerConnected {
        /// Joiner ID.
        joiner_id: [u8; 8],
    },
    /// A joiner's JOIN_FIN.req was answered.
    JoinerFinalized {
        /// Joiner ID.
        joiner_id: [u8; 8],
        /// Whether the joiner was accepted.
        accepted: bool,
        /// Vendor information from the request.
        info: super::joiner::JoinerFinalizeInfo,
    },
}

/// MeshCoP result status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResultCode {
    /// Accepted.
    Accept,
    /// Rejected.
    Reject,
    /// Pending.
    Pending,
}

/// Petition response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PetitionResponse {
    /// Allocated commissioner session ID.
    pub session_id: u16,
    /// Existing commissioner ID when the petition is rejected by an active commissioner.
    pub existing_commissioner_id: Option<String>,
}

impl_bitflag_newtype! {
    /// Active and pending operational dataset TLV flags used by MeshCoP get requests.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct DatasetFlags(u64);
    constants {
        /// Empty flag set.
        pub const EMPTY: Self = Self(0);
        /// All known flags set.
        pub const ALL: Self = Self(u64::MAX);
        /// Active dataset: Active Timestamp.
        pub const ACTIVE_TIMESTAMP: Self = Self(1 << 15);
        /// Active dataset: Channel.
        pub const CHANNEL: Self = Self(1 << 14);
        /// Active dataset: Channel Mask.
        pub const CHANNEL_MASK: Self = Self(1 << 13);
        /// Active dataset: Extended PAN ID.
        pub const EXTENDED_PAN_ID: Self = Self(1 << 12);
        /// Active dataset: Mesh-Local Prefix.
        pub const MESH_LOCAL_PREFIX: Self = Self(1 << 11);
        /// Active dataset: Network Key.
        pub const NETWORK_KEY: Self = Self(1 << 10);
        /// Active dataset: Network Name.
        pub const NETWORK_NAME: Self = Self(1 << 9);
        /// Active dataset: PAN ID.
        pub const PAN_ID: Self = Self(1 << 8);
        /// Active dataset: PSKc.
        pub const PSKC: Self = Self(1 << 7);
        /// Active dataset: Security Policy.
        pub const SECURITY_POLICY: Self = Self(1 << 6);
        /// Pending dataset: Delay Timer.
        pub const DELAY_TIMER: Self = Self(1 << 5);
        /// Pending dataset: Pending Timestamp.
        pub const PENDING_TIMESTAMP: Self = Self(1 << 4);
    }
    methods {
        /// Creates flags from raw bits.
        from_bits;
        /// Returns raw bits.
        bits;
        /// Returns whether every bit in `other` is set.
        contains(other: Self);
    }
    bit_ops;
}

impl_bitflag_newtype! {
    /// Commissioner dataset TLV flags used by MeshCoP commissioner and BBR get requests.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct CommissionerDatasetFlags(u64);
    constants {
        /// Empty flag set.
        pub const EMPTY: Self = Self(0);
        /// All known flags set.
        pub const ALL: Self = Self(u64::MAX);
        /// Border Agent Locator.
        pub const BORDER_AGENT_LOCATOR: Self = Self(1 << 15);
        /// Commissioner Session ID.
        pub const COMMISSIONER_SESSION_ID: Self = Self(1 << 14);
        /// Steering Data.
        pub const STEERING_DATA: Self = Self(1 << 13);
        /// AE Steering Data.
        pub const AE_STEERING_DATA: Self = Self(1 << 12);
        /// NMKP Steering Data.
        pub const NMKP_STEERING_DATA: Self = Self(1 << 11);
        /// Joiner UDP Port.
        pub const JOINER_UDP_PORT: Self = Self(1 << 10);
        /// AE UDP Port.
        pub const AE_UDP_PORT: Self = Self(1 << 9);
        /// NMKP UDP Port.
        pub const NMKP_UDP_PORT: Self = Self(1 << 8);
    }
    methods {
        /// Creates flags from raw bits.
        from_bits;
        /// Returns raw bits.
        bits;
        /// Returns whether every bit in `other` is set.
        contains(other: Self);
    }
    bit_ops;
}

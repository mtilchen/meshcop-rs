//! MeshCoP TLV and URI constants.

/// CoAP Uri-Path option number.
pub const COAP_OPTION_URI_PATH: u16 = 11;

/// CoAP Content-Format option number.
pub const COAP_OPTION_CONTENT_FORMAT: u16 = 12;

/// MeshCoP TLV: Border Agent Locator.
pub const TLV_BORDER_AGENT_LOCATOR: u8 = 9;
/// MeshCoP TLV: Commissioner ID.
pub const TLV_COMMISSIONER_ID: u8 = 10;
/// MeshCoP TLV: Commissioner Session ID.
pub const TLV_COMMISSIONER_SESSION_ID: u8 = 11;
/// MeshCoP TLV: Get.
pub const TLV_GET: u8 = 13;
/// MeshCoP TLV: Commissioner UDP port.
pub const TLV_COMMISSIONER_UDP_PORT: u8 = 15;
/// MeshCoP TLV: State.
pub const TLV_STATE: u8 = 16;
/// MeshCoP TLV: Joiner DTLS encapsulation.
pub const TLV_JOINER_DTLS_ENCAPSULATION: u8 = 17;
/// MeshCoP TLV: Joiner UDP port.
pub const TLV_JOINER_UDP_PORT: u8 = 18;
/// MeshCoP TLV: Joiner IID.
pub const TLV_JOINER_IID: u8 = 19;
/// MeshCoP TLV: Joiner router locator.
pub const TLV_JOINER_ROUTER_LOCATOR: u8 = 20;
/// MeshCoP TLV: Joiner router KEK.
pub const TLV_JOINER_ROUTER_KEK: u8 = 21;
/// MeshCoP TLV: Provisioning URL.
pub const TLV_PROVISIONING_URL: u8 = 32;
/// MeshCoP TLV: Vendor Name.
pub const TLV_VENDOR_NAME: u8 = 33;
/// MeshCoP TLV: Vendor Model.
pub const TLV_VENDOR_MODEL: u8 = 34;
/// MeshCoP TLV: Vendor SW Version.
pub const TLV_VENDOR_SW_VERSION: u8 = 35;
/// MeshCoP TLV: Vendor Data.
pub const TLV_VENDOR_DATA: u8 = 36;
/// MeshCoP TLV: Vendor Stack Version.
pub const TLV_VENDOR_STACK_VERSION: u8 = 37;
/// MeshCoP TLV: UDP Encapsulation.
pub const TLV_UDP_ENCAPSULATION: u8 = 48;
/// MeshCoP TLV: IPv6 Address.
pub const TLV_IPV6_ADDRESS: u8 = 49;
/// MeshCoP TLV: Network name.
pub const TLV_NETWORK_NAME: u8 = 3;
/// MeshCoP TLV: PAN ID.
pub const TLV_PAN_ID: u8 = 1;
/// MeshCoP TLV: Steering Data.
pub const TLV_STEERING_DATA: u8 = 8;
/// MeshCoP TLV: Channel mask.
pub const TLV_CHANNEL_MASK: u8 = 53;
/// MeshCoP TLV: Count.
pub const TLV_COUNT: u8 = 54;
/// MeshCoP TLV: Period.
pub const TLV_PERIOD: u8 = 55;
/// MeshCoP TLV: Scan duration.
pub const TLV_SCAN_DURATION: u8 = 56;
/// MeshCoP TLV: Energy list.
pub const TLV_ENERGY_LIST: u8 = 57;
/// MeshCoP TLV: Secure dissemination.
pub const TLV_SECURE_DISSEMINATION: u8 = 58;
/// MeshCoP TLV: AE Steering Data.
pub const TLV_AE_STEERING_DATA: u8 = 61;
/// MeshCoP TLV: NMKP Steering Data.
pub const TLV_NMKP_STEERING_DATA: u8 = 62;
/// MeshCoP TLV: AE UDP port.
pub const TLV_AE_UDP_PORT: u8 = 65;
/// MeshCoP TLV: NMKP UDP port.
pub const TLV_NMKP_UDP_PORT: u8 = 66;

/// Thread network-layer TLV: Status.
pub const THREAD_TLV_STATUS: u8 = 4;
/// Thread network-layer TLV: Timeout.
pub const THREAD_TLV_TIMEOUT: u8 = 11;
/// Thread network-layer TLV: IPv6 addresses.
pub const THREAD_TLV_IPV6_ADDRESSES: u8 = 14;
/// Thread network-layer TLV: Commissioner Session ID.
pub const THREAD_TLV_COMMISSIONER_SESSION_ID: u8 = 15;

/// Thread network-diagnostic TLV: Type List.
pub const NETWORK_DIAG_TLV_TYPE_LIST: u8 = 18;

/// Default Thread Management (MM) UDP port used by proxied MeshCoP requests.
pub const DEFAULT_MM_PORT: u16 = 61631;
/// Anycast locator (ALOC16) of the Thread Leader.
pub const LEADER_ALOC16: u16 = 0xfc00;
/// Anycast locator (ALOC16) of the Primary Backbone Router.
pub const PRIMARY_BBR_ALOC16: u16 = 0xfc38;

/// MeshCoP CoAP resources from the Thread commissioner profile.
pub mod uri {
    /// COMM_PET.req.
    pub const PETITIONING: &str = "/c/cp";
    /// COMM_KA.req.
    pub const KEEP_ALIVE: &str = "/c/ca";
    /// MGMT_COMMISSIONER_GET.req.
    pub const MGMT_COMMISSIONER_GET: &str = "/c/cg";
    /// MGMT_COMMISSIONER_SET.req.
    pub const MGMT_COMMISSIONER_SET: &str = "/c/cs";
    /// MGMT_BBR_GET.req.
    pub const MGMT_BBR_GET: &str = "/c/bg";
    /// MGMT_BBR_SET.req.
    pub const MGMT_BBR_SET: &str = "/c/bs";
    /// MGMT_ACTIVE_GET.req.
    pub const MGMT_ACTIVE_GET: &str = "/c/ag";
    /// MGMT_ACTIVE_SET.req.
    pub const MGMT_ACTIVE_SET: &str = "/c/as";
    /// MGMT_PENDING_GET.req.
    pub const MGMT_PENDING_GET: &str = "/c/pg";
    /// MGMT_PENDING_SET.req.
    pub const MGMT_PENDING_SET: &str = "/c/ps";
    /// MGMT_DATASET_CHANGED.ntf.
    pub const MGMT_DATASET_CHANGED: &str = "/c/dc";
    /// MGMT_ANNOUNCE_BEGIN.ntf.
    pub const MGMT_ANNOUNCE_BEGIN: &str = "/c/ab";
    /// MGMT_PANID_QUERY.qry.
    pub const MGMT_PANID_QUERY: &str = "/c/pq";
    /// MGMT_PANID_CONFLICT.ans.
    pub const MGMT_PANID_CONFLICT: &str = "/c/pc";
    /// MGMT_ED_SCAN.qry.
    pub const MGMT_ED_SCAN: &str = "/c/es";
    /// MGMT_ED_REPORT.ans.
    pub const MGMT_ED_REPORT: &str = "/c/er";
    /// MGMT_REENROLL.req.
    pub const MGMT_REENROLL: &str = "/c/re";
    /// MGMT_DOMAIN_RESET.req.
    pub const MGMT_DOMAIN_RESET: &str = "/c/rt";
    /// MGMT_NET_MIGRATE.req.
    pub const MGMT_NET_MIGRATE: &str = "/c/nm";
    /// MGMT_SEC_PENDING_SET.req.
    pub const MGMT_SEC_PENDING_SET: &str = "/c/sp";
    /// RLY_TX.ntf.
    pub const RELAY_TX: &str = "/c/tx";
    /// RLY_RX.ntf.
    pub const RELAY_RX: &str = "/c/rx";
    /// UDP_TX.ntf.
    pub const UDP_TX: &str = "/c/ut";
    /// UDP_RX.ntf.
    pub const UDP_RX: &str = "/c/ur";
    /// JOIN_FIN.req.
    pub const JOIN_FIN: &str = "/c/jf";
    /// DIAG_GET.req (unicast; the DIAG_GET.rsp carries the TLVs piggybacked).
    pub const DIAG_GET_REQUEST: &str = "/d/dg";
    /// DIAG_GET.qry (may be multicast; answers arrive separately at DIAG_GET.ans).
    pub const DIAG_GET_QUERY: &str = "/d/dq";
    /// DIAG_GET.ans.
    pub const DIAG_GET_ANSWER: &str = "/d/da";
    /// DIAG_RST.ntf.
    pub const DIAG_RESET: &str = "/d/dr";
    /// MLR.req.
    pub const MLR: &str = "/n/mr";
}

//! Joiner commissioning sessions over the border-agent relay.
//!
//! When a joiner attaches through a joiner router, its DTLS records reach the
//! commissioner encapsulated in RLY_RX.ntf messages. The commissioner acts as
//! a DTLS 1.2 server authenticated with EC J-PAKE over the joiner PSKd,
//! receives the JOIN_FIN.req over the established session, and answers with a
//! JOIN_FIN.rsp. Accepting the finalization attaches the Joiner Router KEK to
//! the relayed response, which signals the joiner router to entrust the
//! joiner with the network credentials (Thread 1.4 §8.4.5.1).
//!
//! [`JoinerSession`] is a runtime-neutral state machine: callers feed the
//! decapsulated relay payloads in and forward the produced datagrams back
//! through RLY_TX.ntf. [`crate::commissioner::Commissioner`] drives it from
//! its event loop.

use std::time::{Duration, Instant};

use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::{
    Result,
    error::Error,
    meshcop::{self, CoapCode, CoapMessage, CoapType},
    tlv::TlvSet,
};
use meshcop_dtls::{
    ContentType, DtlsCookieGenerator, DtlsRecord, HandshakeMessage, HandshakeType,
    HelloVerifyRequest, RecordProtectionKey, ThreadDtlsKeyMaterial, ThreadDtlsServerHandshake,
    open_aes_128_ccm_8_record, parse_unfragmented_handshake_messages, protect_aes_128_ccm_8_record,
};

/// The IID of a joiner is its randomized link-local interface identifier; the
/// joiner ID restores the universal/local bit.
const LOCAL_EXTERNAL_ADDR_MASK: u8 = 1 << 1;

/// How long a joiner session may live before it is swept: the maximum DTLS
/// handshake time plus the JOIN_FIN.req wait, matching the C++ reference.
pub(crate) const JOINER_SESSION_TIMEOUT: Duration = Duration::from_secs(60 + 20);

/// Returns the joiner ID for a relayed joiner IID.
pub fn joiner_id_from_iid(joiner_iid: &[u8; 8]) -> [u8; 8] {
    let mut joiner_id = *joiner_iid;
    joiner_id[0] ^= LOCAL_EXTERNAL_ADDR_MASK;
    joiner_id
}

/// Vendor and provisioning information carried by a JOIN_FIN.req.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinerFinalizeInfo {
    /// Vendor Name TLV.
    pub vendor_name: String,
    /// Vendor Model TLV.
    pub vendor_model: String,
    /// Vendor SW Version TLV.
    pub vendor_sw_version: String,
    /// Vendor Stack Version TLV bytes.
    pub vendor_stack_version: Vec<u8>,
    /// Provisioning URL TLV, when present.
    pub provisioning_url: Option<String>,
    /// Vendor Data TLV, when present.
    pub vendor_data: Option<Vec<u8>>,
}

/// Application decisions for joiner commissioning.
///
/// This is the event-driven analog of the C++ `CommissionerHandler` joiner
/// callbacks: credentials and finalization decisions are synchronous so the
/// relay exchange can be answered inline.
pub trait JoinerHandler: Send + core::fmt::Debug {
    /// Returns the PSKd for a joiner, or `None` to ignore it.
    fn joiner_pskd(&mut self, joiner_id: &[u8; 8]) -> Option<String>;

    /// Called when a joiner completes its DTLS handshake.
    fn on_joiner_connected(&mut self, joiner_id: &[u8; 8]) {
        let _ = joiner_id;
    }

    /// Decides whether a joiner's JOIN_FIN.req is accepted.
    fn on_joiner_finalize(&mut self, joiner_id: &[u8; 8], info: &JoinerFinalizeInfo) -> bool {
        let _ = (joiner_id, info);
        true
    }
}

/// [`JoinerHandler`] backed by a static table of enabled joiners.
///
/// Mirrors the joiner enablement model of the C++ `CommissionerApp`: joiners
/// can be enabled individually by joiner ID (or EUI-64) or collectively with
/// a wildcard PSKd. Every JOIN_FIN.req from an enabled joiner is accepted.
#[derive(Default)]
pub struct StaticJoinerHandler {
    wildcard_pskd: Option<Zeroizing<String>>,
    by_joiner_id: Vec<([u8; 8], Zeroizing<String>)>,
}

impl core::fmt::Debug for StaticJoinerHandler {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StaticJoinerHandler")
            .field(
                "wildcard_pskd",
                &self.wildcard_pskd.as_ref().map(|_| "<redacted>"),
            )
            .field("enabled_joiner_count", &self.by_joiner_id.len())
            .finish()
    }
}

impl StaticJoinerHandler {
    /// Creates an empty handler that ignores every joiner.
    pub fn new() -> Self {
        Self::default()
    }

    /// Enables every joiner with a shared PSKd.
    pub fn enable_all(&mut self, pskd: impl Into<String>) {
        self.wildcard_pskd = Some(Zeroizing::new(pskd.into()));
    }

    /// Enables one joiner by joiner ID.
    pub fn enable_joiner_id(&mut self, joiner_id: [u8; 8], pskd: impl Into<String>) {
        self.by_joiner_id.retain(|(id, _)| *id != joiner_id);
        self.by_joiner_id
            .push((joiner_id, Zeroizing::new(pskd.into())));
    }

    /// Enables one joiner by factory EUI-64.
    pub fn enable_eui64(&mut self, eui64: u64, pskd: impl Into<String>) {
        self.enable_joiner_id(crate::crypto::compute_joiner_id(eui64), pskd);
    }

    /// Disables a previously enabled joiner ID.
    pub fn disable_joiner_id(&mut self, joiner_id: &[u8; 8]) {
        self.by_joiner_id.retain(|(id, _)| id != joiner_id);
    }

    /// Disables the wildcard PSKd.
    pub fn disable_all(&mut self) {
        self.wildcard_pskd = None;
    }
}

impl JoinerHandler for StaticJoinerHandler {
    fn joiner_pskd(&mut self, joiner_id: &[u8; 8]) -> Option<String> {
        self.by_joiner_id
            .iter()
            .find(|(id, _)| id == joiner_id)
            .map(|(_, pskd)| pskd.as_str().to_owned())
            .or_else(|| {
                self.wildcard_pskd
                    .as_ref()
                    .map(|pskd| pskd.as_str().to_owned())
            })
    }
}

/// Output produced while feeding relayed joiner records into a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum JoinerSessionEvent {
    /// DTLS records to relay back through RLY_TX.ntf.
    Transmit {
        /// Encoded DTLS records forming one datagram.
        datagram: Vec<u8>,
        /// Whether the RLY_TX must carry the Joiner Router KEK TLV.
        include_kek: bool,
    },
    /// The joiner completed its DTLS handshake.
    Connected,
    /// The joiner sent JOIN_FIN.req and a decision was made.
    Finalized {
        /// Whether the joiner was accepted.
        accepted: bool,
        /// Vendor information from the request.
        info: JoinerFinalizeInfo,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JoinerSessionPhase {
    /// Waiting for a ClientHello carrying a valid cookie.
    AwaitingClientHello,
    /// Server flight sent; waiting for the client key exchange and Finished.
    AwaitingClientFlight,
    /// Handshake complete; waiting for JOIN_FIN.req.
    Connected,
    /// JOIN_FIN was answered.
    Finalized,
}

/// One in-progress joiner commissioning session.
#[derive(Debug)]
pub(crate) struct JoinerSession {
    joiner_id: [u8; 8],
    joiner_iid: [u8; 8],
    joiner_udp_port: u16,
    joiner_router_locator: u16,
    phase: JoinerSessionPhase,
    handshake: ThreadDtlsServerHandshake,
    cookie: DtlsCookieGenerator,
    key_material: Option<ThreadDtlsKeyMaterial>,
    /// Cached server flight so a retransmitted ClientHello can be answered.
    server_flight: Vec<u8>,
    epoch0_sequence: u64,
    epoch1_sequence: u64,
    saw_client_change_cipher_spec: bool,
    finalize_decision: Option<bool>,
    expires_at: Instant,
}

impl JoinerSession {
    /// Creates a session for one relayed joiner.
    pub(crate) fn new(
        joiner_iid: [u8; 8],
        joiner_udp_port: u16,
        joiner_router_locator: u16,
        pskd: &str,
        now: Instant,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Self {
        Self {
            joiner_id: joiner_id_from_iid(&joiner_iid),
            joiner_iid,
            joiner_udp_port,
            joiner_router_locator,
            phase: JoinerSessionPhase::AwaitingClientHello,
            handshake: ThreadDtlsServerHandshake::new(pskd.as_bytes(), rng),
            cookie: DtlsCookieGenerator::new(rng),
            key_material: None,
            server_flight: Vec::new(),
            epoch0_sequence: 0,
            epoch1_sequence: 0,
            saw_client_change_cipher_spec: false,
            finalize_decision: None,
            expires_at: now + JOINER_SESSION_TIMEOUT,
        }
    }

    /// Returns the joiner ID this session commissions.
    pub(crate) const fn joiner_id(&self) -> [u8; 8] {
        self.joiner_id
    }

    /// Returns the joiner IID used on the relay.
    pub(crate) const fn joiner_iid(&self) -> [u8; 8] {
        self.joiner_iid
    }

    /// Returns the joiner UDP port used on the relay.
    pub(crate) const fn joiner_udp_port(&self) -> u16 {
        self.joiner_udp_port
    }

    /// Returns the joiner router locator used on the relay.
    pub(crate) const fn joiner_router_locator(&self) -> u16 {
        self.joiner_router_locator
    }

    /// Returns whether this session is past its deadline.
    pub(crate) fn expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    /// Feeds one decapsulated relay payload into the session.
    pub(crate) fn receive(
        &mut self,
        encapsulated: &[u8],
        handler: &mut dyn JoinerHandler,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Vec<JoinerSessionEvent>> {
        let mut events = Vec::new();
        for record in DtlsRecord::parse_datagram(encapsulated)? {
            match (record.header.epoch, record.header.content_type) {
                (0, ContentType::Handshake) => {
                    for message in parse_unfragmented_handshake_messages(&record)? {
                        self.handle_plaintext_handshake(&message, &mut events, rng)?;
                    }
                }
                (0, ContentType::ChangeCipherSpec) => {
                    if record.payload != [1] {
                        return Err(Error::Crypto(
                            "invalid ChangeCipherSpec payload".to_string(),
                        ));
                    }
                    self.saw_client_change_cipher_spec = true;
                }
                (1, ContentType::Handshake) => {
                    self.handle_encrypted_handshake(&record, &mut events)?;
                }
                (1, ContentType::ApplicationData) => {
                    self.handle_application_data(&record, handler, &mut events)?;
                }
                (_, ContentType::Alert) => {
                    return Err(Error::Crypto(format!(
                        "joiner DTLS alert epoch={} seq={}",
                        record.header.epoch, record.header.sequence_number
                    )));
                }
                _ => {}
            }
        }
        Ok(events)
    }

    fn handle_plaintext_handshake(
        &mut self,
        message: &HandshakeMessage,
        events: &mut Vec<JoinerSessionEvent>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<()> {
        match (message.message_type, self.phase) {
            (HandshakeType::ClientHello, JoinerSessionPhase::AwaitingClientHello) => {
                let hello = meshcop_dtls::ClientHello::decode(&message.payload)?;
                if !self.cookie.verify(&hello.random, &hello.cookie) {
                    let verify = HandshakeMessage {
                        message_type: HandshakeType::HelloVerifyRequest,
                        message_seq: message.message_seq,
                        payload: HelloVerifyRequest {
                            server_version: meshcop_dtls::DTLS_1_2_VERSION,
                            cookie: self.cookie.cookie(&hello.random)?.to_vec(),
                        }
                        .encode()?,
                    };
                    let datagram = self.plaintext_record(verify.encode()?)?;
                    events.push(JoinerSessionEvent::Transmit {
                        datagram,
                        include_kek: false,
                    });
                    return Ok(());
                }

                self.handshake.handle_client_hello(message)?;
                let server_hello = self.handshake.build_server_hello(1)?;
                let key_exchange = self.handshake.build_server_key_exchange(2, rng)?;
                let hello_done = self.handshake.build_server_hello_done(3)?;
                let mut datagram = Vec::new();
                datagram.extend_from_slice(&self.plaintext_record(server_hello.encode()?)?);
                datagram.extend_from_slice(&self.plaintext_record(key_exchange.encode()?)?);
                datagram.extend_from_slice(&self.plaintext_record(hello_done.encode()?)?);
                self.server_flight = datagram.clone();
                self.phase = JoinerSessionPhase::AwaitingClientFlight;
                events.push(JoinerSessionEvent::Transmit {
                    datagram,
                    include_kek: false,
                });
                Ok(())
            }
            (HandshakeType::ClientHello, JoinerSessionPhase::AwaitingClientFlight) => {
                // The server flight was lost; repeat it for the retried hello.
                events.push(JoinerSessionEvent::Transmit {
                    datagram: self.server_flight.clone(),
                    include_kek: false,
                });
                Ok(())
            }
            (HandshakeType::ClientKeyExchange, JoinerSessionPhase::AwaitingClientFlight) => {
                self.handshake.handle_client_key_exchange(message)?;
                self.key_material = Some(self.handshake.derive_key_material()?);
                Ok(())
            }
            _ => Err(Error::Crypto(format!(
                "unexpected joiner handshake message {:?}",
                message.message_type
            ))),
        }
    }

    fn handle_encrypted_handshake(
        &mut self,
        record: &DtlsRecord,
        events: &mut Vec<JoinerSessionEvent>,
    ) -> Result<()> {
        if self.phase != JoinerSessionPhase::AwaitingClientFlight {
            return Ok(());
        }
        if !self.saw_client_change_cipher_spec {
            return Err(Error::Crypto(
                "joiner Finished arrived before ChangeCipherSpec".to_string(),
            ));
        }
        let plaintext = self.open_record(record)?;
        let plain_record = DtlsRecord::new(ContentType::Handshake, 1, 0, plaintext)?;
        for message in parse_unfragmented_handshake_messages(&plain_record)? {
            if message.message_type != HandshakeType::Finished {
                continue;
            }
            let key_material = self.key_material_required()?.clone();
            self.handshake
                .verify_client_finished(&message, &key_material)?;
            let server_finished = self.handshake.build_server_finished(4, &key_material)?;

            let mut datagram = self.plaintext_change_cipher_spec()?;
            let finished_record = protect_aes_128_ccm_8_record(
                ContentType::Handshake,
                1,
                self.epoch1_sequence,
                RecordProtectionKey::new(key_material.key_block.server_write_key),
                &key_material.key_block.server_write_iv,
                &server_finished.encode()?,
            )?;
            self.epoch1_sequence = self.epoch1_sequence.wrapping_add(1);
            datagram.extend_from_slice(&finished_record.encode()?);
            self.phase = JoinerSessionPhase::Connected;
            events.push(JoinerSessionEvent::Transmit {
                datagram,
                include_kek: false,
            });
            events.push(JoinerSessionEvent::Connected);
        }
        Ok(())
    }

    fn handle_application_data(
        &mut self,
        record: &DtlsRecord,
        handler: &mut dyn JoinerHandler,
        events: &mut Vec<JoinerSessionEvent>,
    ) -> Result<()> {
        if !matches!(
            self.phase,
            JoinerSessionPhase::Connected | JoinerSessionPhase::Finalized
        ) {
            return Err(Error::Crypto(
                "joiner application data before handshake completion".to_string(),
            ));
        }
        let plaintext = self.open_record(record)?;
        let request = CoapMessage::decode(&plaintext)?;
        if request.uri_path()?.as_deref() != Some(meshcop::uri::JOIN_FIN) {
            return Ok(());
        }
        let info = parse_join_fin(&request)?;
        let accepted = *self
            .finalize_decision
            .get_or_insert_with(|| handler.on_joiner_finalize(&self.joiner_id, &info));

        let mut payload = Vec::new();
        let state = if accepted {
            meshcop::MeshcopState::Accept
        } else {
            meshcop::MeshcopState::Reject
        };
        payload.extend_from_slice(&[meshcop::TLV_STATE, 1, state.to_wire()]);
        let response = CoapMessage {
            ty: CoapType::Acknowledgement,
            code: CoapCode::CHANGED,
            message_id: request.message_id,
            token: request.token.clone(),
            options: Vec::new(),
            payload,
        };
        let key_material = self.key_material_required()?;
        let response_record = protect_aes_128_ccm_8_record(
            ContentType::ApplicationData,
            1,
            self.epoch1_sequence,
            RecordProtectionKey::new(key_material.key_block.server_write_key),
            &key_material.key_block.server_write_iv,
            &response.encode()?,
        )?;
        self.epoch1_sequence = self.epoch1_sequence.wrapping_add(1);

        let first_decision = self.phase != JoinerSessionPhase::Finalized;
        self.phase = JoinerSessionPhase::Finalized;
        events.push(JoinerSessionEvent::Transmit {
            datagram: response_record.encode()?,
            // The KEK signals entrustment, so it accompanies accepting
            // responses only. (The C++ reference attaches it to rejecting
            // JOIN_FIN.rsp messages as well; the Thread spec ties the KEK to
            // an authenticated, accepted joiner.)
            include_kek: accepted,
        });
        if first_decision {
            events.push(JoinerSessionEvent::Finalized { accepted, info });
        }
        Ok(())
    }

    /// Derives the Joiner Router KEK once the handshake has key material.
    pub(crate) fn joiner_router_kek(&self) -> Result<[u8; 16]> {
        let key_material = self.key_material_required()?;
        self.handshake
            .derive_joiner_router_kek(key_material)
            .map_err(Error::from)
    }

    fn key_material_required(&self) -> Result<&ThreadDtlsKeyMaterial> {
        self.key_material
            .as_ref()
            .ok_or(Error::InvalidState("joiner key material is not derived"))
    }

    fn open_record(&self, record: &DtlsRecord) -> Result<Vec<u8>> {
        let key_material = self.key_material_required()?;
        open_aes_128_ccm_8_record(
            record,
            RecordProtectionKey::new(key_material.key_block.client_write_key),
            &key_material.key_block.client_write_iv,
        )
        .map_err(Error::from)
    }

    fn plaintext_record(&mut self, payload: Vec<u8>) -> Result<Vec<u8>> {
        let record = DtlsRecord::new(ContentType::Handshake, 0, self.epoch0_sequence, payload)?;
        self.epoch0_sequence = self.epoch0_sequence.wrapping_add(1);
        record.encode().map_err(Error::from)
    }

    fn plaintext_change_cipher_spec(&mut self) -> Result<Vec<u8>> {
        let record = DtlsRecord::new(
            ContentType::ChangeCipherSpec,
            0,
            self.epoch0_sequence,
            vec![1],
        )?;
        self.epoch0_sequence = self.epoch0_sequence.wrapping_add(1);
        record.encode().map_err(Error::from)
    }
}

impl JoinerFinalizeInfo {
    /// Parses the TLV payload of a JOIN_FIN.req.
    ///
    /// The State and vendor identification TLVs are mandatory; the
    /// provisioning URL and vendor data TLVs are optional (Thread 1.4 §8.4.4).
    pub fn from_payload(payload: &[u8]) -> Result<Self> {
        let tlvs = TlvSet::parse(payload)?;
        let required = |ty: u8, name: &str| {
            tlvs.last_value(ty)
                .ok_or_else(|| Error::Dataset(format!("JOIN_FIN.req missing {name} TLV")))
        };
        let utf8 = |value: &[u8], name: &str| {
            core::str::from_utf8(value)
                .map(str::to_owned)
                .map_err(|_| Error::Dataset(format!("JOIN_FIN.req {name} TLV is not UTF-8")))
        };

        required(meshcop::TLV_STATE, "State")?;
        let vendor_name = utf8(
            required(meshcop::TLV_VENDOR_NAME, "Vendor Name")?,
            "Vendor Name",
        )?;
        let vendor_model = utf8(
            required(meshcop::TLV_VENDOR_MODEL, "Vendor Model")?,
            "Vendor Model",
        )?;
        let vendor_sw_version = utf8(
            required(meshcop::TLV_VENDOR_SW_VERSION, "Vendor SW Version")?,
            "Vendor SW Version",
        )?;
        let vendor_stack_version =
            required(meshcop::TLV_VENDOR_STACK_VERSION, "Vendor Stack Version")?.to_vec();
        let provisioning_url = tlvs
            .last_value(meshcop::TLV_PROVISIONING_URL)
            .map(|value| utf8(value, "Provisioning URL"))
            .transpose()?;
        let vendor_data = tlvs
            .last_value(meshcop::TLV_VENDOR_DATA)
            .map(<[u8]>::to_vec);

        Ok(Self {
            vendor_name,
            vendor_model,
            vendor_sw_version,
            vendor_stack_version,
            provisioning_url,
            vendor_data,
        })
    }
}

/// Parses a JOIN_FIN.req message.
pub(crate) fn parse_join_fin(request: &CoapMessage) -> Result<JoinerFinalizeInfo> {
    JoinerFinalizeInfo::from_payload(&request.payload)
}

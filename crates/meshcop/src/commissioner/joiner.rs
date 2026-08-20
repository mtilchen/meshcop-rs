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
pub(crate) const MAX_DUPLICATE_FLIGHT_RETRANSMISSIONS: u8 = 4;

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

#[derive(Debug, Default)]
struct JoinerReplayWindow {
    newest_sequence: Option<u64>,
    seen: u64,
}

impl JoinerReplayWindow {
    fn has_seen(&self, sequence: u64) -> bool {
        let Some(newest) = self.newest_sequence else {
            return false;
        };
        if sequence > newest {
            return false;
        }
        let offset = newest - sequence;
        offset >= u64::BITS as u64 || ((self.seen >> offset) & 1) == 1
    }

    fn mark_seen(&mut self, sequence: u64) {
        match self.newest_sequence {
            None => {
                self.newest_sequence = Some(sequence);
                self.seen = 1;
            }
            Some(newest) if sequence > newest => {
                let shift = sequence - newest;
                self.seen = if shift >= u64::BITS as u64 {
                    1
                } else {
                    (self.seen << shift) | 1
                };
                self.newest_sequence = Some(sequence);
            }
            Some(newest) => {
                let offset = newest - sequence;
                if offset < u64::BITS as u64 {
                    self.seen |= 1 << offset;
                }
            }
        }
    }
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
    /// Cached handshake messages so retransmissions can use fresh records.
    accepted_client_hello: Option<HandshakeMessage>,
    accepted_client_key_exchange: Option<HandshakeMessage>,
    server_flight: Vec<DtlsRecord>,
    server_finished: Vec<u8>,
    server_flight_retransmissions: u8,
    server_finished_retransmissions: u8,
    replay_window: JoinerReplayWindow,
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
            accepted_client_hello: None,
            accepted_client_key_exchange: None,
            server_flight: Vec::new(),
            server_finished: Vec::new(),
            server_flight_retransmissions: 0,
            server_finished_retransmissions: 0,
            replay_window: JoinerReplayWindow::default(),
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
        let records = DtlsRecord::parse_datagram(encapsulated)?;
        let was_established = matches!(
            self.phase,
            JoinerSessionPhase::Connected | JoinerSessionPhase::Finalized
        );
        let mut events = Vec::new();
        if was_established
            && !self.server_finished.is_empty()
            && is_client_finished_flight(&records)
            && self.server_finished_retransmissions < MAX_DUPLICATE_FLIGHT_RETRANSMISSIONS
        {
            self.server_finished_retransmissions =
                self.server_finished_retransmissions.saturating_add(1);
            events.push(JoinerSessionEvent::Transmit {
                datagram: self.build_server_finished_flight()?,
                include_kek: false,
            });
        }

        for record in records {
            match (record.header.epoch, record.header.content_type) {
                (0, ContentType::Handshake) if !was_established => {
                    for message in parse_unfragmented_handshake_messages(&record)? {
                        self.handle_plaintext_handshake(
                            &message,
                            record.header.sequence_number,
                            &mut events,
                            rng,
                        )?;
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
                (0, ContentType::Alert)
                    if !matches!(
                        self.phase,
                        JoinerSessionPhase::Connected | JoinerSessionPhase::Finalized
                    ) =>
                {
                    return Err(Error::Crypto(format!(
                        "joiner DTLS alert epoch={} seq={}",
                        record.header.epoch, record.header.sequence_number
                    )));
                }
                (1, ContentType::Alert) => {
                    if let Ok(Some(plaintext)) = self.open_record(&record) {
                        return Err(Error::Crypto(format!(
                            "joiner DTLS alert epoch=1 seq={} level={} description={}",
                            record.header.sequence_number,
                            plaintext.first().copied().unwrap_or_default(),
                            plaintext.get(1).copied().unwrap_or_default()
                        )));
                    }
                }
                _ => {}
            }
        }
        Ok(events)
    }

    fn handle_plaintext_handshake(
        &mut self,
        message: &HandshakeMessage,
        record_sequence: u64,
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
                    let datagram = DtlsRecord::new(
                        ContentType::Handshake,
                        0,
                        record_sequence,
                        verify.encode()?,
                    )?
                    .encode()?;
                    events.push(JoinerSessionEvent::Transmit {
                        datagram,
                        include_kek: false,
                    });
                    return Ok(());
                }

                self.handshake.handle_client_hello(message)?;
                self.accepted_client_hello = Some(message.clone());
                self.epoch0_sequence = record_sequence;
                let server_message_sequence = message.message_seq;
                let server_hello = self.handshake.build_server_hello(server_message_sequence)?;
                let key_exchange = self
                    .handshake
                    .build_server_key_exchange(server_message_sequence.wrapping_add(1), rng)?;
                let hello_done = self
                    .handshake
                    .build_server_hello_done(server_message_sequence.wrapping_add(2))?;
                self.server_flight = vec![
                    self.plaintext_record(server_hello.encode()?)?,
                    self.plaintext_record(key_exchange.encode()?)?,
                    self.plaintext_record(hello_done.encode()?)?,
                ];
                let datagram = encode_records(&self.server_flight)?;
                self.phase = JoinerSessionPhase::AwaitingClientFlight;
                events.push(JoinerSessionEvent::Transmit {
                    datagram,
                    include_kek: false,
                });
                Ok(())
            }
            (HandshakeType::ClientHello, JoinerSessionPhase::AwaitingClientFlight) => {
                if self.accepted_client_hello.as_ref() == Some(message)
                    && self.server_flight_retransmissions < MAX_DUPLICATE_FLIGHT_RETRANSMISSIONS
                {
                    self.server_flight_retransmissions =
                        self.server_flight_retransmissions.saturating_add(1);
                    renumber_epoch_zero_flight(&mut self.server_flight, &mut self.epoch0_sequence);
                    events.push(JoinerSessionEvent::Transmit {
                        datagram: encode_records(&self.server_flight)?,
                        include_kek: false,
                    });
                }
                Ok(())
            }
            (HandshakeType::ClientKeyExchange, JoinerSessionPhase::AwaitingClientFlight) => {
                if self.accepted_client_key_exchange.as_ref() == Some(message) {
                    return Ok(());
                }
                self.handshake.handle_client_key_exchange(message)?;
                self.key_material = Some(self.handshake.derive_key_material()?);
                self.accepted_client_key_exchange = Some(message.clone());
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
        let Some(plaintext) = self.open_record(record)? else {
            return Ok(());
        };
        let plain_record = DtlsRecord::new(ContentType::Handshake, 1, 0, plaintext)?;
        for message in parse_unfragmented_handshake_messages(&plain_record)? {
            if message.message_type != HandshakeType::Finished {
                continue;
            }
            let key_material = self.key_material_required()?.clone();
            self.handshake
                .verify_client_finished(&message, &key_material)?;
            let server_message_sequence = self
                .accepted_client_hello
                .as_ref()
                .ok_or(Error::InvalidState("accepted ClientHello is missing"))?
                .message_seq;
            let server_finished = self
                .handshake
                .build_server_finished(server_message_sequence.wrapping_add(3), &key_material)?;
            self.server_finished = server_finished.encode()?;
            let datagram = self.build_server_finished_flight()?;
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
        let Some(plaintext) = self.open_record(record)? else {
            return Ok(());
        };
        self.server_finished.clear();
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

    fn open_record(&mut self, record: &DtlsRecord) -> Result<Option<Vec<u8>>> {
        if self.replay_window.has_seen(record.header.sequence_number) {
            return Ok(None);
        }
        let plaintext = {
            let key_material = self.key_material_required()?;
            open_aes_128_ccm_8_record(
                record,
                RecordProtectionKey::new(key_material.key_block.client_write_key),
                &key_material.key_block.client_write_iv,
            )?
        };
        self.replay_window.mark_seen(record.header.sequence_number);
        Ok(Some(plaintext))
    }

    fn plaintext_record(&mut self, payload: Vec<u8>) -> Result<DtlsRecord> {
        let record = DtlsRecord::new(ContentType::Handshake, 0, self.epoch0_sequence, payload)?;
        self.epoch0_sequence = self.epoch0_sequence.wrapping_add(1);
        Ok(record)
    }

    fn plaintext_change_cipher_spec(&mut self) -> Result<DtlsRecord> {
        let record = DtlsRecord::new(
            ContentType::ChangeCipherSpec,
            0,
            self.epoch0_sequence,
            vec![1],
        )?;
        self.epoch0_sequence = self.epoch0_sequence.wrapping_add(1);
        Ok(record)
    }

    fn build_server_finished_flight(&mut self) -> Result<Vec<u8>> {
        let key_material = self.key_material_required()?.clone();
        let change_cipher_spec = self.plaintext_change_cipher_spec()?;
        let finished = protect_aes_128_ccm_8_record(
            ContentType::Handshake,
            1,
            self.epoch1_sequence,
            RecordProtectionKey::new(key_material.key_block.server_write_key),
            &key_material.key_block.server_write_iv,
            &self.server_finished,
        )?;
        self.epoch1_sequence = self.epoch1_sequence.wrapping_add(1);
        encode_records(&[change_cipher_spec, finished])
    }
}

pub(crate) fn is_client_finished_flight(records: &[DtlsRecord]) -> bool {
    records.iter().any(
        |record| match (record.header.epoch, record.header.content_type) {
            (0, ContentType::Handshake) => {
                parse_unfragmented_handshake_messages(record).is_ok_and(|messages| {
                    messages
                        .iter()
                        .any(|message| message.message_type == HandshakeType::ClientKeyExchange)
                })
            }
            (1, ContentType::Handshake) => true,
            _ => false,
        },
    )
}

fn renumber_epoch_zero_flight(records: &mut [DtlsRecord], next_sequence: &mut u64) {
    for record in records {
        if record.header.epoch == 0 {
            record.header.sequence_number = take_record_sequence(next_sequence);
        }
    }
}

fn take_record_sequence(next_sequence: &mut u64) -> u64 {
    let sequence = *next_sequence;
    *next_sequence = next_sequence.wrapping_add(1);
    sequence
}

fn encode_records(records: &[DtlsRecord]) -> Result<Vec<u8>> {
    let mut datagram = Vec::new();
    for record in records {
        datagram.extend_from_slice(&record.encode()?);
    }
    Ok(datagram)
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

#[cfg(test)]
mod tests {
    use super::JoinerReplayWindow;

    #[test]
    fn replay_window_preserves_gaps_and_marks_older_sequences() {
        let mut window = JoinerReplayWindow::default();
        assert!(!window.has_seen(10));
        window.mark_seen(10);
        window.mark_seen(12);
        assert!(window.has_seen(10));
        assert!(!window.has_seen(11));
        assert!(window.has_seen(12));
        assert!(!window.has_seen(13));

        window.mark_seen(11);
        assert!(window.has_seen(10));
        assert!(window.has_seen(11));
        assert!(window.has_seen(12));
        window.mark_seen(10);
        assert!(window.has_seen(10));
        assert!(window.has_seen(12));
    }

    #[test]
    fn replay_window_handles_both_edges_of_its_bitmap() {
        let width = u64::BITS as u64;
        let mut window = JoinerReplayWindow::default();
        window.mark_seen(1);
        window.mark_seen(1 + width);
        assert!(window.has_seen(1 + width));
        assert!(window.has_seen(1));
        assert!(!window.has_seen(2));
        window.mark_seen(1);
        assert!(!window.has_seen(2));

        let mut nearby = JoinerReplayWindow::default();
        nearby.mark_seen(20);
        nearby.mark_seen(18);
        assert!(nearby.has_seen(18));
        assert!(!nearby.has_seen(19));
        assert!(nearby.has_seen(20));
    }
}

//! Runtime-neutral asynchronous DTLS record I/O.
//!
//! The driver uses [`embedded_nal_async::UnconnectedUdp`] because DTLS
//! servers must learn the sender of each datagram before committing handshake
//! state, and must send the stateless HelloVerifyRequest back to that sender.
//! Its explicit local and remote addresses model that exchange directly.
//! [`embedded_hal_async::delay::DelayNs`] supplies the timer future raced
//! against each receive. Both traits are executor-independent and are already
//! part of the embedded networking ecosystem. `embassy-net` 0.9 depends on
//! the same trait crate but does not currently implement `UnconnectedUdp` for
//! its raw `udp::UdpSocket`; an Embassy application therefore uses a local
//! newtype that forwards `send`/`receive_into` to `send_to`/`recv_from`.
//! The future ESP32-H2 demo is the intended home for that board-specific
//! adapter, socket buffers, and executor policy while this crate owns only
//! DTLS state.
//!
//! Tokio support uses small adapters for the same traits. Handshakes retain
//! each outbound flight and retransmit the same handshake messages in records
//! with fresh sequence numbers after an initial one-second timeout, doubling
//! the interval up to 60 seconds. The retransmission timer is armed once per
//! transmitted flight, so datagrams the handshake ignores cannot postpone it.
//! A duplicate of the peer's preceding flight triggers an immediate
//! retransmission, capped at four duplicate-triggered responses per wait to
//! bound reflection. The caller's timeout is an absolute deadline for the
//! complete handshake rather than a fresh allowance for every receive.
//! Handshake and receive methods clone the [`DelayNs`] value so an absolute
//! deadline and an inner receive/retransmission timer can remain live
//! concurrently; embedded timer adapters therefore need cheap, independent
//! `Clone` semantics and enough timer capacity for both futures.
//!
//! Datagrams that do not parse as DTLS records, and protected records that
//! fail authentication, are discarded (RFC 6347 §4.1.2.7) rather than ending
//! the association. The one exception is the peer's Finished during a
//! handshake: once the peer has switched cipher state, a Finished that fails
//! authentication means the two sides derived different keys, so it aborts the
//! handshake the way mbedTLS does instead of waiting for the deadline.

use alloc::{format, vec::Vec};
use core::{
    fmt,
    future::{Future, poll_fn},
    net::SocketAddr,
    pin::{Pin, pin},
    task::Poll,
    time::Duration,
};

pub use embedded_hal_async::delay::DelayNs;
pub use embedded_nal_async::UnconnectedUdp;

use crate::{
    ContentType, DtlsRecord, Error, RecordHeader, RecordProtectionKey, ReplayWindow,
    ThreadDtlsKeyMaterial, open_aes_128_ccm_8_record, protect_aes_128_ccm_8_record,
    util::dtls_trace,
};

/// Maximum UDP datagram accepted by the async drivers.
pub const MAX_DATAGRAM_SIZE: usize = 4096;

pub(crate) const INITIAL_RETRANSMIT_TIMEOUT: Duration = Duration::from_secs(1);
#[cfg(not(test))]
pub(crate) const DRIVER_INITIAL_RETRANSMIT_TIMEOUT: Duration = INITIAL_RETRANSMIT_TIMEOUT;
// Loopback state-machine tests exercise the same timer/backoff transitions at
// a smaller scale so mutation runs do not spend seconds sleeping per mutant.
#[cfg(test)]
pub(crate) const DRIVER_INITIAL_RETRANSMIT_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_RETRANSMIT_TIMEOUT: Duration = Duration::from_secs(60);
pub(crate) const MAX_DUPLICATE_RETRANSMISSIONS: u8 = 4;

/// Error produced by a runtime-neutral DTLS driver.
#[derive(Debug)]
pub enum DriverError<E> {
    /// DTLS framing, handshake, or cryptographic processing failed.
    Protocol(Error),
    /// The datagram transport failed.
    Transport(E),
    /// A DTLS operation did not complete before its supplied deadline.
    Timeout,
}

impl<E> From<Error> for DriverError<E> {
    fn from(error: Error) -> Self {
        Self::Protocol(error)
    }
}

impl<E: fmt::Display> fmt::Display for DriverError<E> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Protocol(error) => error.fmt(formatter),
            Self::Transport(error) => write!(formatter, "datagram transport error: {error}"),
            Self::Timeout => formatter.write_str("DTLS operation timed out"),
        }
    }
}

impl<E> core::error::Error for DriverError<E>
where
    E: core::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Protocol(error) => Some(error),
            Self::Transport(error) => Some(error),
            Self::Timeout => None,
        }
    }
}

/// Runtime-neutral result returned by async DTLS drivers.
pub type DriverResult<T, E> = core::result::Result<T, DriverError<E>>;

#[derive(Debug, Clone, Copy)]
pub(crate) struct RetransmitSchedule {
    timeout: Duration,
}

impl RetransmitSchedule {
    pub(crate) const fn new() -> Self {
        Self {
            timeout: DRIVER_INITIAL_RETRANSMIT_TIMEOUT,
        }
    }

    #[cfg(test)]
    const fn with_initial(timeout: Duration) -> Self {
        Self { timeout }
    }

    pub(crate) const fn timeout(self) -> Duration {
        self.timeout
    }

    pub(crate) fn back_off(&mut self) {
        self.timeout = self.timeout.saturating_mul(2).min(MAX_RETRANSMIT_TIMEOUT);
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct DuplicateRetransmitBudget {
    used: u8,
}

impl DuplicateRetransmitBudget {
    pub(crate) const fn new() -> Self {
        Self { used: 0 }
    }

    pub(crate) fn take(&mut self) -> bool {
        if self.used >= MAX_DUPLICATE_RETRANSMISSIONS {
            return false;
        }
        self.used = self.used.saturating_add(1);
        true
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum SessionRole {
    Client,
    Server,
}

#[derive(Debug)]
pub(crate) struct SessionState {
    key_material: ThreadDtlsKeyMaterial,
    role: SessionRole,
    next_application_sequence: u64,
    application_replay: ReplayWindow,
}

impl SessionState {
    /// Builds a session whose own Finished already used epoch-1 sequence 0.
    #[cfg(any(test, feature = "tokio"))]
    pub(crate) fn new(key_material: ThreadDtlsKeyMaterial, role: SessionRole) -> Self {
        Self::with_next_application_sequence(key_material, role, 1)
    }

    pub(crate) fn during_handshake(key_material: ThreadDtlsKeyMaterial, role: SessionRole) -> Self {
        Self::with_next_application_sequence(key_material, role, 0)
    }

    fn with_next_application_sequence(
        key_material: ThreadDtlsKeyMaterial,
        role: SessionRole,
        next_application_sequence: u64,
    ) -> Self {
        Self {
            key_material,
            role,
            next_application_sequence,
            application_replay: ReplayWindow::new(),
        }
    }

    pub(crate) const fn key_material(&self) -> &ThreadDtlsKeyMaterial {
        &self.key_material
    }

    pub(crate) fn protect_application_data(
        &mut self,
        plaintext: &[u8],
    ) -> crate::Result<DtlsRecord> {
        self.protect_record(ContentType::ApplicationData, plaintext)
    }

    pub(crate) fn protect_record(
        &mut self,
        content_type: ContentType,
        plaintext: &[u8],
    ) -> crate::Result<DtlsRecord> {
        let (key, iv) = match self.role {
            SessionRole::Client => (
                self.key_material.key_block.client_write_key,
                self.key_material.key_block.client_write_iv,
            ),
            SessionRole::Server => (
                self.key_material.key_block.server_write_key,
                self.key_material.key_block.server_write_iv,
            ),
        };
        let record = protect_aes_128_ccm_8_record(
            content_type,
            1,
            self.next_application_sequence,
            RecordProtectionKey::new(key),
            &iv,
            plaintext,
        )?;
        self.next_application_sequence = self.next_application_sequence.wrapping_add(1);
        Ok(record)
    }

    /// Opens one epoch-1 record from the peer.
    ///
    /// Returns `Ok(None)` for a replayed record and an error when the record
    /// fails authentication; only authenticated records advance the window.
    pub(crate) fn open_protected_record(
        &mut self,
        record: &DtlsRecord,
    ) -> crate::Result<Option<Vec<u8>>> {
        if self
            .application_replay
            .has_seen(record.header.sequence_number)
        {
            return Ok(None);
        }
        let (key, iv) = match self.role {
            SessionRole::Client => (
                self.key_material.key_block.server_write_key,
                self.key_material.key_block.server_write_iv,
            ),
            SessionRole::Server => (
                self.key_material.key_block.client_write_key,
                self.key_material.key_block.client_write_iv,
            ),
        };
        let plaintext = open_aes_128_ccm_8_record(record, RecordProtectionKey::new(key), &iv)?;
        self.application_replay
            .mark_seen(record.header.sequence_number);
        Ok(Some(plaintext))
    }

    /// Opens the protected records of one established-session datagram.
    ///
    /// Returns the first authenticated application-data plaintext, or the
    /// error for an authenticated alert. Unauthenticated, replayed, and
    /// non-application records are discarded, yielding `None` when nothing in
    /// the datagram is usable.
    pub(crate) fn open_session_datagram(
        &mut self,
        records: &[DtlsRecord],
    ) -> Option<crate::Result<Vec<u8>>> {
        for record in records {
            if record.header.epoch != 1 {
                continue;
            }
            let is_alert = match record.header.content_type {
                ContentType::ApplicationData => false,
                ContentType::Alert => true,
                _ => continue,
            };
            let Ok(Some(plaintext)) = self.open_protected_record(record) else {
                continue;
            };
            return Some(if is_alert {
                Err(decode_authenticated_alert(&record.header, &plaintext))
            } else {
                Ok(plaintext)
            });
        }
        None
    }
}

pub(crate) async fn send_records<U>(
    transport: &mut U,
    local: SocketAddr,
    remote: SocketAddr,
    records: &[DtlsRecord],
) -> DriverResult<(), U::Error>
where
    U: UnconnectedUdp,
{
    let datagram = DtlsRecord::encode_datagram(records)?;
    transport
        .send(local, remote, &datagram)
        .await
        .map_err(DriverError::Transport)
}

#[cfg(test)]
pub(crate) async fn recv_records<U, D>(
    transport: &mut U,
    delay: &mut D,
    duration: Duration,
) -> DriverResult<(Vec<DtlsRecord>, SocketAddr, SocketAddr), U::Error>
where
    U: UnconnectedUdp,
    D: DelayNs,
{
    with_timeout(recv_records_unbounded(transport), delay, duration).await
}

/// Receives the next parseable datagram from `peer`, or times out when
/// `expiry` completes first.
///
/// Handshake loops pass the retransmission timer armed for their last
/// transmitted flight, so the time spent on ignored datagrams still counts
/// toward it.
pub(crate) async fn recv_records_before<U, T>(
    transport: &mut U,
    peer: SocketAddr,
    expiry: Pin<&mut T>,
) -> DriverResult<(Vec<DtlsRecord>, SocketAddr, SocketAddr), U::Error>
where
    U: UnconnectedUdp,
    T: Future<Output = ()>,
{
    race_expiry(recv_records_from_unbounded(transport, peer), expiry).await
}

pub(crate) async fn recv_records_from_unbounded<U>(
    transport: &mut U,
    peer: SocketAddr,
) -> DriverResult<(Vec<DtlsRecord>, SocketAddr, SocketAddr), U::Error>
where
    U: UnconnectedUdp,
{
    recv_parsed_datagram(transport, Some(peer)).await
}

pub(crate) async fn recv_records_unbounded<U>(
    transport: &mut U,
) -> DriverResult<(Vec<DtlsRecord>, SocketAddr, SocketAddr), U::Error>
where
    U: UnconnectedUdp,
{
    recv_parsed_datagram(transport, None).await
}

/// Receives datagrams until one from `peer` (or from anyone when `None`)
/// parses as DTLS records, discarding everything else.
async fn recv_parsed_datagram<U>(
    transport: &mut U,
    peer: Option<SocketAddr>,
) -> DriverResult<(Vec<DtlsRecord>, SocketAddr, SocketAddr), U::Error>
where
    U: UnconnectedUdp,
{
    let mut buffer = [0u8; MAX_DATAGRAM_SIZE];
    loop {
        let (length, local, remote) = transport
            .receive_into(&mut buffer)
            .await
            .map_err(DriverError::Transport)?;
        if peer.is_some_and(|peer| peer != remote) {
            continue;
        }
        // A transport reports the full length of a datagram it truncated.
        let Some(datagram) = buffer.get(..length) else {
            dtls_trace(format_args!(
                "drop oversized datagram from {remote} len={length}"
            ));
            continue;
        };
        match DtlsRecord::parse_datagram(datagram) {
            Ok(records) => return Ok((records, local, remote)),
            Err(error) => dtls_trace(format_args!(
                "drop malformed datagram from {remote}: {error}"
            )),
        }
    }
}

pub(crate) async fn recv_application_data<U, D>(
    state: &mut SessionState,
    transport: &mut U,
    delay: &D,
    peer: SocketAddr,
    duration: Duration,
) -> DriverResult<Vec<u8>, U::Error>
where
    U: UnconnectedUdp,
    D: DelayNs + Clone,
{
    let receive = async {
        loop {
            let (records, _, _) = recv_records_from_unbounded(transport, peer).await?;
            if let Some(result) = state.open_session_datagram(&records) {
                return result.map_err(DriverError::from);
            }
        }
    };
    with_timeout(receive, delay.clone(), duration).await
}

/// TLS `close_notify` alert description (RFC 5246 §7.2.1).
const ALERT_CLOSE_NOTIFY: u8 = 0;

/// Converts an authenticated alert from an established session into an
/// error, reporting an orderly `close_notify` as [`Error::PeerClosed`].
fn decode_authenticated_alert(header: &RecordHeader, payload: &[u8]) -> Error {
    match payload {
        [_, ALERT_CLOSE_NOTIFY, ..] => Error::PeerClosed,
        _ => decode_alert_error(header, payload),
    }
}

/// Converts a received alert's header and plaintext into an error.
pub(crate) fn decode_alert_error(header: &RecordHeader, payload: &[u8]) -> Error {
    match payload {
        [level, description, ..] => Error::Crypto(format!(
            "DTLS alert epoch={} seq={} level={level} description={description}",
            header.epoch, header.sequence_number
        )),
        _ => Error::Crypto(format!(
            "DTLS alert epoch={} seq={} received",
            header.epoch, header.sequence_number
        )),
    }
}

pub(crate) async fn with_timeout<F, D, T, E>(
    future: F,
    delay: D,
    duration: Duration,
) -> DriverResult<T, E>
where
    F: Future<Output = DriverResult<T, E>>,
    D: DelayNs,
{
    race_expiry(future, pin!(sleep(delay, duration))).await
}

/// Completes with `future`'s output, or with [`DriverError::Timeout`] once
/// `expiry` completes first. The expiry is borrowed so a caller can keep one
/// timer running across several operations.
async fn race_expiry<F, T, E, X>(future: F, mut expiry: Pin<&mut X>) -> DriverResult<T, E>
where
    F: Future<Output = DriverResult<T, E>>,
    X: Future<Output = ()>,
{
    let mut future = pin!(future);
    poll_fn(|context| {
        if let Poll::Ready(result) = future.as_mut().poll(context) {
            return Poll::Ready(result);
        }
        if expiry.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(DriverError::Timeout));
        }
        Poll::Pending
    })
    .await
}

/// Sleeps for `duration` on an owned timer handle.
///
/// Handshake loops pin one of these per transmitted flight and replace it
/// only after retransmitting.
pub(crate) async fn sleep<D: DelayNs>(mut delay: D, duration: Duration) {
    delay_duration(&mut delay, duration).await;
}

async fn delay_duration(delay: &mut impl DelayNs, duration: Duration) {
    const MAX_DELAY_NANOSECONDS: u128 = u32::MAX as u128;

    let nanoseconds = duration.as_nanos();
    let full_chunks = nanoseconds
        .checked_div(MAX_DELAY_NANOSECONDS)
        .unwrap_or_default();
    for _ in 0..full_chunks {
        delay.delay_ns(u32::MAX).await;
    }
    let remainder = nanoseconds % MAX_DELAY_NANOSECONDS;
    if remainder != 0 {
        delay.delay_ns(remainder as u32).await;
    }
}

#[cfg(test)]
mod tests {
    use alloc::{collections::VecDeque, vec};
    use core::{
        convert::Infallible,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        task::Poll,
    };

    use crate::{RecordHeader, Tls12Aes128Ccm8KeyBlock};

    use super::*;

    const LOCAL: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1000);
    const PEER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2000);

    // The drivers are IPv6-first in this project; the mutation-focused tests
    // below use these instead of the `ScriptedUdp` fixture's IPv4 constants.
    const LOCAL_ADDR: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 1000);
    const PEER_ADDR: SocketAddr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 2000);

    struct ScriptedUdp {
        received: VecDeque<Vec<u8>>,
        sent: Vec<Vec<u8>>,
    }

    impl UnconnectedUdp for ScriptedUdp {
        type Error = Infallible;

        async fn send(
            &mut self,
            _local: SocketAddr,
            _remote: SocketAddr,
            data: &[u8],
        ) -> core::result::Result<(), Self::Error> {
            self.sent.push(data.to_vec());
            Ok(())
        }

        async fn receive_into(
            &mut self,
            buffer: &mut [u8],
        ) -> core::result::Result<(usize, SocketAddr, SocketAddr), Self::Error> {
            poll_fn(|_| {
                let Some(datagram) = self.received.pop_front() else {
                    return Poll::Pending;
                };
                buffer[..datagram.len()].copy_from_slice(&datagram);
                Poll::Ready(Ok((datagram.len(), LOCAL, PEER)))
            })
            .await
        }
    }

    #[derive(Clone, Copy)]
    struct PendingDelay;

    impl DelayNs for PendingDelay {
        async fn delay_ns(&mut self, _nanoseconds: u32) {
            poll_fn(|_| Poll::<()>::Pending).await;
        }
    }

    #[test]
    fn scripted_transport_drives_record_io_without_a_socket() {
        let record =
            DtlsRecord::new(ContentType::Handshake, 0, 4, vec![1, 2, 3]).expect("test record");
        let mut transport = ScriptedUdp {
            received: VecDeque::from([record.encode().expect("encoded test record")]),
            sent: Vec::new(),
        };
        let mut delay = PendingDelay;
        let (records, local, peer) = futures_lite_for_test::block_on(recv_records(
            &mut transport,
            &mut delay,
            Duration::from_secs(1),
        ))
        .expect("scripted receive");
        assert_eq!(records, vec![record]);
        assert_eq!(local, LOCAL);
        assert_eq!(peer, PEER);
    }

    /// A queued UDP transport whose `receive_into` mirrors a truncating
    /// `recvfrom`: it copies at most `buffer.len()` bytes but still reports
    /// the queued datagram's full length, exactly as a real socket would for
    /// an oversized datagram. Yields `Poll::Pending` forever once drained.
    struct QueuedUdp {
        queue: VecDeque<(Vec<u8>, SocketAddr, SocketAddr)>,
    }

    impl UnconnectedUdp for QueuedUdp {
        type Error = Infallible;

        async fn send(
            &mut self,
            _local: SocketAddr,
            _remote: SocketAddr,
            _data: &[u8],
        ) -> core::result::Result<(), Self::Error> {
            Ok(())
        }

        async fn receive_into(
            &mut self,
            buffer: &mut [u8],
        ) -> core::result::Result<(usize, SocketAddr, SocketAddr), Self::Error> {
            poll_fn(|_| {
                let Some((datagram, local, remote)) = self.queue.pop_front() else {
                    return Poll::Pending;
                };
                let copied = datagram.len().min(buffer.len());
                buffer[..copied].copy_from_slice(&datagram[..copied]);
                Poll::Ready(Ok((datagram.len(), local, remote)))
            })
            .await
        }
    }

    /// A delay that resolves each chunk immediately (so a transport that
    /// never yields a datagram times out promptly) while counting its calls
    /// and panicking past a small budget. Every test that can reach
    /// `delay_duration`'s real loop needs this guard, not just the dedicated
    /// `delay_duration` test below: a mutated termination condition or
    /// accumulator would otherwise spin the test binary forever instead of
    /// failing it.
    #[derive(Clone)]
    struct BudgetedDelay {
        calls: u32,
        total_nanoseconds: u128,
    }

    impl BudgetedDelay {
        const CALL_BUDGET: u32 = 8;

        const fn new() -> Self {
            Self {
                calls: 0,
                total_nanoseconds: 0,
            }
        }
    }

    impl DelayNs for BudgetedDelay {
        async fn delay_ns(&mut self, nanoseconds: u32) {
            self.calls += 1;
            assert!(
                self.calls <= Self::CALL_BUDGET,
                "delay_duration must terminate within a bounded number of chunks"
            );
            self.total_nanoseconds += u128::from(nanoseconds);
        }
    }

    #[derive(Debug)]
    struct MockTransportError;

    impl fmt::Display for MockTransportError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("mock transport failure")
        }
    }

    impl core::error::Error for MockTransportError {}

    fn test_key_material() -> ThreadDtlsKeyMaterial {
        ThreadDtlsKeyMaterial {
            master_secret: [0x11; 48],
            key_block: Tls12Aes128Ccm8KeyBlock {
                client_write_key: [0x21; 16],
                server_write_key: [0x32; 16],
                client_write_iv: [0x43; 4],
                server_write_iv: [0x54; 4],
            },
        }
    }

    #[test]
    fn driver_error_display_matches_each_variant() {
        let protocol = DriverError::<MockTransportError>::Protocol(Error::Crypto("boom".into()));
        assert_eq!(format!("{protocol}"), "crypto error: boom");

        let transport = DriverError::Transport(MockTransportError);
        assert_eq!(
            format!("{transport}"),
            "datagram transport error: mock transport failure"
        );

        let timeout = DriverError::<MockTransportError>::Timeout;
        assert_eq!(format!("{timeout}"), "DTLS operation timed out");
    }

    #[test]
    fn driver_error_source_only_wraps_inner_errors() {
        use core::error::Error as _;

        let protocol = DriverError::<MockTransportError>::Protocol(Error::Crypto("boom".into()));
        let source = protocol
            .source()
            .expect("Protocol must expose its wrapped error as the source");
        assert_eq!(format!("{source}"), "crypto error: boom");

        let transport = DriverError::Transport(MockTransportError);
        let source = transport
            .source()
            .expect("Transport must expose its wrapped error as the source");
        assert_eq!(format!("{source}"), "mock transport failure");

        let timeout = DriverError::<MockTransportError>::Timeout;
        assert!(
            timeout.source().is_none(),
            "Timeout has no wrapped cause to report"
        );
    }

    #[test]
    fn recv_records_accepts_a_datagram_at_the_maximum_size() {
        let payload_len = MAX_DATAGRAM_SIZE - RecordHeader::LEN;
        let record = DtlsRecord::new(ContentType::Handshake, 0, 0, vec![0xab; payload_len])
            .expect("test record");
        let encoded = record.encode().expect("test record encodes");
        assert_eq!(encoded.len(), MAX_DATAGRAM_SIZE);

        let mut transport = QueuedUdp {
            queue: VecDeque::from([(encoded, LOCAL_ADDR, PEER_ADDR)]),
        };
        let mut delay = PendingDelay;
        let (records, local, peer) = futures_lite_for_test::block_on(recv_records(
            &mut transport,
            &mut delay,
            Duration::from_secs(1),
        ))
        .expect("a datagram at exactly MAX_DATAGRAM_SIZE must be accepted");
        assert_eq!(records, vec![record]);
        assert_eq!(local, LOCAL_ADDR);
        assert_eq!(peer, PEER_ADDR);
    }

    #[test]
    fn recv_records_drops_a_datagram_longer_than_the_buffer() {
        // A transport that reports more bytes than fit in the receive buffer
        // mirrors a truncating `recvfrom` on an oversized datagram: real
        // bytes are capped at the buffer size but the reported length is
        // not. The receive must discard it rather than slicing the
        // fixed-size buffer past its end, then deliver the next datagram.
        let oversized = vec![0u8; MAX_DATAGRAM_SIZE + 1];
        let record = DtlsRecord::new(ContentType::Handshake, 0, 1, vec![0x0e]).expect("record");
        let mut transport = QueuedUdp {
            queue: VecDeque::from([
                (oversized, LOCAL_ADDR, PEER_ADDR),
                (
                    record.encode().expect("record encodes"),
                    LOCAL_ADDR,
                    PEER_ADDR,
                ),
            ]),
        };
        let mut delay = PendingDelay;
        let (records, ..) = futures_lite_for_test::block_on(recv_records(
            &mut transport,
            &mut delay,
            Duration::from_secs(1),
        ))
        .expect("the oversized datagram must be skipped");
        assert_eq!(records, vec![record]);
    }

    #[test]
    fn peer_receive_drops_malformed_and_foreign_datagrams() {
        let other_peer = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 3000);
        let record = DtlsRecord::new(ContentType::Handshake, 0, 1, vec![0x0e]).expect("record");
        let encoded = record.encode().expect("record encodes");
        let mut truncated = encoded.clone();
        truncated.pop();
        let mut transport = QueuedUdp {
            queue: VecDeque::from([
                (vec![0x16, 0xfe], LOCAL_ADDR, PEER_ADDR),
                (truncated, LOCAL_ADDR, PEER_ADDR),
                (encoded.clone(), LOCAL_ADDR, other_peer),
                (encoded, LOCAL_ADDR, PEER_ADDR),
            ]),
        };
        let (records, _, remote) =
            futures_lite_for_test::block_on(recv_records_from_unbounded(&mut transport, PEER_ADDR))
                .expect("malformed datagrams must not end the receive");
        assert_eq!(records, vec![record]);
        assert_eq!(remote, PEER_ADDR);
        assert!(transport.queue.is_empty());
    }

    #[test]
    fn any_source_receive_drops_malformed_datagrams() {
        let record = DtlsRecord::new(ContentType::Handshake, 0, 1, vec![0x0e]).expect("record");
        let mut transport = QueuedUdp {
            queue: VecDeque::from([
                (vec![0xff; 3], LOCAL_ADDR, PEER_ADDR),
                (
                    record.encode().expect("record encodes"),
                    LOCAL_ADDR,
                    PEER_ADDR,
                ),
            ]),
        };
        let (records, ..) = futures_lite_for_test::block_on(recv_records_unbounded(&mut transport))
            .expect("a malformed datagram must not fail an accept-side receive");
        assert_eq!(records, vec![record]);
    }

    #[test]
    fn recv_records_parses_every_record_in_a_datagram() {
        let first = DtlsRecord::new(ContentType::Handshake, 0, 3, vec![0x0e]).expect("first");
        let second =
            DtlsRecord::new(ContentType::ApplicationData, 1, 4, vec![0xaa, 0xbb]).expect("second");
        let mut datagram = first.encode().expect("first record encodes");
        datagram.extend_from_slice(&second.encode().expect("second record encodes"));

        let mut transport = QueuedUdp {
            queue: VecDeque::from([(datagram, LOCAL_ADDR, PEER_ADDR)]),
        };
        let mut delay = PendingDelay;
        let (records, ..) = futures_lite_for_test::block_on(recv_records(
            &mut transport,
            &mut delay,
            Duration::from_secs(1),
        ))
        .expect("scripted receive");
        assert_eq!(records, vec![first, second]);
    }

    #[test]
    fn delay_duration_splits_large_durations_into_bounded_chunks() {
        // One nanosecond past two full u32::MAX chunks forces exactly three
        // calls. Mutated chunk arithmetic changes the counts/totals below or
        // trips the delay's own call budget.
        let requested_nanos = 2 * u64::from(u32::MAX) + 1;
        let mut delay = BudgetedDelay::new();
        futures_lite_for_test::block_on(delay_duration(
            &mut delay,
            Duration::from_nanos(requested_nanos),
        ));
        assert_eq!(delay.calls, 3);
        assert_eq!(delay.total_nanoseconds, u128::from(requested_nanos));
    }

    #[test]
    fn retransmit_schedule_doubles_and_caps_at_sixty_seconds() {
        assert_eq!(
            RetransmitSchedule::new().timeout(),
            Duration::from_millis(100)
        );
        let mut schedule = RetransmitSchedule::with_initial(INITIAL_RETRANSMIT_TIMEOUT);
        let expected = [1, 2, 4, 8, 16, 32, 60, 60];
        for seconds in expected {
            assert_eq!(schedule.timeout(), Duration::from_secs(seconds));
            schedule.back_off();
        }
    }

    #[test]
    fn duplicate_retransmit_budget_stops_after_four_responses() {
        let mut budget = DuplicateRetransmitBudget::new();
        for _ in 0..MAX_DUPLICATE_RETRANSMISSIONS {
            assert!(budget.take());
        }
        assert!(!budget.take());
    }

    #[test]
    fn with_timeout_bounds_a_pending_operation() {
        let pending = async { poll_fn(|_| Poll::<DriverResult<(), Infallible>>::Pending).await };
        let result = futures_lite_for_test::block_on(with_timeout(
            pending,
            BudgetedDelay::new(),
            Duration::from_nanos(1),
        ));
        assert!(matches!(result, Err(DriverError::Timeout)));
    }

    #[test]
    fn recv_application_data_ignores_unauthenticated_records_and_reports_protected_alerts() {
        let ignored = DtlsRecord::new(ContentType::Handshake, 0, 0, vec![0xde]).expect("ignored");
        let unauthenticated =
            DtlsRecord::new(ContentType::Alert, 1, 1, vec![2, 40]).expect("unauthenticated");
        let key_material = test_key_material();
        let alert = protect_aes_128_ccm_8_record(
            ContentType::Alert,
            1,
            1,
            RecordProtectionKey::new(key_material.key_block.server_write_key),
            &key_material.key_block.server_write_iv,
            &[2, 40],
        )
        .expect("protected alert");
        let mut datagram = ignored.encode().expect("ignored record encodes");
        datagram.extend_from_slice(
            &unauthenticated
                .encode()
                .expect("unauthenticated record encodes"),
        );
        datagram.extend_from_slice(&alert.encode().expect("alert record encodes"));

        let mut transport = QueuedUdp {
            queue: VecDeque::from([(datagram, LOCAL_ADDR, PEER_ADDR)]),
        };
        let delay = PendingDelay;
        let mut state = SessionState::new(key_material, SessionRole::Client);
        let err = futures_lite_for_test::block_on(recv_application_data(
            &mut state,
            &mut transport,
            &delay,
            PEER_ADDR,
            Duration::from_secs(1),
        ))
        .expect_err("a bare alert record must surface as an error");
        match err {
            DriverError::Protocol(Error::Crypto(message)) => {
                assert!(
                    message.contains("description=40"),
                    "unexpected error message: {message}"
                );
            }
            other => panic!("expected a decoded alert error, got {other:?}"),
        }
    }

    #[test]
    fn recv_application_data_reports_a_protected_close_notify_as_peer_closed() {
        const WARNING_LEVEL: u8 = 1;
        let key_material = test_key_material();
        let close_notify = protect_aes_128_ccm_8_record(
            ContentType::Alert,
            1,
            1,
            RecordProtectionKey::new(key_material.key_block.server_write_key),
            &key_material.key_block.server_write_iv,
            &[WARNING_LEVEL, ALERT_CLOSE_NOTIFY],
        )
        .expect("protected close_notify");
        let mut transport = QueuedUdp {
            queue: VecDeque::from([(
                close_notify.encode().expect("close_notify encodes"),
                LOCAL_ADDR,
                PEER_ADDR,
            )]),
        };
        let delay = PendingDelay;
        let mut state = SessionState::new(key_material, SessionRole::Client);
        let err = futures_lite_for_test::block_on(recv_application_data(
            &mut state,
            &mut transport,
            &delay,
            PEER_ADDR,
            Duration::from_secs(1),
        ))
        .expect_err("close_notify must end the receive");
        assert!(
            matches!(err, DriverError::Protocol(Error::PeerClosed)),
            "expected PeerClosed, got {err:?}"
        );
    }

    #[test]
    fn recv_application_data_drops_replayed_application_records() {
        let key_material = test_key_material();
        let replayed = protect_aes_128_ccm_8_record(
            ContentType::ApplicationData,
            1,
            7,
            RecordProtectionKey::new(key_material.key_block.server_write_key),
            &key_material.key_block.server_write_iv,
            b"first",
        )
        .expect("protect first record");
        let next = protect_aes_128_ccm_8_record(
            ContentType::ApplicationData,
            1,
            8,
            RecordProtectionKey::new(key_material.key_block.server_write_key),
            &key_material.key_block.server_write_iv,
            b"second",
        )
        .expect("protect second record");

        let mut state = SessionState::new(key_material, SessionRole::Client);
        let delay = PendingDelay;

        let mut transport = QueuedUdp {
            queue: VecDeque::from([(
                replayed.encode().expect("replayed record encodes"),
                LOCAL_ADDR,
                PEER_ADDR,
            )]),
        };
        let first = futures_lite_for_test::block_on(recv_application_data(
            &mut state,
            &mut transport,
            &delay,
            PEER_ADDR,
            Duration::from_secs(1),
        ))
        .expect("first record must open");
        assert_eq!(first, b"first");

        let mut second_datagram = replayed.encode().expect("replayed record encodes");
        second_datagram.extend_from_slice(&next.encode().expect("next record encodes"));
        let mut transport = QueuedUdp {
            queue: VecDeque::from([(second_datagram, LOCAL_ADDR, PEER_ADDR)]),
        };
        let second = futures_lite_for_test::block_on(recv_application_data(
            &mut state,
            &mut transport,
            &delay,
            PEER_ADDR,
            Duration::from_secs(1),
        ))
        .expect("second record must open, skipping the replay");
        assert_eq!(second, b"second");
    }

    #[test]
    fn recv_application_data_times_out_without_records() {
        let mut transport = QueuedUdp {
            queue: VecDeque::new(),
        };
        let delay = BudgetedDelay::new();
        let mut state = SessionState::new(test_key_material(), SessionRole::Client);
        let err = futures_lite_for_test::block_on(recv_application_data(
            &mut state,
            &mut transport,
            &delay,
            PEER_ADDR,
            Duration::from_millis(10),
        ))
        .expect_err("an empty transport must time out");
        assert!(
            matches!(err, DriverError::Timeout),
            "expected a Timeout, got {err:?}"
        );
    }

    mod futures_lite_for_test {
        use core::{
            future::Future,
            pin::pin,
            task::{Context, Poll, Waker},
        };

        pub(super) fn block_on<T>(future: impl Future<Output = T>) -> T {
            let mut future = pin!(future);
            let waker = Waker::noop();
            let mut context = Context::from_waker(waker);
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => output,
                Poll::Pending => panic!("scripted future unexpectedly pending"),
            }
        }
    }
}

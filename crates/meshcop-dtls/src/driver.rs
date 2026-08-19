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
//! Tokio support uses small adapters for the same traits. The receive policy
//! deliberately matches the original Tokio client: each expected flight gets
//! the caller's timeout and sent flights are not automatically retransmitted.
//! No additional retry or backoff policy is imposed here.

use alloc::{format, vec::Vec};
use core::{
    fmt,
    future::{Future, poll_fn},
    net::SocketAddr,
    task::Poll,
    time::Duration,
};

pub use embedded_hal_async::delay::DelayNs;
pub use embedded_nal_async::UnconnectedUdp;

use crate::{
    ContentType, DtlsRecord, Error, RecordProtectionKey, ThreadDtlsKeyMaterial,
    open_aes_128_ccm_8_record, protect_aes_128_ccm_8_record,
};

/// Maximum UDP datagram accepted by the async drivers.
pub const MAX_DATAGRAM_SIZE: usize = 4096;

/// Error produced by a runtime-neutral DTLS driver.
#[derive(Debug)]
pub enum DriverError<E> {
    /// DTLS framing, handshake, or cryptographic processing failed.
    Protocol(Error),
    /// The datagram transport failed.
    Transport(E),
    /// A receive did not complete within the supplied timeout.
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
            Self::Timeout => formatter.write_str("DTLS receive timed out"),
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
pub(crate) enum SessionRole {
    Client,
    Server,
}

#[derive(Debug)]
pub(crate) struct SessionState {
    key_material: ThreadDtlsKeyMaterial,
    role: SessionRole,
    next_application_sequence: u64,
    application_replay: DtlsReplayWindow,
}

impl SessionState {
    pub(crate) fn new(key_material: ThreadDtlsKeyMaterial, role: SessionRole) -> Self {
        Self {
            key_material,
            role,
            next_application_sequence: 1,
            application_replay: DtlsReplayWindow::new(),
        }
    }

    pub(crate) const fn key_material(&self) -> &ThreadDtlsKeyMaterial {
        &self.key_material
    }

    pub(crate) fn protect_application_data(
        &mut self,
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
            ContentType::ApplicationData,
            1,
            self.next_application_sequence,
            RecordProtectionKey::new(key),
            &iv,
            plaintext,
        )?;
        self.next_application_sequence = self.next_application_sequence.wrapping_add(1);
        Ok(record)
    }

    pub(crate) fn open_application_data(
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
    let mut datagram = Vec::new();
    for record in records {
        datagram.extend_from_slice(&record.encode()?);
    }
    transport
        .send(local, remote, &datagram)
        .await
        .map_err(DriverError::Transport)
}

pub(crate) async fn recv_records<U, D>(
    transport: &mut U,
    delay: &mut D,
    duration: Duration,
) -> DriverResult<(Vec<DtlsRecord>, SocketAddr, SocketAddr), U::Error>
where
    U: UnconnectedUdp,
    D: DelayNs,
{
    let mut buffer = [0u8; MAX_DATAGRAM_SIZE];
    let (length, local, remote) =
        recv_with_timeout(transport, delay, &mut buffer, duration).await?;
    if length > buffer.len() {
        return Err(Error::Crypto("DTLS datagram is too long".into()).into());
    }
    Ok((
        DtlsRecord::parse_datagram(&buffer[..length])?,
        local,
        remote,
    ))
}

pub(crate) async fn recv_application_data<U, D>(
    state: &mut SessionState,
    transport: &mut U,
    delay: &mut D,
    peer: SocketAddr,
    duration: Duration,
) -> DriverResult<Vec<u8>, U::Error>
where
    U: UnconnectedUdp,
    D: DelayNs,
{
    loop {
        let (records, _, source) = recv_records(transport, delay, duration).await?;
        if source != peer {
            continue;
        }
        for record in records {
            match (record.header.epoch, record.header.content_type) {
                (1, ContentType::ApplicationData) => {
                    if let Some(plaintext) = state.open_application_data(&record)? {
                        return Ok(plaintext);
                    }
                }
                (_, ContentType::Alert) => return Err(decode_alert_error(&record).into()),
                _ => {}
            }
        }
    }
}

pub(crate) fn decode_alert_error(record: &DtlsRecord) -> Error {
    if record.payload.len() >= 2 {
        Error::Crypto(format!(
            "DTLS alert epoch={} seq={} level={} description={}",
            record.header.epoch,
            record.header.sequence_number,
            record.payload[0],
            record.payload[1]
        ))
    } else {
        Error::Crypto(format!(
            "DTLS alert epoch={} seq={} received",
            record.header.epoch, record.header.sequence_number
        ))
    }
}

async fn recv_with_timeout<U, D>(
    transport: &mut U,
    delay: &mut D,
    buffer: &mut [u8],
    duration: Duration,
) -> DriverResult<(usize, SocketAddr, SocketAddr), U::Error>
where
    U: UnconnectedUdp,
    D: DelayNs,
{
    let receive = transport.receive_into(buffer);
    let timeout = delay_duration(delay, duration);
    let mut receive = core::pin::pin!(receive);
    let mut timeout = core::pin::pin!(timeout);

    poll_fn(|context| {
        if let Poll::Ready(result) = receive.as_mut().poll(context) {
            return Poll::Ready(result.map_err(DriverError::Transport));
        }
        if timeout.as_mut().poll(context).is_ready() {
            return Poll::Ready(Err(DriverError::Timeout));
        }
        Poll::Pending
    })
    .await
}

async fn delay_duration(delay: &mut impl DelayNs, duration: Duration) {
    let mut nanoseconds = duration.as_nanos();
    while nanoseconds > 0 {
        let chunk = nanoseconds.min(u32::MAX as u128) as u32;
        delay.delay_ns(chunk).await;
        nanoseconds -= u128::from(chunk);
    }
}

#[derive(Debug)]
struct DtlsReplayWindow {
    newest_sequence: Option<u64>,
    seen: u64,
}

impl DtlsReplayWindow {
    const fn new() -> Self {
        Self {
            newest_sequence: None,
            seen: 0,
        }
    }

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
        assert_eq!(format!("{timeout}"), "DTLS receive timed out");
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
    fn replay_window_detects_in_window_replays_and_preserves_bits() {
        let mut window = DtlsReplayWindow::new();
        assert!(!window.has_seen(100)); // empty window has seen nothing

        window.mark_seen(10);
        assert!(window.has_seen(10));
        assert!(!window.has_seen(11)); // future sequence
        assert!(!window.has_seen(9)); // older, never marked

        window.mark_seen(12); // newer: window slides left by two, bit 2 holds 10
        assert!(window.has_seen(12));
        assert!(window.has_seen(10));
        assert!(!window.has_seen(11)); // gap stays unseen
        assert!(!window.has_seen(9)); // beyond the marked bits, still unseen
        assert!(!window.has_seen(13)); // future

        window.mark_seen(11); // older within window: fills the gap
        assert!(window.has_seen(11));
        assert!(window.has_seen(10)); // neighbouring bits untouched
        assert!(window.has_seen(12));
    }

    #[test]
    fn replay_window_handles_window_edges() {
        // An older sequence two positions back must set bit two, distinguishing
        // subtraction from division/addition in the offset computation.
        let mut window = DtlsReplayWindow::new();
        window.mark_seen(20);
        window.mark_seen(18);
        assert!(window.has_seen(18));
        assert!(!window.has_seen(19));
        assert!(window.has_seen(20));

        // A jump of exactly the window width resets the bitmap to the newest
        // sequence only. The boundary checks keep the 64-bit shifts in range.
        let width = u64::BITS as u64;
        let mut window = DtlsReplayWindow::new();
        window.mark_seen(1);
        window.mark_seen(1 + width); // shift == 64 resets rather than shifting
        assert!(window.has_seen(1 + width));
        assert!(window.has_seen(1)); // offset == 64 is treated as too old to trust
        assert!(!window.has_seen(2)); // within the fresh window but never marked
        window.mark_seen(1); // offset == 64 must be a no-op, not a 1 << 64 shift
        assert!(!window.has_seen(2));
    }

    #[test]
    fn replay_window_remarking_a_seen_sequence_does_not_clear_its_bit() {
        // Re-marking an already-seen older sequence must leave its bit set
        // (`|=`), not toggle it off or wipe out its neighbours.
        let mut window = DtlsReplayWindow::new();
        window.mark_seen(10);
        window.mark_seen(12); // seen = 0b101; bit 2 holds sequence 10
        window.mark_seen(10); // re-mark the already-set bit
        assert!(window.has_seen(10));
        assert!(window.has_seen(12));
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
    fn recv_records_rejects_a_datagram_longer_than_the_buffer() {
        // A transport that reports more bytes than fit in the receive buffer
        // mirrors a truncating `recvfrom` on an oversized datagram: real
        // bytes are capped at the buffer size but the reported length is
        // not. The guard must reject this cleanly rather than slicing the
        // fixed-size buffer past its end.
        let oversized = vec![0u8; 5000];
        let mut transport = QueuedUdp {
            queue: VecDeque::from([(oversized, LOCAL_ADDR, PEER_ADDR)]),
        };
        let mut delay = PendingDelay;
        let result = futures_lite_for_test::block_on(recv_records(
            &mut transport,
            &mut delay,
            Duration::from_secs(1),
        ));
        match result {
            Err(DriverError::Protocol(Error::Crypto(message))) => {
                assert!(
                    message.contains("too long"),
                    "unexpected error message: {message}"
                );
            }
            other => panic!("expected a clean 'too long' error, got {other:?}"),
        }
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
        // One nanosecond past u32::MAX forces exactly two chunks: a full
        // u32::MAX-sized chunk, then a one-nanosecond remainder. A mutated
        // termination test or accumulator update either stops too early
        // (wrong totals below) or never terminates (caught by the delay's
        // own call budget).
        let requested_nanos = u64::from(u32::MAX) + 1;
        let mut delay = BudgetedDelay::new();
        futures_lite_for_test::block_on(delay_duration(
            &mut delay,
            Duration::from_nanos(requested_nanos),
        ));
        assert_eq!(delay.calls, 2);
        assert_eq!(delay.total_nanoseconds, u128::from(requested_nanos));
    }

    #[test]
    fn recv_application_data_ignores_plain_records_and_reports_alerts() {
        let ignored = DtlsRecord::new(ContentType::Handshake, 0, 0, vec![0xde]).expect("ignored");
        let alert = DtlsRecord::new(ContentType::Alert, 1, 1, vec![2, 40]).expect("alert");
        let mut datagram = ignored.encode().expect("ignored record encodes");
        datagram.extend_from_slice(&alert.encode().expect("alert record encodes"));

        let mut transport = QueuedUdp {
            queue: VecDeque::from([(datagram, LOCAL_ADDR, PEER_ADDR)]),
        };
        let mut delay = PendingDelay;
        let mut state = SessionState::new(test_key_material(), SessionRole::Client);
        let err = futures_lite_for_test::block_on(recv_application_data(
            &mut state,
            &mut transport,
            &mut delay,
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
        let mut delay = PendingDelay;

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
            &mut delay,
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
            &mut delay,
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
        let mut delay = BudgetedDelay::new();
        let mut state = SessionState::new(test_key_material(), SessionRole::Client);
        let err = futures_lite_for_test::block_on(recv_application_data(
            &mut state,
            &mut transport,
            &mut delay,
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

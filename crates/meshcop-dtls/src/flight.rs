//! Handshake flight helpers shared by DTLS servers that retransmit flights.
//!
//! The async drivers use these directly. They are public so a server driven
//! over another transport, such as the commissioner's relayed joiner sessions,
//! applies the same retransmission rules.

use crate::{ContentType, DtlsRecord, HandshakeType, parse_unfragmented_handshake_messages};

/// Returns the next record sequence number and advances the counter.
pub(crate) fn take_record_sequence(next_sequence: &mut u64) -> u64 {
    let sequence = *next_sequence;
    *next_sequence = next_sequence.wrapping_add(1);
    sequence
}

/// Assigns fresh epoch-0 sequence numbers to a flight before retransmission.
///
/// DTLS retransmits the same handshake messages in new records, so each
/// plaintext record takes the next number from `next_sequence`. Protected
/// epoch-1 records are left untouched; callers rebuild them instead.
pub fn renumber_epoch_zero_flight(records: &mut [DtlsRecord], next_sequence: &mut u64) {
    for record in records {
        if record.header.epoch == 0 {
            record.header.sequence_number = take_record_sequence(next_sequence);
        }
    }
}

/// Returns whether a datagram carries part of a client's
/// ClientKeyExchange/ChangeCipherSpec/Finished flight.
///
/// A server that has already sent its Finished treats this as a
/// retransmission from a client that did not receive it.
pub fn is_client_finished_flight(records: &[DtlsRecord]) -> bool {
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

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;
    use crate::HandshakeMessage;

    fn handshake_record(message: &HandshakeMessage, epoch: u16) -> DtlsRecord {
        DtlsRecord::new(
            ContentType::Handshake,
            epoch,
            1,
            message.encode().expect("encode handshake message"),
        )
        .expect("build handshake record")
    }

    #[test]
    fn renumbers_only_plaintext_records_in_flight_order() {
        let mut flight = vec![
            DtlsRecord::new(ContentType::Handshake, 0, 0, vec![1]).expect("first"),
            DtlsRecord::new(ContentType::Handshake, 1, 9, vec![2]).expect("protected"),
            DtlsRecord::new(ContentType::ChangeCipherSpec, 0, 1, vec![1]).expect("second"),
        ];
        let mut next = 5;
        renumber_epoch_zero_flight(&mut flight, &mut next);
        let sequences = flight
            .iter()
            .map(|record| record.header.sequence_number)
            .collect::<Vec<_>>();
        assert_eq!(sequences, [5, 9, 6]);
        assert_eq!(next, 7);
    }

    #[test]
    fn recognizes_each_meaningful_client_finished_flight_record() {
        let key_exchange = HandshakeMessage {
            message_type: HandshakeType::ClientKeyExchange,
            message_seq: 2,
            payload: Vec::new(),
        };
        assert!(is_client_finished_flight(&[handshake_record(
            &key_exchange,
            0
        )]));

        let server_hello = HandshakeMessage {
            message_type: HandshakeType::ServerHello,
            message_seq: 1,
            payload: Vec::new(),
        };
        assert!(!is_client_finished_flight(&[handshake_record(
            &server_hello,
            0
        )]));
        let encrypted_finished =
            DtlsRecord::new(ContentType::Handshake, 1, 1, vec![0xaa]).expect("finished record");
        assert!(is_client_finished_flight(&[encrypted_finished]));
        let change_cipher_spec =
            DtlsRecord::new(ContentType::ChangeCipherSpec, 0, 2, vec![1]).expect("CCS record");
        assert!(!is_client_finished_flight(&[change_cipher_spec]));
    }
}

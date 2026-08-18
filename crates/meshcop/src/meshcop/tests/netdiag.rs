use super::*;

#[test]
fn relay_tx_request_appends_kek_when_present() {
    let kek = [0x5a; 16];
    let message = relay_tx_request_with_kek(
        9,
        [0x02],
        &[1, 2, 3, 4, 5, 6, 7, 8],
        1000,
        0x6800,
        b"records",
        Some(&kek),
    )
    .unwrap();
    let tlvs = TlvSet::parse(&message.payload).unwrap();
    assert_eq!(tlvs.last_value(TLV_JOINER_ROUTER_KEK), Some(kek.as_slice()));

    let without = relay_tx_request_with_kek(
        9,
        [0x02],
        &[1, 2, 3, 4, 5, 6, 7, 8],
        1000,
        0x6800,
        b"records",
        None,
    )
    .unwrap();
    let tlvs = TlvSet::parse(&without.payload).unwrap();
    assert_eq!(tlvs.last_value(TLV_JOINER_ROUTER_KEK), None);
}

#[test]
fn diag_flag_constants_match_reference_bit_assignments_and_tlv_mapping() {
    use diag::diag_flags;

    let cases = [
        (diag_flags::EXT_MAC_ADDR, 1u64 << 0, 0u8),
        (diag_flags::MAC_ADDR, 1 << 1, 1),
        (diag_flags::MODE, 1 << 2, 2),
        (diag_flags::ROUTE64, 1 << 3, 5),
        (diag_flags::LEADER_DATA, 1 << 4, 6),
        (diag_flags::IPV6_ADDRESSES, 1 << 5, 8),
        (diag_flags::CHILD_TABLE, 1 << 6, 16),
        (diag_flags::EUI64, 1 << 7, 23),
        (diag_flags::MAC_COUNTERS, 1 << 8, 9),
        (diag_flags::CHILD_IPV6_ADDRESSES, 1 << 9, 30),
        (diag_flags::NETWORK_DATA, 1 << 10, 7),
        (diag_flags::TIMEOUT, 1 << 11, 3),
        (diag_flags::CONNECTIVITY, 1 << 12, 4),
        (diag_flags::BATTERY_LEVEL, 1 << 13, 14),
        (diag_flags::SUPPLY_VOLTAGE, 1 << 14, 15),
        (diag_flags::CHANNEL_PAGES, 1 << 15, 17),
        (diag_flags::TYPE_LIST, 1 << 16, 18),
    ];
    for (flag, expected_bit, tlv_type) in cases {
        assert_eq!(flag, expected_bit, "flag bit for TLV {tlv_type}");
        assert_eq!(
            network_diag_tlv_types(flag),
            vec![tlv_type],
            "TLV mapping for flag {flag:#x}"
        );
    }
    assert_eq!(diag_flags::ALL, 0x1ffff);
    assert_eq!(network_diag_tlv_types(diag_flags::ALL).len(), 17);
}

#[test]
fn mode_data_decodes_each_bit_independently() {
    use diag::ModeData;

    // R bit only (0x08): rx-on-when-idle MTD that wants stable data.
    let rx_only = ModeData::decode(&[0x08]).unwrap();
    assert!(rx_only.rx_on_when_idle);
    assert!(rx_only.is_mtd);
    assert!(!rx_only.requires_full_network_data);

    // D bit only (0x02): a sleepy FTD.
    let ftd_only = ModeData::decode(&[0x02]).unwrap();
    assert!(!ftd_only.rx_on_when_idle);
    assert!(!ftd_only.is_mtd);
    assert!(!ftd_only.requires_full_network_data);

    // N bit only (0x01): requires full network data.
    let network_data_only = ModeData::decode(&[0x01]).unwrap();
    assert!(!network_data_only.rx_on_when_idle);
    assert!(network_data_only.is_mtd);
    assert!(network_data_only.requires_full_network_data);

    // Reserved-only bits decode as all-off, not as false positives.
    let reserved = ModeData::decode(&[0xf4]).unwrap();
    assert!(!reserved.rx_on_when_idle);
    assert!(reserved.is_mtd);
    assert!(!reserved.requires_full_network_data);
}

#[test]
fn child_timeout_and_network_data_boundaries_decode_exactly() {
    use diag::{ChildTableEntry, ModeData, NetworkData};

    // 2^(exponent - 4) seconds, with sub-second exponents reported as zero.
    let entry = |timeout_exponent| ChildTableEntry {
        timeout_exponent,
        incoming_link_quality: 0,
        child_id: 0,
        mode: ModeData::default(),
    };
    assert_eq!(entry(2).timeout_seconds(), 0);
    assert_eq!(entry(3).timeout_seconds(), 0);
    assert_eq!(entry(4).timeout_seconds(), 1);
    assert_eq!(entry(5).timeout_seconds(), 2);
    assert_eq!(entry(31).timeout_seconds(), 1 << 27);

    // A network-data TLV with a zero-length value is valid and skipped when
    // it is not a prefix.
    let skipped = NetworkData::decode(&[5 << 1, 0]).unwrap();
    assert!(skipped.prefixes.is_empty());

    // A minimal prefix entry: domain ID and a zero-bit prefix, no sub-TLVs.
    let minimal = NetworkData::decode(&[1 << 1, 2, 7, 0]).unwrap();
    assert_eq!(minimal.prefixes.len(), 1);
    assert_eq!(minimal.prefixes[0].domain_id, 7);
    assert_eq!(minimal.prefixes[0].prefix_bit_length, 0);
    assert!(minimal.prefixes[0].prefix.is_empty());
}

#[test]
fn network_data_iteration_advances_past_each_tlv_exactly() {
    use diag::NetworkData;

    // Two prefix TLVs back to back; the first carries an unknown sub-TLV.
    // Decoding both proves the iterator advances by exactly header plus
    // length: the existing minimal cases use length 2, where `2 + len` and
    // `2 * len` coincide, so this needs asymmetric lengths.
    let data = NetworkData::decode(&[
        1 << 1,
        9,
        0,
        16,
        0xfd,
        0x00,
        5 << 1,
        3,
        1,
        2,
        3, // prefix fd00::/16 with an unknown sub-TLV
        1 << 1,
        3,
        5,
        8,
        0xfe, // prefix fe00::/8 in domain 5
    ])
    .unwrap();

    assert_eq!(data.prefixes.len(), 2);
    assert_eq!(data.prefixes[0].domain_id, 0);
    assert_eq!(data.prefixes[0].prefix_bit_length, 16);
    assert_eq!(data.prefixes[0].prefix, [0xfd, 0x00]);
    assert_eq!(data.prefixes[1].domain_id, 5);
    assert_eq!(data.prefixes[1].prefix_bit_length, 8);
    assert_eq!(data.prefixes[1].prefix, [0xfe]);
}

#[test]
fn border_router_and_has_route_flags_decode_with_bit_precision() {
    use diag::NetworkData;

    // Two border-router entries with complementary flag patterns so every
    // flag bit is observed both set and clear.
    let prefix_value: Vec<u8> = {
        let mut value = vec![0, 0];
        value.extend_from_slice(&[
            2 << 1,
            8,
            0xa8,
            0x00,
            0b1010_1010,
            0b1000_0000,
            0x2c,
            0x01,
            0b0101_0101,
            0b0100_0000,
        ]);
        // Two HasRoute entries: NAT64 set with preference 1, then NAT64
        // clear with preference 2.
        value.extend_from_slice(&[0, 6, 0x20, 0x00, 0b0110_0000, 0x20, 0x01, 0b1000_0000]);
        // 6LoWPAN context with the compression bit clear but a reserved bit
        // set, so masking must isolate the C flag.
        value.extend_from_slice(&[(3 << 1) | 1, 2, 0x25, 32]);
        value
    };
    let mut payload = vec![7, (2 + prefix_value.len()) as u8, 1 << 1];
    payload.push(prefix_value.len() as u8);
    payload.extend_from_slice(&prefix_value);

    let data = diag::NetDiagData::decode(&payload).unwrap();
    let prefix = &data.network_data.as_ref().unwrap().prefixes[0];

    let first = &prefix.border_routers[0];
    assert_eq!(first.rloc16, 0xa800);
    assert_eq!(first.prefix_preference, 2);
    assert!(first.is_preferred);
    assert!(!first.is_slaac);
    assert!(first.is_dhcp);
    assert!(!first.is_configure);
    assert!(first.is_default_route);
    assert!(!first.is_on_mesh);
    assert!(first.is_nd_dns);
    assert!(!first.is_dp);

    let second = &prefix.border_routers[1];
    assert_eq!(second.rloc16, 0x2c01);
    assert_eq!(second.prefix_preference, 1);
    assert!(!second.is_preferred);
    assert!(second.is_slaac);
    assert!(!second.is_dhcp);
    assert!(second.is_configure);
    assert!(!second.is_default_route);
    assert!(second.is_on_mesh);
    assert!(!second.is_nd_dns);
    assert!(second.is_dp);

    let nat64 = &prefix.has_route[0];
    assert_eq!(nat64.rloc16, 0x2000);
    assert_eq!(nat64.router_preference, 1);
    assert!(nat64.is_nat64);
    let plain = &prefix.has_route[1];
    assert_eq!(plain.rloc16, 0x2001);
    assert_eq!(plain.router_preference, 2);
    assert!(!plain.is_nat64);

    let context = prefix.six_low_pan_context.unwrap();
    assert!(!context.is_compress);
    assert_eq!(context.context_id, 5);
    assert_eq!(context.context_length, 32);

    // A prefix whose stated bit length exceeds the value must error rather
    // than slice out of bounds.
    assert!(NetworkData::decode(&[1 << 1, 3, 0, 64, 0xfd]).is_err());
}

#[test]
fn connectivity_decodes_every_parent_priority_code() {
    use diag::NetDiagData;

    let connectivity = |byte0: u8| {
        let data = NetDiagData::decode(&[4, 7, byte0, 0, 0, 0, 0, 0, 0]).unwrap();
        data.connectivity.unwrap().parent_priority
    };
    assert_eq!(connectivity(0b0100_0000), 1);
    assert_eq!(connectivity(0b0000_0000), 0);
    assert_eq!(connectivity(0b1100_0000), -1);
    assert_eq!(connectivity(0b1000_0000), -2);

    // Exactly seven bytes is the minimum valid Connectivity TLV; the
    // optional rx-off fields stay absent.
    let minimal = NetDiagData::decode(&[4, 7, 0, 1, 2, 3, 4, 5, 6]).unwrap();
    let minimal = minimal.connectivity.unwrap();
    assert_eq!(minimal.rx_off_child_buffer_size, None);
    assert_eq!(minimal.rx_off_child_datagram_count, None);
}

#[test]
fn route64_handles_boundary_masks_and_high_router_ids() {
    use diag::NetDiagData;

    // Mask with no assigned routers: nine bytes total, no route data.
    let empty = NetDiagData::decode(&[5, 9, 3, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
    let empty = empty.route64.unwrap();
    assert_eq!(empty.id_sequence, 3);
    assert!(empty.route_data.is_empty());

    // Eight bytes cannot hold the sequence number plus the full mask.
    assert!(NetDiagData::decode(&[5, 8, 3, 0, 0, 0, 0, 0, 0, 0]).is_err());

    // A router ID in the last mask byte must be found by the bit scan, and
    // both link-quality fields decode from their own bit positions.
    let high = NetDiagData::decode(&[5, 10, 3, 0, 0, 0, 0, 0, 0, 0, 0x08, 0xa5]).unwrap();
    let high = high.route64.unwrap();
    assert_eq!(high.route_data.len(), 1);
    assert_eq!(high.route_data[0].router_id, 60);
    assert_eq!(high.route_data[0].outgoing_link_quality, 2);
    assert_eq!(high.route_data[0].incoming_link_quality, 2);
    assert_eq!(high.route_data[0].route_cost, 5);
}

#[test]
fn child_ipv6_address_list_boundaries_decode_exactly() {
    use diag::NetDiagData;

    // An RLOC16 with zero registered addresses is a valid, empty list.
    let empty = NetDiagData::decode(&[30, 2, 0xa8, 0x07]).unwrap();
    let children = empty.child_ipv6_addresses.unwrap();
    assert_eq!(children[0].rloc16, 0xa807);
    assert!(children[0].addresses.is_empty());

    // A truncated RLOC16 must error without underflowing.
    assert!(NetDiagData::decode(&[30, 1, 0xa8]).is_err());
    assert!(NetDiagData::decode(&[30, 0]).is_err());
}

#[test]
fn udp_rx_with_empty_datagram_and_overlapping_channel_masks_parse() {
    // UDP encapsulation carrying only the two ports is a valid empty datagram.
    let mut payload = vec![TLV_IPV6_ADDRESS, 16];
    payload.extend_from_slice(&[0xfd; 16]);
    payload.extend_from_slice(&[TLV_UDP_ENCAPSULATION, 4]);
    payload.extend_from_slice(&0xf0b0u16.to_be_bytes());
    payload.extend_from_slice(&DEFAULT_MM_PORT.to_be_bytes());
    let message =
        CoapMessage::post_request(CoapType::NonConfirmable, 3, [], uri::UDP_RX, payload).unwrap();
    let parsed = parse_udp_rx(&message).unwrap().unwrap();
    assert!(parsed.payload.is_empty());

    // Multiple page-0 channel-mask entries in a PANID_CONFLICT.ans merge with
    // OR semantics: overlapping bits must stay set.
    let mut payload = Vec::new();
    payload.extend_from_slice(&[TLV_CHANNEL_MASK, 12]);
    payload.extend_from_slice(&[0, 4, 0x00, 0xff, 0xf8, 0x00]);
    payload.extend_from_slice(&[0, 4, 0x00, 0xff, 0x00, 0x00]);
    payload.extend_from_slice(&[TLV_PAN_ID, 2, 0xfa, 0xce]);
    let conflict = CoapMessage::post_request(
        CoapType::Confirmable,
        4,
        [0x11],
        uri::MGMT_PANID_CONFLICT,
        payload,
    )
    .unwrap();
    assert_eq!(
        parse_notification(&conflict).unwrap(),
        Some(MeshcopNotification::PanIdConflict {
            channel_mask: 0x00fff800,
            pan_id: 0xface,
        })
    );
}

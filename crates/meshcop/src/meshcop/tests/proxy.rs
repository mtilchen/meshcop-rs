use super::*;

#[test]
fn udp_tx_request_encapsulates_inner_datagrams() {
    let destination: std::net::Ipv6Addr = "fd00:db8::ff:fe00:fc00".parse().unwrap();
    let inner = CoapMessage::post_request(
        CoapType::Confirmable,
        7,
        [0xaa],
        uri::MGMT_COMMISSIONER_GET,
        Vec::new(),
    )
    .unwrap()
    .encode()
    .unwrap();
    let udp_tx = udp_tx_request(0x100, [0x01], destination, DEFAULT_MM_PORT, &inner).unwrap();

    assert_eq!(udp_tx.ty, CoapType::NonConfirmable);
    assert_eq!(udp_tx.uri_path().unwrap().as_deref(), Some(uri::UDP_TX));
    let tlvs = TlvSet::parse(&udp_tx.payload).unwrap();
    assert_eq!(
        tlvs.last_value(TLV_IPV6_ADDRESS),
        Some(destination.octets().as_slice())
    );
    let encapsulation = tlvs.last_value(TLV_UDP_ENCAPSULATION).unwrap();
    assert_eq!(&encapsulation[..2], DEFAULT_MM_PORT.to_be_bytes());
    assert_eq!(&encapsulation[2..4], DEFAULT_MM_PORT.to_be_bytes());
    assert_eq!(&encapsulation[4..], inner);
}

#[test]
fn parse_udp_rx_round_trips_and_ignores_other_resources() {
    let source: std::net::Ipv6Addr = "fd00:db8::1".parse().unwrap();
    let inner = b"datagram".to_vec();
    let mut payload = Vec::new();
    payload.extend_from_slice(&[TLV_IPV6_ADDRESS, 16]);
    payload.extend_from_slice(&source.octets());
    payload.extend_from_slice(&[TLV_UDP_ENCAPSULATION, 4 + inner.len() as u8]);
    payload.extend_from_slice(&0xf0b0u16.to_be_bytes());
    payload.extend_from_slice(&DEFAULT_MM_PORT.to_be_bytes());
    payload.extend_from_slice(&inner);
    let udp_rx =
        CoapMessage::post_request(CoapType::NonConfirmable, 3, [], uri::UDP_RX, payload).unwrap();

    let parsed = parse_udp_rx(&udp_rx).unwrap().unwrap();
    assert_eq!(parsed.source_address, source);
    assert_eq!(parsed.source_port, 0xf0b0);
    assert_eq!(parsed.destination_port, DEFAULT_MM_PORT);
    assert_eq!(parsed.payload, inner);

    let other =
        CoapMessage::post_request(CoapType::NonConfirmable, 3, [], uri::RELAY_RX, Vec::new())
            .unwrap();
    assert_eq!(parse_udp_rx(&other).unwrap(), None);
}

#[test]
fn parse_udp_rx_rejects_malformed_payloads() {
    let cases = [
        ("no TLVs at all", Vec::new()),
        ("missing encapsulation", {
            let mut payload = vec![TLV_IPV6_ADDRESS, 16];
            payload.extend_from_slice(&[0u8; 16]);
            payload
        }),
        ("short address", {
            let mut payload = vec![TLV_IPV6_ADDRESS, 4, 1, 2, 3, 4];
            payload.extend_from_slice(&[TLV_UDP_ENCAPSULATION, 4, 0, 1, 2, 3]);
            payload
        }),
        ("encapsulation without ports", {
            let mut payload = vec![TLV_IPV6_ADDRESS, 16];
            payload.extend_from_slice(&[0u8; 16]);
            payload.extend_from_slice(&[TLV_UDP_ENCAPSULATION, 2, 0, 1]);
            payload
        }),
    ];
    for (name, payload) in cases {
        let message =
            CoapMessage::post_request(CoapType::NonConfirmable, 3, [], uri::UDP_RX, payload)
                .unwrap();
        assert!(parse_udp_rx(&message).is_err(), "{name}");
    }
}

#[test]
fn diag_answer_notification_decodes_net_diag_data() {
    let mut payload = Vec::new();
    // Extended MAC address (0).
    payload.extend_from_slice(&[0, 8, 1, 2, 3, 4, 5, 6, 7, 8]);
    // MAC address / RLOC16 (1).
    payload.extend_from_slice(&[1, 2, 0xa8, 0x00]);
    // Mode (2): rx-on-when-idle | FTD | full network data.
    payload.extend_from_slice(&[2, 1, 0x0b]);
    // Leader data (6).
    payload.extend_from_slice(&[6, 8, 0, 0, 0, 9, 64, 7, 6, 3]);
    let message = CoapMessage::post_request(
        CoapType::Confirmable,
        9,
        [0x44],
        uri::DIAG_GET_ANSWER,
        payload,
    )
    .unwrap();

    let Some(MeshcopNotification::DiagGetAnswer { data }) = parse_notification(&message).unwrap()
    else {
        panic!("expected a diagnostic answer notification");
    };
    assert_eq!(
        data.ext_mac_addr.as_deref(),
        Some(&[1u8, 2, 3, 4, 5, 6, 7, 8][..])
    );
    assert_eq!(data.mac_addr, Some(0xa800));
    let mode = data.mode.unwrap();
    assert!(mode.rx_on_when_idle);
    assert!(!mode.is_mtd);
    assert!(mode.requires_full_network_data);
    let leader = data.leader_data.unwrap();
    assert_eq!(leader.partition_id, 9);
    assert_eq!(leader.weighting, 64);
    assert_eq!(leader.data_version, 7);
    assert_eq!(leader.stable_data_version, 6);
    assert_eq!(leader.router_id, 3);
}

#[test]
fn net_diag_data_decodes_structured_tlvs() {
    use diag::NetDiagData;

    let mut payload = Vec::new();
    // Timeout (3).
    payload.extend_from_slice(&[3, 4, 0, 0, 0, 240]);
    // Connectivity (4): parent priority low (0b11), optional fields present.
    payload.extend_from_slice(&[4, 10, 0b1100_0000, 5, 4, 3, 2, 17, 6, 0x01, 0x00, 9]);
    // Route64 (5): id-seq 7, mask with router IDs 0 and 9 assigned.
    payload.extend_from_slice(&[5, 11, 7, 0x80, 0x40, 0, 0, 0, 0, 0, 0, 0x16, 0x29]);
    // IPv6 address list (8) with one address.
    payload.extend_from_slice(&[8, 16]);
    payload.extend_from_slice(
        &"fd00:db8::5"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    // MAC counters (9).
    let mut counters = vec![9, 36];
    for counter in 1u32..=9 {
        counters.extend_from_slice(&counter.to_be_bytes());
    }
    payload.extend_from_slice(&counters);
    // Battery level (14) and supply voltage (15).
    payload.extend_from_slice(&[14, 1, 88]);
    payload.extend_from_slice(&[15, 2, 0x0c, 0xe4]);
    // Child table (16): timeout exponent 9, ILQ 3, child id 0x123, mode FTD.
    payload.extend_from_slice(&[16, 3, 0b0100_1111, 0x23, 0x0b]);
    // Channel pages (17) and type list (18).
    payload.extend_from_slice(&[17, 1, 0]);
    payload.extend_from_slice(&[18, 2, 6, 16]);
    // EUI-64 (23).
    payload.extend_from_slice(&[23, 8, 9, 8, 7, 6, 5, 4, 3, 2]);
    // Child IPv6 address list (30): RLOC16 then one address.
    payload.extend_from_slice(&[30, 18, 0xa8, 0x07]);
    payload.extend_from_slice(
        &"fd00:db8::7"
            .parse::<std::net::Ipv6Addr>()
            .unwrap()
            .octets(),
    );
    // Network data (7): one prefix entry with border router + context.
    let prefix_value: Vec<u8> = {
        let mut value = vec![0, 64];
        value.extend_from_slice(&[0xfd, 0x00, 0x0d, 0xb8, 0, 0, 0, 0]);
        // Border router sub-TLV (2 << 1): rloc 0xa800, P+default-route, DP.
        value.extend_from_slice(&[2 << 1, 4, 0xa8, 0x00, 0b0010_0010, 0b0100_0000]);
        // 6LoWPAN context sub-TLV (3 << 1 | stable): compress, cid 2, length 64.
        value.extend_from_slice(&[(3 << 1) | 1, 2, 0x12, 64]);
        // HasRoute sub-TLV (0 << 1): rloc 0x2000, preference 1, NAT64.
        value.extend_from_slice(&[0, 3, 0x20, 0x00, 0b0110_0000]);
        value
    };
    payload.extend_from_slice(&[7, (2 + prefix_value.len()) as u8, 1 << 1]);
    payload.push(prefix_value.len() as u8);
    payload.extend_from_slice(&prefix_value);

    let data = NetDiagData::decode(&payload).unwrap();
    assert_eq!(data.timeout, Some(240));

    let connectivity = data.connectivity.unwrap();
    assert_eq!(connectivity.parent_priority, -1);
    assert_eq!(connectivity.link_quality_3, 5);
    assert_eq!(connectivity.active_routers, 6);
    assert_eq!(connectivity.rx_off_child_buffer_size, Some(0x0100));
    assert_eq!(connectivity.rx_off_child_datagram_count, Some(9));

    let route64 = data.route64.unwrap();
    assert_eq!(route64.id_sequence, 7);
    assert_eq!(route64.route_data.len(), 2);
    assert_eq!(route64.route_data[0].router_id, 0);
    assert_eq!(route64.route_data[0].outgoing_link_quality, 0);
    assert_eq!(route64.route_data[0].incoming_link_quality, 1);
    assert_eq!(route64.route_data[0].route_cost, 6);
    assert_eq!(route64.route_data[1].router_id, 9);

    assert_eq!(
        data.addresses.unwrap(),
        vec!["fd00:db8::5".parse::<std::net::Ipv6Addr>().unwrap()]
    );
    let counters = data.mac_counters.unwrap();
    assert_eq!(counters.if_in_unknown_protos, 1);
    assert_eq!(counters.if_out_discards, 9);
    assert_eq!(data.battery_level, Some(88));
    assert_eq!(data.supply_voltage, Some(3300));

    let child_table = data.child_table.unwrap();
    assert_eq!(child_table.len(), 1);
    assert_eq!(child_table[0].timeout_exponent, 9);
    assert_eq!(child_table[0].timeout_seconds(), 32);
    assert_eq!(child_table[0].incoming_link_quality, 3);
    assert_eq!(child_table[0].child_id, 0x123);
    assert!(!child_table[0].mode.is_mtd);

    assert_eq!(data.channel_pages.as_deref(), Some(&[0u8][..]));
    assert_eq!(data.type_list.as_deref(), Some(&[6u8, 16][..]));
    assert_eq!(data.eui64, Some([9, 8, 7, 6, 5, 4, 3, 2]));

    let children = data.child_ipv6_addresses.unwrap();
    assert_eq!(children.len(), 1);
    assert_eq!(children[0].rloc16, 0xa807);
    assert_eq!(children[0].child_id, 0x007);
    assert_eq!(
        children[0].addresses,
        vec!["fd00:db8::7".parse::<std::net::Ipv6Addr>().unwrap()]
    );

    let network_data = data.network_data.unwrap();
    assert_eq!(network_data.prefixes.len(), 1);
    let prefix = &network_data.prefixes[0];
    assert_eq!(prefix.domain_id, 0);
    assert_eq!(prefix.prefix_bit_length, 64);
    assert_eq!(prefix.prefix, [0xfd, 0x00, 0x0d, 0xb8, 0, 0, 0, 0]);
    let border_router = &prefix.border_routers[0];
    assert_eq!(border_router.rloc16, 0xa800);
    assert!(border_router.is_preferred);
    assert!(border_router.is_default_route);
    assert!(border_router.is_dp);
    assert!(!border_router.is_slaac);
    let context = prefix.six_low_pan_context.unwrap();
    assert!(context.is_compress);
    assert_eq!(context.context_id, 2);
    assert_eq!(context.context_length, 64);
    let has_route = &prefix.has_route[0];
    assert_eq!(has_route.rloc16, 0x2000);
    assert_eq!(has_route.router_preference, 1);
    assert!(has_route.is_nat64);
}

#[test]
fn net_diag_data_rejects_malformed_tlvs() {
    use diag::NetDiagData;

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("short mac address", vec![1, 1, 7]),
        ("bad mode length", vec![2, 2, 0, 0]),
        ("short timeout", vec![3, 2, 0, 1]),
        ("short connectivity", vec![4, 3, 0, 1, 2]),
        ("route64 without mask", vec![5, 3, 1, 2, 3]),
        (
            "route64 route data mismatch",
            vec![5, 9, 7, 0x80, 0, 0, 0, 0, 0, 0, 0],
        ),
        ("short leader data", vec![6, 2, 1, 2]),
        ("ragged ipv6 list", vec![8, 3, 1, 2, 3]),
        ("short mac counters", vec![9, 4, 1, 2, 3, 4]),
        ("bad battery", vec![14, 2, 1, 2]),
        ("bad voltage", vec![15, 1, 9]),
        ("ragged child table", vec![16, 2, 1, 2]),
        ("bad eui64", vec![23, 2, 1, 2]),
        ("ragged child ipv6 list", vec![30, 3, 1, 2, 3]),
        ("truncated network data tlv", vec![7, 1, 2]),
        ("network data prefix too short", vec![7, 3, 1 << 1, 1, 0]),
    ];
    for (name, payload) in cases {
        assert!(NetDiagData::decode(&payload).is_err(), "{name}");
    }

    // Unknown diagnostic TLVs must be skipped, not rejected.
    let unknown = NetDiagData::decode(&[200, 2, 1, 2]).unwrap();
    assert_eq!(unknown, NetDiagData::default());
}

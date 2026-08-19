//! Conversions between the library [`Dataset`] and the C++ `ot-commissioner`
//! JSON schema (field names like `ActiveTimestamp`, `Channel`, `PanId`,
//! `SecurityPolicy`, `BorderAgentLocator`, ...).

use serde_json::{Map, Value, json};

use meshcop::{
    dataset::{
        Channel, ChannelMaskEntry, Dataset, SecurityPolicy, SecurityPolicyFlags,
        TLV_ACTIVE_TIMESTAMP, TLV_CHANNEL, TLV_CHANNEL_MASK, TLV_DELAY_TIMER, TLV_EXTENDED_PAN_ID,
        TLV_MESH_LOCAL_PREFIX, TLV_NETWORK_KEY, TLV_NETWORK_NAME, TLV_PAN_ID,
        TLV_PENDING_TIMESTAMP, TLV_PSKC, TLV_SECURITY_POLICY, Timestamp,
    },
    error::{Error, Result},
    meshcop::{
        TLV_AE_STEERING_DATA, TLV_AE_UDP_PORT, TLV_BORDER_AGENT_LOCATOR,
        TLV_COMMISSIONER_SESSION_ID, TLV_JOINER_UDP_PORT, TLV_NMKP_STEERING_DATA,
        TLV_NMKP_UDP_PORT, TLV_STEERING_DATA,
    },
};

const PANID_TLV: u8 = TLV_PAN_ID;

fn dataset_err(message: impl Into<String>) -> Error {
    Error::Dataset(message.into())
}

/// Parses a hex string (with or without a `0x` prefix) into bytes.
fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim().strip_prefix("0x").unwrap_or(s.trim());
    hex::decode(s).map_err(|err| dataset_err(format!("invalid hex '{s}': {err}")))
}

fn as_str<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| dataset_err(format!("missing or non-string field '{key}'")))
}

fn as_u64(value: &Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| dataset_err(format!("missing or non-integer field '{key}'")))
}

// --- single-field renderers (match the C++ ToString helpers) ---

/// Renders a [`Timestamp`] as the C++ `{Seconds, Ticks, U}` object.
pub fn timestamp_json(ts: Timestamp) -> Value {
    let raw = u64::from_be_bytes(ts.to_value());
    json!({
        "Seconds": raw >> 16,
        "Ticks": (raw >> 1) & 0x7fff,
        "U": raw & 1,
    })
}

fn timestamp_from_json(value: &Value) -> Result<Timestamp> {
    let seconds = as_u64(value, "Seconds")?;
    let ticks = as_u64(value, "Ticks")? as u16;
    let u = as_u64(value, "U")? != 0;
    Ok(Timestamp::from_components(seconds, ticks, u))
}

/// Renders a [`Channel`] as the C++ `{Page, Number}` object.
pub fn channel_json(channel: Channel) -> Value {
    json!({ "Page": channel.page, "Number": channel.channel })
}

/// Renders a channel mask as the C++ `[{Page, Masks}]` array.
pub fn channel_mask_json(entries: &[ChannelMaskEntry]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|e| json!({ "Page": e.page, "Masks": hex::encode(&e.mask) }))
            .collect(),
    )
}

/// Renders a [`SecurityPolicy`] as the C++ `{RotationTime, Flags}` object.
pub fn security_policy_json(policy: SecurityPolicy) -> Value {
    let bytes = policy.to_value();
    json!({ "RotationTime": policy.rotation_time, "Flags": hex::encode(&bytes[2..]) })
}

/// Formats a mesh-local prefix as `addr/64`.
pub fn mesh_local_prefix_string(prefix: [u8; 8]) -> String {
    let mut octets = [0u8; 16];
    octets[..8].copy_from_slice(&prefix);
    format!("{}/64", std::net::Ipv6Addr::from(octets))
}

// --- operational dataset <-> JSON ---

/// Builds the C++ operational-dataset JSON for an active or pending dataset.
pub fn op_dataset_to_json(dataset: &Dataset, pending: bool) -> Result<Value> {
    let mut map = Map::new();
    if let Some(ts) = dataset.active_timestamp()? {
        map.insert("ActiveTimestamp".into(), timestamp_json(ts));
    }
    if pending {
        if let Some(ts) = dataset.pending_timestamp()? {
            map.insert("PendingTimestamp".into(), timestamp_json(ts));
        }
        if let Some(delay) = dataset.delay_timer()? {
            map.insert("Delay".into(), json!(delay));
        }
    }
    if let Some(name) = dataset.network_name()? {
        map.insert("NetworkName".into(), json!(name));
    }
    if let Some(channel) = dataset.channel()? {
        map.insert("Channel".into(), channel_json(channel));
    }
    if let Some(mask) = dataset.channel_mask()? {
        map.insert("ChannelMask".into(), channel_mask_json(&mask));
    }
    if let Some(xpanid) = dataset.extended_pan_id()? {
        map.insert("ExtendedPanId".into(), json!(hex::encode(xpanid)));
    }
    if let Some(panid) = dataset.pan_id()? {
        map.insert("PanId".into(), json!(format!("0x{panid:04x}")));
    }
    if let Some(prefix) = dataset.mesh_local_prefix()? {
        map.insert(
            "MeshLocalPrefix".into(),
            json!(mesh_local_prefix_string(prefix)),
        );
    }
    if let Some(key) = dataset.network_key()? {
        map.insert("NetworkMasterKey".into(), json!(hex::encode(key)));
    }
    if let Some(pskc) = dataset.pskc() {
        map.insert("PSKc".into(), json!(hex::encode(pskc)));
    }
    if let Some(policy) = dataset.security_policy()? {
        map.insert("SecurityPolicy".into(), security_policy_json(policy));
    }
    Ok(Value::Object(map))
}

/// Parses a C++ operational-dataset JSON object into a [`Dataset`].
pub fn op_dataset_from_json(value: &Value, pending: bool) -> Result<Dataset> {
    let mut dataset = Dataset::default();
    if let Some(ts) = value.get("ActiveTimestamp") {
        dataset.set_raw(
            TLV_ACTIVE_TIMESTAMP,
            timestamp_from_json(ts)?.to_value().to_vec(),
        );
    }
    if pending {
        if let Some(ts) = value.get("PendingTimestamp") {
            dataset.set_raw(
                TLV_PENDING_TIMESTAMP,
                timestamp_from_json(ts)?.to_value().to_vec(),
            );
        }
        if let Some(delay) = value.get("Delay").and_then(Value::as_u64) {
            dataset.set_raw(TLV_DELAY_TIMER, (delay as u32).to_be_bytes().to_vec());
        }
    }
    if let Some(name) = value.get("NetworkName").and_then(Value::as_str) {
        dataset.set_raw(TLV_NETWORK_NAME, name.as_bytes().to_vec());
    }
    if let Some(channel) = value.get("Channel") {
        let page = as_u64(channel, "Page")? as u8;
        let number = as_u64(channel, "Number")? as u16;
        dataset.set_raw(
            TLV_CHANNEL,
            Channel {
                page,
                channel: number,
            }
            .to_value()
            .to_vec(),
        );
    }
    if let Some(Value::Array(entries)) = value.get("ChannelMask") {
        let parsed = entries
            .iter()
            .map(|e| {
                Ok(ChannelMaskEntry {
                    page: as_u64(e, "Page")? as u8,
                    mask: parse_hex(as_str(e, "Masks")?)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        dataset.set_raw(TLV_CHANNEL_MASK, ChannelMaskEntry::encode_all(&parsed)?);
    }
    if let Some(xpanid) = value.get("ExtendedPanId").and_then(Value::as_str) {
        dataset.set_raw(TLV_EXTENDED_PAN_ID, parse_hex(xpanid)?);
    }
    if let Some(panid) = value.get("PanId").and_then(Value::as_str) {
        let panid = parse_panid(panid)?;
        dataset.set_raw(PANID_TLV, panid.to_be_bytes().to_vec());
    }
    if let Some(prefix) = value.get("MeshLocalPrefix").and_then(Value::as_str) {
        dataset.set_raw(
            TLV_MESH_LOCAL_PREFIX,
            parse_mesh_local_prefix(prefix)?.to_vec(),
        );
    }
    if let Some(key) = value.get("NetworkMasterKey").and_then(Value::as_str) {
        dataset.set_raw(TLV_NETWORK_KEY, parse_hex(key)?);
    }
    if let Some(pskc) = value.get("PSKc").and_then(Value::as_str) {
        dataset.set_raw(TLV_PSKC, parse_hex(pskc)?);
    }
    if let Some(policy) = value.get("SecurityPolicy") {
        let rotation = as_u64(policy, "RotationTime")? as u16;
        let flag_bytes = parse_hex(as_str(policy, "Flags")?)?;
        let flags = match flag_bytes.as_slice() {
            [hi, lo, ..] => u16::from_be_bytes([*hi, *lo]),
            [only] => u16::from(*only) << 8,
            [] => return Err(dataset_err("SecurityPolicy Flags must not be empty")),
        };
        let policy = SecurityPolicy {
            rotation_time: rotation,
            flags: SecurityPolicyFlags::from_bits_retain(flags),
        };
        dataset.set_raw(TLV_SECURITY_POLICY, policy.to_value().to_vec());
    }
    Ok(dataset)
}

/// Parses a PAN ID (`0x1234` or `1234` hex, or decimal).
pub fn parse_panid(s: &str) -> Result<u16> {
    let s = s.trim();
    let parsed = if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u16::from_str_radix(hex, 16)
    } else {
        // The C++ Hex() output has no 0x, so a bare hex string is accepted too.
        u16::from_str_radix(s, 16).or_else(|_| s.parse::<u16>())
    };
    parsed.map_err(|_| dataset_err(format!("invalid PAN ID '{s}'")))
}

/// Parses a `addr/len` or bare-address mesh-local prefix into 8 bytes.
pub fn parse_mesh_local_prefix(s: &str) -> Result<[u8; 8]> {
    let addr_part = s.split('/').next().unwrap_or(s).trim();
    let addr: std::net::Ipv6Addr = addr_part
        .parse()
        .map_err(|_| dataset_err(format!("invalid mesh-local prefix '{s}'")))?;
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&addr.octets()[..8]);
    Ok(prefix)
}

// --- commissioner dataset <-> JSON ---

/// Builds the C++ commissioner-dataset JSON from a TLV [`Dataset`].
pub fn comm_dataset_to_json(dataset: &Dataset) -> Value {
    let mut map = Map::new();
    let u16_field = |map: &mut Map<String, Value>, ty: u8, key: &str| {
        if let Some(bytes) = dataset.raw(ty) {
            if bytes.len() == 2 {
                map.insert(key.into(), json!(u16::from_be_bytes([bytes[0], bytes[1]])));
            }
        }
    };
    let hex_field = |map: &mut Map<String, Value>, ty: u8, key: &str| {
        if let Some(bytes) = dataset.raw(ty) {
            map.insert(key.into(), json!(hex::encode(bytes)));
        }
    };
    u16_field(&mut map, TLV_BORDER_AGENT_LOCATOR, "BorderAgentLocator");
    u16_field(&mut map, TLV_COMMISSIONER_SESSION_ID, "SessionId");
    hex_field(&mut map, TLV_STEERING_DATA, "SteeringData");
    hex_field(&mut map, TLV_AE_STEERING_DATA, "AeSteeringData");
    hex_field(&mut map, TLV_NMKP_STEERING_DATA, "NmkpSteeringData");
    u16_field(&mut map, TLV_JOINER_UDP_PORT, "JoinerUdpPort");
    u16_field(&mut map, TLV_AE_UDP_PORT, "AeUdpPort");
    u16_field(&mut map, TLV_NMKP_UDP_PORT, "NmkpUdpPort");
    Value::Object(map)
}

/// Parses a C++ commissioner-dataset JSON object into a settable TLV
/// [`Dataset`]. Only the writable fields are honored (steering data and joiner
/// UDP ports); the protocol-managed locator/session ID are ignored.
pub fn comm_dataset_from_json(value: &Value) -> Result<Dataset> {
    let mut dataset = Dataset::default();
    let mut set_hex = |ty: u8, key: &str| -> Result<()> {
        if let Some(s) = value.get(key).and_then(Value::as_str) {
            dataset.set_raw(ty, parse_hex(s)?);
        }
        Ok(())
    };
    set_hex(TLV_STEERING_DATA, "SteeringData")?;
    set_hex(TLV_AE_STEERING_DATA, "AeSteeringData")?;
    set_hex(TLV_NMKP_STEERING_DATA, "NmkpSteeringData")?;
    let mut set_u16 = |ty: u8, key: &str| {
        if let Some(n) = value.get(key).and_then(Value::as_u64) {
            dataset.set_raw(ty, (n as u16).to_be_bytes().to_vec());
        }
    };
    set_u16(TLV_JOINER_UDP_PORT, "JoinerUdpPort");
    set_u16(TLV_AE_UDP_PORT, "AeUdpPort");
    set_u16(TLV_NMKP_UDP_PORT, "NmkpUdpPort");
    Ok(dataset)
}

/// Pretty-prints a JSON value, matching the C++ `json.dump(indent)` style.
pub fn dump(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshcop::dataset::{TLV_NETWORK_NAME, TLV_PAN_ID};
    use meshcop::meshcop::TLV_BORDER_AGENT_LOCATOR;

    #[test]
    fn timestamp_round_trips_through_cpp_object() {
        let ts = Timestamp::from_components(1_756_994_612, 7, true);
        let value = timestamp_json(ts);
        assert_eq!(value["Seconds"], 1_756_994_612u64);
        assert_eq!(value["Ticks"], 7u64);
        assert_eq!(value["U"], 1u64);
        assert_eq!(
            timestamp_from_json(&value).unwrap().to_value(),
            ts.to_value()
        );
    }

    #[test]
    fn channel_json_uses_cpp_field_names() {
        let value = channel_json(Channel {
            page: 0,
            channel: 19,
        });
        assert_eq!(value, json!({ "Page": 0, "Number": 19 }));
    }

    #[test]
    fn parse_panid_prefers_hex_then_falls_back_to_decimal() {
        assert_eq!(parse_panid("0x1234").unwrap(), 0x1234);
        assert_eq!(parse_panid("1234").unwrap(), 0x1234); // bare hex, no prefix
        assert_eq!(parse_panid("65535").unwrap(), 65535); // hex overflow -> decimal
        assert!(parse_panid("nope").is_err());
    }

    #[test]
    fn mesh_local_prefix_round_trips() {
        let prefix = parse_mesh_local_prefix("fd4c:3e8a:e5ab:73e::/64").unwrap();
        assert_eq!(mesh_local_prefix_string(prefix), "fd4c:3e8a:e5ab:73e::/64");
    }

    #[test]
    fn op_dataset_round_trips_core_fields() {
        let mut ds = Dataset::default();
        ds.set_raw(TLV_NETWORK_NAME, b"net".to_vec());
        ds.set_raw(TLV_PAN_ID, 0xabcdu16.to_be_bytes().to_vec());
        ds.set_raw(
            TLV_CHANNEL,
            Channel {
                page: 0,
                channel: 11,
            }
            .to_value()
            .to_vec(),
        );

        let value = op_dataset_to_json(&ds, false).unwrap();
        assert_eq!(value["NetworkName"], "net");
        assert_eq!(value["PanId"], "0xabcd");
        assert_eq!(value["Channel"], json!({ "Page": 0, "Number": 11 }));

        let back = op_dataset_from_json(&value, false).unwrap();
        assert_eq!(back.network_name().unwrap(), Some("net"));
        assert_eq!(back.pan_id().unwrap(), Some(0xabcd));
        assert_eq!(back.channel().unwrap().map(|c| c.channel), Some(11));
    }

    #[test]
    fn comm_dataset_json_exposes_managed_fields_but_only_parses_writable_ones() {
        let mut ds = Dataset::default();
        ds.set_raw(TLV_BORDER_AGENT_LOCATOR, 0x1234u16.to_be_bytes().to_vec());
        ds.set_raw(TLV_STEERING_DATA, vec![0xff]);
        ds.set_raw(TLV_JOINER_UDP_PORT, 1000u16.to_be_bytes().to_vec());

        let value = comm_dataset_to_json(&ds);
        assert_eq!(value["BorderAgentLocator"], 0x1234);
        assert_eq!(value["SteeringData"], "ff");
        assert_eq!(value["JoinerUdpPort"], 1000);

        // The protocol-managed locator is read-only and must be dropped on parse.
        let parsed = comm_dataset_from_json(&value).unwrap();
        assert_eq!(parsed.raw(TLV_STEERING_DATA), Some(&[0xff][..]));
        assert_eq!(parsed.raw(TLV_BORDER_AGENT_LOCATOR), None);
    }
}

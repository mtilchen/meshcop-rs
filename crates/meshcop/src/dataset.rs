//! Thread operational dataset TLV support.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    Result,
    error::Error,
    tlv::{self, TlvEntry, TlvSet},
};

/// Channel TLV type.
pub const TLV_CHANNEL: u8 = 0x00;
/// PAN ID TLV type.
pub const TLV_PAN_ID: u8 = 0x01;
/// Extended PAN ID TLV type.
pub const TLV_EXTENDED_PAN_ID: u8 = 0x02;
/// Network name TLV type.
pub const TLV_NETWORK_NAME: u8 = 0x03;
/// PSKc TLV type.
pub const TLV_PSKC: u8 = 0x04;
/// Network key TLV type.
pub const TLV_NETWORK_KEY: u8 = 0x05;
/// Mesh-local prefix TLV type.
pub const TLV_MESH_LOCAL_PREFIX: u8 = 0x07;
/// Security policy TLV type.
pub const TLV_SECURITY_POLICY: u8 = 0x0c;
/// Active timestamp TLV type.
pub const TLV_ACTIVE_TIMESTAMP: u8 = 0x0e;
/// Pending timestamp TLV type.
pub const TLV_PENDING_TIMESTAMP: u8 = 0x33;
/// Delay timer TLV type.
pub const TLV_DELAY_TIMER: u8 = 0x34;
/// Channel mask TLV type.
pub const TLV_CHANNEL_MASK: u8 = 0x35;

/// A generic Thread dataset preserving all TLVs in wire order.
#[derive(Clone, Default, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Dataset {
    tlvs: TlvSet,
}

impl core::fmt::Debug for Dataset {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Dataset")
            .field("tlvs", &"<redacted>")
            .finish()
    }
}

/// Active operational dataset.
pub type ActiveOperationalDataset = Dataset;

/// Pending operational dataset.
pub type PendingOperationalDataset = Dataset;

impl Dataset {
    /// Parses a binary Thread dataset.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Ok(Self {
            tlvs: TlvSet::parse(bytes)?,
        })
    }

    /// Parses a hex-encoded Thread dataset.
    pub fn from_hex(hex: impl AsRef<[u8]>) -> Result<Self> {
        let bytes = Zeroizing::new(hex::decode(hex)?);
        Self::from_bytes(&bytes)
    }

    /// Returns all TLVs in wire order.
    pub fn entries(&self) -> &[TlvEntry] {
        self.tlvs.entries()
    }

    /// Encodes this dataset as bytes.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        Ok(self.tlvs.encode()?)
    }

    /// Encodes this dataset as lowercase hex.
    pub fn to_hex(&self) -> Result<String> {
        let bytes = Zeroizing::new(self.to_bytes()?);
        Ok(hex::encode(bytes.as_slice()))
    }

    /// Returns the last raw value for a TLV type.
    pub fn raw(&self, ty: u8) -> Option<&[u8]> {
        self.tlvs.last_value(ty)
    }

    /// Sets a TLV value, removing previous values of the same type.
    pub fn set_raw(&mut self, ty: u8, value: impl Into<Vec<u8>>) {
        self.remove_all(ty);
        self.tlvs.push(TlvEntry::new(ty, value));
    }

    /// Removes every TLV of the given type.
    pub fn remove_all(&mut self, ty: u8) {
        self.tlvs.entries_mut().retain_mut(|entry| {
            if entry.ty == ty {
                entry.zeroize();
                false
            } else {
                true
            }
        });
    }

    /// Returns the commissioner PSKc, if present.
    pub fn pskc(&self) -> Option<&[u8]> {
        self.raw(TLV_PSKC)
    }

    /// Returns the network name, if present.
    pub fn network_name(&self) -> Result<Option<&str>> {
        self.raw(TLV_NETWORK_NAME)
            .map(|value| {
                core::str::from_utf8(value)
                    .map_err(|_| Error::Dataset("network name is not UTF-8".to_string()))
            })
            .transpose()
    }

    /// Returns the channel, if present.
    pub fn channel(&self) -> Result<Option<Channel>> {
        self.raw(TLV_CHANNEL).map(Channel::parse).transpose()
    }

    /// Returns the PAN ID, if present.
    pub fn pan_id(&self) -> Result<Option<u16>> {
        self.raw(TLV_PAN_ID)
            .map(tlv::read_u16)
            .transpose()
            .map_err(Into::into)
    }

    /// Returns the extended PAN ID, if present.
    pub fn extended_pan_id(&self) -> Result<Option<[u8; 8]>> {
        self.raw(TLV_EXTENDED_PAN_ID)
            .map(read_array::<8>)
            .transpose()
    }

    /// Returns the network key, if present.
    pub fn network_key(&self) -> Result<Option<[u8; 16]>> {
        self.raw(TLV_NETWORK_KEY).map(read_array::<16>).transpose()
    }

    /// Returns the mesh-local prefix, if present.
    pub fn mesh_local_prefix(&self) -> Result<Option<[u8; 8]>> {
        self.raw(TLV_MESH_LOCAL_PREFIX)
            .map(read_array::<8>)
            .transpose()
    }

    /// Returns the active timestamp, if present.
    pub fn active_timestamp(&self) -> Result<Option<Timestamp>> {
        self.raw(TLV_ACTIVE_TIMESTAMP)
            .map(Timestamp::parse)
            .transpose()
    }

    /// Returns the pending timestamp, if present.
    pub fn pending_timestamp(&self) -> Result<Option<Timestamp>> {
        self.raw(TLV_PENDING_TIMESTAMP)
            .map(Timestamp::parse)
            .transpose()
    }

    /// Returns the delay timer, if present.
    pub fn delay_timer(&self) -> Result<Option<u32>> {
        self.raw(TLV_DELAY_TIMER)
            .map(tlv::read_u32)
            .transpose()
            .map_err(Into::into)
    }

    /// Returns the security policy, if present.
    pub fn security_policy(&self) -> Result<Option<SecurityPolicy>> {
        self.raw(TLV_SECURITY_POLICY)
            .map(SecurityPolicy::parse)
            .transpose()
    }

    /// Returns the channel mask, if present.
    pub fn channel_mask(&self) -> Result<Option<Vec<ChannelMaskEntry>>> {
        self.raw(TLV_CHANNEL_MASK)
            .map(ChannelMaskEntry::parse_all)
            .transpose()
    }
}

/// Thread channel dataset value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Channel {
    /// Channel page.
    pub page: u8,
    /// Channel number.
    pub channel: u16,
}

impl Channel {
    /// Parses a channel TLV value.
    pub fn parse(value: &[u8]) -> Result<Self> {
        if value.len() != 3 {
            return Err(Error::Dataset("channel TLV must be 3 bytes".to_string()));
        }
        Ok(Self {
            page: value[0],
            channel: u16::from_be_bytes([value[1], value[2]]),
        })
    }

    /// Serializes this channel value without the TLV header.
    pub fn to_value(self) -> [u8; 3] {
        let [hi, lo] = self.channel.to_be_bytes();
        [self.page, hi, lo]
    }
}

/// Thread timestamp value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Timestamp(u64);

impl Timestamp {
    /// Builds a timestamp from raw Thread bits.
    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }

    /// Builds a timestamp from components.
    pub fn from_components(seconds: u64, ticks: u16, authoritative: bool) -> Self {
        Self((seconds << 16) | (((ticks as u64) & 0x7fff) << 1) | u64::from(authoritative))
    }

    /// Parses a timestamp value.
    pub fn parse(value: &[u8]) -> Result<Self> {
        Ok(Self(tlv::read_u64(value)?))
    }

    /// Returns the raw Thread timestamp bits.
    pub const fn raw(self) -> u64 {
        self.0
    }

    /// Returns the seconds field.
    pub const fn seconds(self) -> u64 {
        self.0 >> 16
    }

    /// Returns the tick field.
    pub const fn ticks(self) -> u16 {
        ((self.0 & 0xfffe) >> 1) as u16
    }

    /// Returns whether the timestamp is authoritative.
    pub const fn authoritative(self) -> bool {
        (self.0 & 1) == 1
    }

    /// Serializes this timestamp without a TLV header.
    pub fn to_value(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }
}

/// Thread security policy value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityPolicy {
    /// Key rotation time in hours.
    pub rotation_time: u16,
    /// Security policy flags.
    pub flags: SecurityPolicyFlags,
}

impl SecurityPolicy {
    /// Parses a security policy value.
    pub fn parse(value: &[u8]) -> Result<Self> {
        if value.len() != 4 {
            return Err(Error::Dataset(
                "security policy TLV must be 4 bytes".to_string(),
            ));
        }
        Ok(Self {
            rotation_time: u16::from_be_bytes([value[0], value[1]]),
            flags: SecurityPolicyFlags(u16::from_be_bytes([value[2], value[3]])),
        })
    }

    /// Serializes this security policy without a TLV header.
    pub fn to_value(self) -> [u8; 4] {
        let rotation = self.rotation_time.to_be_bytes();
        let flags = self.flags.0.to_be_bytes();
        [rotation[0], rotation[1], flags[0], flags[1]]
    }
}

impl_bitflag_newtype! {
    /// Bit flags in the Thread security policy TLV.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct SecurityPolicyFlags(u16);
    constants {
        /// Out-of-band commissioning is disallowed.
        pub const OUT_OF_BAND_COMMISSIONING_DISALLOWED: u16 = 0x0001;
        /// Native commissioning is disallowed.
        pub const NATIVE_COMMISSIONING_DISALLOWED: u16 = 0x0002;
        /// Legacy routers are enabled.
        pub const LEGACY_ROUTERS_ENABLED: u16 = 0x0004;
        /// External commissioner authentication is required.
        pub const EXTERNAL_COMMISSIONER_AUTH_REQUIRED: u16 = 0x0008;
        /// Commercial commissioning mode is enabled.
        pub const COMMERCIAL_COMMISSIONING_MODE: u16 = 0x0010;

        const VERSION_THRESHOLD_MASK: u16 = 0xe000;
    }
    methods {
        /// Creates flags from raw bits, preserving unknown bits.
        from_bits_retain;
        /// Returns raw bits.
        bits;
        /// Returns whether all bits in `mask` are set.
        contains(mask: u16);
    }
}

impl SecurityPolicyFlags {
    /// Returns the Thread protocol version threshold stored in bits 13-15.
    pub fn version_threshold_for_routing(self) -> ThreadProtocolVersion {
        if self.contains(Self::LEGACY_ROUTERS_ENABLED) {
            return ThreadProtocolVersion::V1Or2;
        }
        ThreadProtocolVersion::from_bits(((self.0 & Self::VERSION_THRESHOLD_MASK) >> 13) as u8)
    }

    /// Sets the Thread protocol version threshold while preserving other bits.
    ///
    /// `V1Or2` is signaled by the legacy-routers flag (the version field is then
    /// don't-care), so it sets that flag; every other version clears the flag
    /// and writes the version field. This keeps
    /// [`Self::version_threshold_for_routing`] a faithful inverse — without
    /// managing the flag, setting `V1Or2` would read back as `V10` (both encode
    /// version bits `0b111`) and a later non-legacy version could not be set.
    pub fn set_version_threshold_for_routing(&mut self, version: ThreadProtocolVersion) {
        match version {
            ThreadProtocolVersion::V1Or2 => self.0 |= Self::LEGACY_ROUTERS_ENABLED,
            _ => {
                self.0 &= !Self::LEGACY_ROUTERS_ENABLED;
                let cleared = self.0 & !Self::VERSION_THRESHOLD_MASK;
                self.0 = cleared | ((version.to_bits() as u16) << 13);
            }
        }
    }
}

/// Thread protocol version threshold encoded in the security policy TLV.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadProtocolVersion {
    /// Version 1 or 2, implied when the legacy router flag is set.
    V1Or2,
    /// Version 3, Thread 1.2.x.
    V3,
    /// Version 4, Thread 1.3.x.
    V4,
    /// Version 5, Thread 1.4.x.
    V5,
    /// Version 6.
    V6,
    /// Version 7.
    V7,
    /// Version 8.
    V8,
    /// Version 9.
    V9,
    /// Version 10.
    V10,
}

impl ThreadProtocolVersion {
    fn from_bits(bits: u8) -> Self {
        match bits & 0x07 {
            0 => Self::V3,
            1 => Self::V4,
            2 => Self::V5,
            3 => Self::V6,
            4 => Self::V7,
            5 => Self::V8,
            6 => Self::V9,
            _ => Self::V10,
        }
    }

    fn to_bits(self) -> u8 {
        match self {
            Self::V1Or2 | Self::V10 => 7,
            Self::V3 => 0,
            Self::V4 => 1,
            Self::V5 => 2,
            Self::V6 => 3,
            Self::V7 => 4,
            Self::V8 => 5,
            Self::V9 => 6,
        }
    }
}

/// One channel-mask entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelMaskEntry {
    /// Channel page.
    pub page: u8,
    /// Page-specific channel mask bytes.
    pub mask: Vec<u8>,
}

impl ChannelMaskEntry {
    /// Parses all channel-mask entries from a TLV value.
    pub fn parse_all(mut value: &[u8]) -> Result<Vec<Self>> {
        let mut out = Vec::new();
        while !value.is_empty() {
            if value.len() < 2 {
                return Err(Error::Dataset(
                    "channel mask entry header is truncated".to_string(),
                ));
            }
            let page = value[0];
            let len = value[1] as usize;
            value = &value[2..];
            if value.len() < len {
                return Err(Error::Dataset(
                    "channel mask entry value is truncated".to_string(),
                ));
            }
            out.push(Self {
                page,
                mask: value[..len].to_vec(),
            });
            value = &value[len..];
        }
        Ok(out)
    }

    /// Encodes all channel-mask entries into one TLV value.
    pub fn encode_all(entries: &[Self]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for entry in entries {
            if entry.mask.len() > u8::MAX as usize {
                return Err(Error::Dataset("channel mask entry too long".to_string()));
            }
            out.push(entry.page);
            out.push(entry.mask.len() as u8);
            out.extend_from_slice(&entry.mask);
        }
        Ok(out)
    }
}

fn read_array<const N: usize>(value: &[u8]) -> Result<[u8; N]> {
    value
        .try_into()
        .map_err(|_| Error::Dataset(format!("expected {N} bytes, got {}", value.len())))
}

#[cfg(test)]
mod tests {
    use super::*;

    const STITCH_ACTIVE_DATASET: &str = "000300001935090004001fffe00101ff0208a168e269cbeb79f60708fd6ed15702b4cdbf051027e5a891e7ca57124b9bb046c7535c14030d53542d3330313130383434313301020b760410ff3a089f65d505e94daf1cfdb055d1a60c0402a0fff80e08000068555fc70000";

    #[test]
    fn parses_and_round_trips_stitch_dataset_vector() {
        let dataset = Dataset::from_hex(STITCH_ACTIVE_DATASET).unwrap();
        assert_eq!(dataset.channel().unwrap().unwrap().channel, 25);
        assert_eq!(dataset.pan_id().unwrap(), Some(0x0b76));
        assert_eq!(dataset.network_name().unwrap(), Some("ST-3011084413"));
        assert_eq!(dataset.pskc().unwrap().len(), 16);
        assert_eq!(dataset.entries().len(), 10);
        assert_eq!(dataset.to_hex().unwrap(), STITCH_ACTIVE_DATASET);
    }

    #[test]
    fn debug_redacts_all_known_and_unknown_tlv_values() {
        let mut dataset = Dataset::default();
        dataset.set_raw(TLV_PSKC, b"commissioner-secret".to_vec());
        dataset.set_raw(TLV_NETWORK_KEY, b"network-secret".to_vec());
        dataset.set_raw(0xfe, b"unknown-secret".to_vec());

        let debug = format!("{dataset:?}");
        assert_eq!(debug, "Dataset { tlvs: \"<redacted>\" }");
        assert!(!debug.contains("commissioner-secret"));
        assert!(!debug.contains("network-secret"));
        assert!(!debug.contains("unknown-secret"));
    }

    #[test]
    fn zeroize_clears_owned_tlvs_without_affecting_clones() {
        fn assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}

        assert_zeroize_on_drop::<Dataset>();
        let mut dataset = Dataset::default();
        dataset.set_raw(TLV_PSKC, b"commissioner-secret".to_vec());
        dataset.set_raw(0xfe, b"unknown-secret".to_vec());
        let mut cloned = dataset.clone();

        dataset.zeroize();
        assert!(dataset.entries().is_empty());
        assert_eq!(cloned.pskc(), Some(b"commissioner-secret".as_slice()));
        assert_eq!(cloned.raw(0xfe), Some(b"unknown-secret".as_slice()));

        cloned.zeroize();
        assert!(cloned.entries().is_empty());
    }

    #[test]
    fn preserves_unknown_and_duplicate_tlvs() {
        let bytes = [
            0xfe, 1, 0xaa, TLV_PAN_ID, 2, 0x12, 0x34, TLV_PAN_ID, 2, 0x56, 0x78,
        ];
        let dataset = Dataset::from_bytes(&bytes).unwrap();
        assert_eq!(dataset.entries()[0].ty, 0xfe);
        assert_eq!(dataset.pan_id().unwrap(), Some(0x5678));
        assert_eq!(dataset.to_bytes().unwrap(), bytes);
    }

    #[test]
    fn version_threshold_round_trips_including_v1_or_2() {
        // Every version, including the legacy-flag-signaled V1Or2, must read
        // back as itself, and switching away from V1Or2 must clear the flag.
        for version in [
            ThreadProtocolVersion::V1Or2,
            ThreadProtocolVersion::V3,
            ThreadProtocolVersion::V4,
            ThreadProtocolVersion::V5,
            ThreadProtocolVersion::V6,
            ThreadProtocolVersion::V7,
            ThreadProtocolVersion::V8,
            ThreadProtocolVersion::V9,
            ThreadProtocolVersion::V10,
        ] {
            // Start from a policy that already has V1Or2 set, to prove the
            // legacy flag is cleared when moving to a concrete version.
            let mut policy = SecurityPolicyFlags::from_bits_retain(0);
            policy.set_version_threshold_for_routing(ThreadProtocolVersion::V1Or2);
            policy.set_version_threshold_for_routing(version);
            assert_eq!(
                policy.version_threshold_for_routing(),
                version,
                "round-trip failed for {version:?}"
            );
        }
    }

    #[test]
    fn timestamp_components_round_trip() {
        let ts = Timestamp::from_components(12345, 100, true);
        let parsed = Timestamp::parse(&ts.to_value()).unwrap();
        assert_eq!(parsed.seconds(), 12345);
        assert_eq!(parsed.ticks(), 100);
        assert!(parsed.authoritative());
    }

    #[test]
    fn parses_channel_mask_entries() {
        let entries = vec![
            ChannelMaskEntry {
                page: 0,
                mask: vec![0x00, 0x1f, 0xff, 0xe0],
            },
            ChannelMaskEntry {
                page: 2,
                mask: vec![0xaa],
            },
        ];
        let encoded = ChannelMaskEntry::encode_all(&entries).unwrap();
        assert_eq!(ChannelMaskEntry::parse_all(&encoded).unwrap(), entries);
    }

    #[test]
    fn typed_accessors_reject_malformed_known_tlvs() {
        let cases = [
            MalformedField::NetworkName,
            MalformedField::Channel,
            MalformedField::PanId,
            MalformedField::ExtendedPanId,
            MalformedField::NetworkKey,
            MalformedField::MeshLocalPrefix,
            MalformedField::ActiveTimestamp,
            MalformedField::PendingTimestamp,
            MalformedField::DelayTimer,
            MalformedField::SecurityPolicy,
            MalformedField::ChannelMaskHeader,
            MalformedField::ChannelMaskValue,
        ];

        for case in cases {
            case.assert_rejected();
        }
    }

    #[test]
    fn channel_mask_encoder_rejects_oversized_entries() {
        let err = ChannelMaskEntry::encode_all(&[ChannelMaskEntry {
            page: 0,
            mask: vec![0xaa; u8::MAX as usize + 1],
        }])
        .unwrap_err();

        assert!(err.to_string().contains("channel mask entry too long"));
    }

    #[derive(Debug, Clone, Copy)]
    enum MalformedField {
        NetworkName,
        Channel,
        PanId,
        ExtendedPanId,
        NetworkKey,
        MeshLocalPrefix,
        ActiveTimestamp,
        PendingTimestamp,
        DelayTimer,
        SecurityPolicy,
        ChannelMaskHeader,
        ChannelMaskValue,
    }

    impl MalformedField {
        fn assert_rejected(self) {
            let mut dataset = Dataset::default();
            let (ty, value, expected) = match self {
                Self::NetworkName => (TLV_NETWORK_NAME, vec![0xff], "network name is not UTF-8"),
                Self::Channel => (TLV_CHANNEL, vec![0, 0], "channel TLV must be 3 bytes"),
                Self::PanId => (TLV_PAN_ID, vec![0], "TLV error: invalid TLV length"),
                Self::ExtendedPanId => (TLV_EXTENDED_PAN_ID, vec![0; 7], "expected 8 bytes"),
                Self::NetworkKey => (TLV_NETWORK_KEY, vec![0; 15], "expected 16 bytes"),
                Self::MeshLocalPrefix => (TLV_MESH_LOCAL_PREFIX, vec![0; 7], "expected 8 bytes"),
                Self::ActiveTimestamp => (
                    TLV_ACTIVE_TIMESTAMP,
                    vec![0; 7],
                    "TLV error: invalid TLV length",
                ),
                Self::PendingTimestamp => (
                    TLV_PENDING_TIMESTAMP,
                    vec![0; 7],
                    "TLV error: invalid TLV length",
                ),
                Self::DelayTimer => (TLV_DELAY_TIMER, vec![0; 3], "TLV error: invalid TLV length"),
                Self::SecurityPolicy => (
                    TLV_SECURITY_POLICY,
                    vec![0; 3],
                    "security policy TLV must be 4 bytes",
                ),
                Self::ChannelMaskHeader => (
                    TLV_CHANNEL_MASK,
                    vec![0],
                    "channel mask entry header is truncated",
                ),
                Self::ChannelMaskValue => (
                    TLV_CHANNEL_MASK,
                    vec![0, 4, 0xaa],
                    "channel mask entry value is truncated",
                ),
            };
            dataset.set_raw(ty, value);

            let err = match self {
                Self::NetworkName => dataset.network_name().unwrap_err(),
                Self::Channel => dataset.channel().unwrap_err(),
                Self::PanId => dataset.pan_id().unwrap_err(),
                Self::ExtendedPanId => dataset.extended_pan_id().unwrap_err(),
                Self::NetworkKey => dataset.network_key().unwrap_err(),
                Self::MeshLocalPrefix => dataset.mesh_local_prefix().unwrap_err(),
                Self::ActiveTimestamp => dataset.active_timestamp().unwrap_err(),
                Self::PendingTimestamp => dataset.pending_timestamp().unwrap_err(),
                Self::DelayTimer => dataset.delay_timer().unwrap_err(),
                Self::SecurityPolicy => dataset.security_policy().unwrap_err(),
                Self::ChannelMaskHeader | Self::ChannelMaskValue => {
                    dataset.channel_mask().unwrap_err()
                }
            };
            assert!(
                err.to_string().contains(expected),
                "{self:?} expected error containing {expected:?}, got {err}"
            );
        }
    }
}

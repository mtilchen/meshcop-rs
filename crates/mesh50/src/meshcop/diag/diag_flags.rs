//! Diagnostic request flag bits accepted by diagnostic get/reset operations.
//!
//! The bit assignments match `NetDiagData::k*Bit` in the C++ reference so flag
//! values are portable between the two implementations.

/// Extended MAC Address TLV (0). Bit 0 of the flag word (`1 << 0`).
pub const EXT_MAC_ADDR: u64 = 1;
/// MAC Address (RLOC16) TLV (1).
pub const MAC_ADDR: u64 = 1 << 1;
/// Mode TLV (2).
pub const MODE: u64 = 1 << 2;
/// Route64 TLV (5).
pub const ROUTE64: u64 = 1 << 3;
/// Leader Data TLV (6).
pub const LEADER_DATA: u64 = 1 << 4;
/// IPv6 Address List TLV (8).
pub const IPV6_ADDRESSES: u64 = 1 << 5;
/// Child Table TLV (16).
pub const CHILD_TABLE: u64 = 1 << 6;
/// EUI-64 TLV (23).
pub const EUI64: u64 = 1 << 7;
/// MAC Counters TLV (9).
pub const MAC_COUNTERS: u64 = 1 << 8;
/// Child IPv6 Address List TLV (30).
pub const CHILD_IPV6_ADDRESSES: u64 = 1 << 9;
/// Network Data TLV (7).
pub const NETWORK_DATA: u64 = 1 << 10;
/// Timeout TLV (3).
pub const TIMEOUT: u64 = 1 << 11;
/// Connectivity TLV (4).
pub const CONNECTIVITY: u64 = 1 << 12;
/// Battery Level TLV (14).
pub const BATTERY_LEVEL: u64 = 1 << 13;
/// Supply Voltage TLV (15).
pub const SUPPLY_VOLTAGE: u64 = 1 << 14;
/// Channel Pages TLV (17).
pub const CHANNEL_PAGES: u64 = 1 << 15;
/// Type List TLV (18).
pub const TYPE_LIST: u64 = 1 << 16;

/// Every request flag understood by this crate.
pub const ALL: u64 = (1 << 17) - 1;

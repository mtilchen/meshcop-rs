//! DTLS constants for the Thread commissioner profile.

/// TLS_ECJPAKE_WITH_AES_128_CCM_8 cipher suite code point used by Thread.
pub const TLS_ECJPAKE_WITH_AES_128_CCM_8: u16 = 0xc0ff;

/// TLS_EMPTY_RENEGOTIATION_INFO_SCSV signaling cipher suite value.
pub const TLS_EMPTY_RENEGOTIATION_INFO_SCSV: u16 = 0x00ff;

/// DTLS 1.2 protocol version as it appears on the wire.
pub const DTLS_1_2_VERSION: u16 = 0xfefd;

/// TLS null compression method.
pub const TLS_COMPRESSION_NULL: u8 = 0;

/// TLS supported_groups extension type.
pub const EXTENSION_SUPPORTED_GROUPS: u16 = 10;

/// TLS max_fragment_length extension type.
pub const EXTENSION_MAX_FRAGMENT_LENGTH: u16 = 1;

/// TLS ec_point_formats extension type.
pub const EXTENSION_EC_POINT_FORMATS: u16 = 11;

/// TLS signature_algorithms extension type.
pub const EXTENSION_SIGNATURE_ALGORITHMS: u16 = 13;

/// Experimental TLS ECJPAKE KKPP extension type used by Thread stacks.
pub const EXTENSION_ECJPAKE_KKPP: u16 = 256;

/// TLS named group ID for secp256r1/P-256.
pub const NAMED_GROUP_SECP256R1: u16 = 23;

/// TLS point format ID for uncompressed points.
pub const EC_POINT_FORMAT_UNCOMPRESSED: u8 = 0;

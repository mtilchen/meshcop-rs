//! Tests for the DTLS profile modules.

use super::*;
use crate::ccm::{RecordProtectionKey, TLS_CCM_8_TAG_LEN, TLS_CCM_EXPLICIT_NONCE_LEN};
use crate::ecjpake::{EcJpakeParty, EcJpakeRole, RoundTwo};
use crate::handshake::MAX_HANDSHAKE_MESSAGE_LEN;
use crate::hello::ec_point_formats_extension;
use crate::util::{MAX_U24, read_u24, write_u24};
use rand_core::OsRng;

mod codec;
mod framing;
mod hello;
mod keys;
mod server_session;

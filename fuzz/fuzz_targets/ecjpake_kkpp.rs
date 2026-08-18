#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh50_dtls::ecjpake::{RoundOne, THREAD_CLIENT_ID, THREAD_SERVER_ID};

// EC J-PAKE round-one (ECJPAKEKeyKPPairList) decoding from the ClientHello /
// ServerHello kkpp extension. Point and proof validation must reject malformed
// or adversarial curve material without panicking.
fuzz_target!(|data: &[u8]| {
    let _ = RoundOne::decode_tls_kkpp(data, THREAD_CLIENT_ID);
    let _ = RoundOne::decode_tls_kkpp(data, THREAD_SERVER_ID);
});

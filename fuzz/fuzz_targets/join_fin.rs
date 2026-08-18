#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh50::commissioner::JoinerFinalizeInfo;

// JOIN_FIN.req payload parsing: TLV extraction plus UTF-8 validation of the
// vendor identification fields. Must never panic on attacker-controlled
// bytes arriving over a joiner DTLS session.
fuzz_target!(|data: &[u8]| {
    let _ = JoinerFinalizeInfo::from_payload(data);
});

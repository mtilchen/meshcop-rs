#![no_main]

use libfuzzer_sys::fuzz_target;
use meshcop::meshcop::NetDiagData;

// DIAG_GET.ans payload decoding: nested network-diagnostic TLVs including
// Route64, Child Table, Connectivity, and Thread Network Data prefix
// sub-TLVs. Must never panic on attacker-controlled bytes.
fuzz_target!(|data: &[u8]| {
    let _ = NetDiagData::decode(data);
});

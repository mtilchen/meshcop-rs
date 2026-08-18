#![no_main]

use libfuzzer_sys::fuzz_target;
use mesh50::dataset::Dataset;

// Operational dataset decoding: every typed accessor must validate fuzzed wire
// bytes without panicking.
fuzz_target!(|data: &[u8]| {
    if let Ok(dataset) = Dataset::from_bytes(data) {
        let _ = dataset.channel();
        let _ = dataset.pan_id();
        let _ = dataset.extended_pan_id();
        let _ = dataset.network_key();
        let _ = dataset.mesh_local_prefix();
        let _ = dataset.network_name();
        let _ = dataset.active_timestamp();
        let _ = dataset.pending_timestamp();
        let _ = dataset.delay_timer();
        let _ = dataset.security_policy();
        let _ = dataset.channel_mask();
        let _ = dataset.to_bytes();
    }
});

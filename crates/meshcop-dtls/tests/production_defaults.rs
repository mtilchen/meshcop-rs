//! Regression checks for production-only driver defaults.

#![cfg(feature = "test-support")]

use core::time::Duration;

#[test]
fn production_retransmit_interval_is_one_second() {
    assert_eq!(
        meshcop_dtls::test_support::driver_initial_retransmit_timeout(),
        Duration::from_secs(1)
    );
}

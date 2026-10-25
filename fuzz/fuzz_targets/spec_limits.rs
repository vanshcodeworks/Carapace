#![no_main]
//! Fuzz the limit parsers (sizes, durations, percents): hostile strings
//! must return errors, never panic, never overflow.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(s) = std::str::from_utf8(data) else { return };
    if let Ok(n) = carapace_core::policy::parse_bytes(s, "fuzz") {
        assert!(n <= u64::MAX);
    }
    if let Ok(d) = carapace_core::policy::parse_duration(s, "fuzz") {
        assert!(!d.is_zero());
        assert!(d <= std::time::Duration::from_secs(366 * 24 * 3600));
    }
});

#![no_main]
//! Fuzz the doctor/report JSON round-trip: hostile JSON must never panic
//! and must never deserialize into a semantically-invalid report.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    // Deserialize hostile JSON into the report model: must not panic.
    if let Ok(report) = serde_json::from_str::<carapace_core::DoctorReport>(text) {
        // Semantic invariants of a deserialized report:
        let ready = report.ready();
        let overall = report.overall();
        // ready() must agree with failed_required().
        if ready {
            assert!(report.failed_required().is_empty());
        } else {
            assert!(!report.failed_required().is_empty());
        }
        // overall() must be Fail exactly when not ready (fail-closed gate).
        assert_eq!(
            overall == carapace_core::Status::Fail,
            !ready,
            "doctor gate must be consistent"
        );
        // Round-trip stability.
        let re = serde_json::to_string(&report).expect("serialize always works");
        let back: carapace_core::DoctorReport =
            serde_json::from_str(&re).expect("our own JSON must parse");
        assert_eq!(back.checks.len(), report.checks.len());
        assert_eq!(back.ready(), ready);
    }
});

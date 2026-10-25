#![no_main]
//! Fuzz the policy parser: hostile TOML must never panic and must never
//! produce a policy that escapes validation invariants.

use libfuzzer_sys::fuzz_target;
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else { return };
    if let Ok(policy) = carapace_core::Policy::parse(text) {
        // Invariants that must hold for ANY parsed policy:
        let l = &policy.limits;
        assert!(l.timeout <= Duration::from_secs(24 * 3600), "timeout capped");
        assert!(l.memory_bytes > 0 && l.memory_bytes <= 1 << 40, "memory sane");
        assert!(l.max_processes > 0 && l.max_processes <= 100_000, "pids sane");
        assert!(l.cpu_percent > 0 && l.cpu_percent <= 100_00, "cpu sane");
        assert!(l.scratch_bytes <= 1 << 40, "scratch sane");
        assert!(l.max_output_bytes <= 1 << 30, "output cap sane");
        // Path invariants: absolute, no .., no sandbox internals.
        for p in policy.read_only.iter().chain(policy.read_write.iter()) {
            assert!(p.is_absolute(), "paths absolute");
            assert!(
                !p.components().any(|c| matches!(c, std::path::Component::ParentDir)),
                "no parent-dir components"
            );
            for forbidden in ["/proc", "/sys", "/dev", "/etc"] {
                assert!(!p.starts_with(forbidden), "no {forbidden} shadowing");
            }
        }
        // An allowlist network mode must never validate with garbage domains.
        if let carapace_core::NetworkMode::Allowlist(domains) = &policy.network {
            for d in domains {
                assert!(!d.is_empty() && d.len() <= 253, "domain length sane");
            }
        }
    }
    // Parsing must be deterministic: same input, same output.
    if let Ok(p1) = carapace_core::Policy::parse(text) {
        let p2 = carapace_core::Policy::parse(text).unwrap();
        assert_eq!(p1.limits.timeout, p2.limits.timeout);
        assert_eq!(p1.limits.memory_bytes, p2.limits.memory_bytes);
    }
});

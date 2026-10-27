//! Rendering layer for `cara doctor`: turns a [`DoctorReport`] into the
//! human-readable table or JSON. Kept separate from main() so it is
//! unit-testable.

use carapace_core::{DoctorReport, Status};

/// Renders the human-readable report. Ends with a verdict line.
pub fn render_human(report: &DoctorReport) -> String {
    let mut out = String::new();
    out.push_str("cara doctor — Tier 1 (native sandbox) environment check\n\n");
    let width = report
        .checks
        .iter()
        .map(|c| c.name.len())
        .max()
        .unwrap_or(10);
    for c in &report.checks {
        let tag = match c.status {
            Status::Ok => " ok  ",
            Status::Warn => "WARN ",
            Status::Fail => "FAIL ",
            Status::Info => " --  ",
        };
        let req = if c.required { "" } else { " (optional)" };
        out.push_str(&format!(
            "{tag}{:<width$}  {}{req}\n",
            c.name,
            c.detail,
            width = width
        ));
        if let Some(r) = &c.remedy
            && matches!(c.status, Status::Fail | Status::Warn)
        {
            let mut lines = r.lines();
            if let Some(first) = lines.next() {
                out.push_str(&format!("      fix: {first}\n"));
            }
            // Continuation lines align with the text after "fix: ".
            for line in lines {
                out.push_str(&format!("           {line}\n"));
            }
        }
    }
    out.push('\n');
    if report.ready() {
        match report.overall() {
            Status::Warn => out.push_str("Result: READY (with warnings listed above)\n"),
            _ => out.push_str("Result: READY — the native sandbox can run here\n"),
        }
    } else {
        out.push_str("Result: NOT READY — required capabilities missing. Carapace refuses\n");
        out.push_str("to run untrusted code in this environment (fail closed).\n");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use carapace_core::Check;

    #[test]
    fn ready_report_renders_ready() {
        let r = DoctorReport::new(vec![Check::ok("kernel", "Kernel", "Linux 6.18 (x86_64)")]);
        let s = render_human(&r);
        assert!(s.contains("READY"));
        assert!(!s.contains("NOT READY"));
    }

    #[test]
    fn multiline_remedy_is_indented_and_complete() {
        let r = DoctorReport::new(vec![Check::fail(
            "userns",
            "User namespaces",
            "denied",
            "line one\nline two\nUpstream: https://example.invalid/doc",
        )]);
        let s = render_human(&r);
        assert!(s.contains("      fix: line one\n"));
        assert!(s.contains("           line two\n"));
        assert!(s.contains("           Upstream: https://example.invalid/doc\n"));
    }

    #[test]
    fn failed_report_renders_remedy() {
        let r = DoctorReport::new(vec![
            Check::ok("kernel", "Kernel", "Linux 6.18 (x86_64)"),
            Check::fail(
                "landlock",
                "Landlock",
                "unavailable",
                "install a newer kernel",
            ),
        ]);
        let s = render_human(&r);
        assert!(s.contains("NOT READY"));
        assert!(s.contains("install a newer kernel"));
    }
}

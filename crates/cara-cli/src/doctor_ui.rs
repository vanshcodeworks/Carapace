//! Rendering layer for `cara doctor`: turns a [`DoctorReport`] into the
//! human-readable table or JSON. Kept separate from main() so it is
//! unit-testable.

use crate::style;
use carapace_core::{DoctorReport, Status};

/// Renders the human-readable report. Ends with a verdict line.
/// Colors are added only when the style module detects a real terminal.
pub fn render_human(report: &DoctorReport) -> String {
    let mut out = String::new();
    out.push_str(&style::accent("cara doctor"));
    out.push_str(&style::dim(" - Tier 1 native sandbox check\n\n"));
    let width = report
        .checks
        .iter()
        .map(|c| c.name.len())
        .max()
        .unwrap_or(10);
    for c in &report.checks {
        let glyph = style::glyph(c.status);
        let tag = match c.status {
            Status::Ok => style::ok(&format!("[{glyph}]")),
            Status::Warn => style::warn(&format!("[{glyph}]")),
            Status::Fail => style::fail(&format!("[{glyph}]")),
            Status::Info => style::info(&format!("[{glyph}]")),
        };
        let req = if c.required {
            String::new()
        } else {
            style::dim(" (optional)").to_string()
        };
        out.push_str(&format!(
            "{tag} {:<width$}  {}{}\n",
            c.name,
            c.detail,
            req,
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
            Status::Warn => out.push_str(&format!(
                "{} {}\n",
                style::warn("Result: READY"),
                style::dim("with warnings listed above")
            )),
            _ => out.push_str(&format!(
                "{} {}\n",
                style::ok("Result: READY"),
                style::dim("the native sandbox can run here")
            )),
        }
    } else {
        out.push_str(&format!(
            "{} {}\n",
            style::fail("Result: NOT READY"),
            style::dim("required capabilities missing")
        ));
        out.push_str(&style::dim(
            "Carapace refuses to run untrusted code here (fail closed).\n",
        ));
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

//! Terminal styling for the `cara` CLI.
//!
//! Colors are opt-out by design. They are disabled when stdout is not a
//! terminal, when `NO_COLOR` is set, or when `TERM=dumb`. `CLICOLOR_FORCE=1`
//! enables them in a pipe (useful for screenshots). Machine-readable JSON
//! never goes through these helpers.

use std::io::IsTerminal;
use std::sync::OnceLock;

static USE_COLOR: OnceLock<bool> = OnceLock::new();

/// Whether ANSI color should be emitted on this run.
pub fn use_color() -> bool {
    *USE_COLOR.get_or_init(|| {
        if std::env::var_os("CLICOLOR_FORCE").is_some_and(|v| v == "1") {
            return true;
        }
        if std::env::var_os("NO_COLOR").is_some() {
            return false;
        }
        if std::env::var("TERM").is_ok_and(|t| t == "dumb") {
            return false;
        }
        std::io::stdout().is_terminal()
    })
}

fn paint(code: &str, text: &str) -> String {
    if use_color() {
        format!("\x1b[{code}m{text}\x1b[0m")
    } else {
        text.to_string()
    }
}

/// Electric green semantic marker for healthy state.
pub fn ok(text: &str) -> String {
    paint("1;32", text)
}

/// Amber semantic marker for warnings.
pub fn warn(text: &str) -> String {
    paint("1;33", text)
}

/// Red semantic marker for failures.
pub fn fail(text: &str) -> String {
    paint("1;31", text)
}

/// Cyan marker for informational state.
pub fn info(text: &str) -> String {
    paint("1;36", text)
}

/// Bold text.
pub fn bold(text: &str) -> String {
    paint("1", text)
}

/// Dimmed text.
pub fn dim(text: &str) -> String {
    paint("2", text)
}

/// The brand accent used for titles.
pub fn accent(text: &str) -> String {
    paint("1;32", text)
}

/// A compact status glyph. Plain text keeps output readable in logs.
pub fn glyph(status: carapace_core::Status) -> &'static str {
    match status {
        carapace_core::Status::Ok => "ok",
        carapace_core::Status::Warn => "!!",
        carapace_core::Status::Fail => "XX",
        carapace_core::Status::Info => "--",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glyphs_are_stable() {
        assert_eq!(glyph(carapace_core::Status::Ok), "ok");
        assert_eq!(glyph(carapace_core::Status::Warn), "!!");
        assert_eq!(glyph(carapace_core::Status::Fail), "XX");
        assert_eq!(glyph(carapace_core::Status::Info), "--");
    }
}

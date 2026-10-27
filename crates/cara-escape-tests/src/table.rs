//! The public "What Carapace stops" table, generated from the catalog.
//!
//! This function is the single source of that table: docs and the README
//! consume its output so a claim can never appear without the test that
//! proves it.

use crate::Catalog;

/// Renders the "What Carapace stops" markdown table from the catalog.
///
/// One row per catalog entry: the attack (with its stable id) and the safe
/// result the suite asserts.
pub fn markdown() -> String {
    let mut out = String::new();
    out.push_str("# What Carapace stops\n\n");
    out.push_str(
        "Every row is a test in the escape suite (crate `carapace-escape-tests`): \
         the payload runs through the real sandbox and the suite asserts the \
         documented result.\n\n",
    );
    out.push_str("| Attack | Result |\n|---|---|\n");
    for t in Catalog::all() {
        out.push_str(&format!("| `{}` — {} | {} |\n", t.id, t.name, t.expected));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_lists_every_catalog_entry() {
        let md = markdown();
        assert!(md.starts_with("# What Carapace stops"), "bad header:\n{md}");
        assert!(md.contains("| Attack | Result |"), "bad header:\n{md}");
        for t in crate::Catalog::all() {
            assert!(
                md.contains(&format!("| `{}` — ", t.id)),
                "table is missing entry {}:\n{md}",
                t.id
            );
        }
    }

    #[test]
    fn readme_table_matches_the_catalog() {
        // The README claims the table is generated from the catalog. Until a
        // generator exists, this test is what makes that claim true: every
        // generated row must be present verbatim in README.md, and no
        // catalog id may be missing from it.
        let readme = include_str!("../../../README.md");
        let md = markdown();
        let missing: Vec<&str> = md
            .lines()
            .filter(|l| l.starts_with("| `"))
            .filter(|line| !readme.contains(line))
            .collect();
        assert!(
            missing.is_empty(),
            "README is missing {} catalog row(s) (update README from the catalog):\n{}",
            missing.len(),
            missing.join("\n")
        );
        for t in crate::Catalog::all() {
            assert!(
                readme.contains(&format!("| `{}` — ", t.id)),
                "README does not mention catalog entry {}",
                t.id
            );
        }
    }

    #[test]
    fn table_rows_are_markdown_safe() {
        // The cells are joined with '|'; field text must not contain the
        // delimiter or the table silently grows columns.
        for t in crate::Catalog::all() {
            assert!(!t.name.contains('|'), "name of {} contains '|'", t.id);
            assert!(
                !t.expected.contains('|'),
                "expected of {} contains '|'",
                t.id
            );
        }
    }
}

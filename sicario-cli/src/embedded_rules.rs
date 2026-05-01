//! Embedded rule assets — the entire `rules/` directory is compiled into the
//! binary at build time via `rust-embed`. This guarantees the full rule set is
//! always available regardless of the filesystem layout on the user's machine.
//!
//! The `RULES_DIR` env var (set in `build.rs` or the workspace root) points
//! `rust-embed` at the correct path relative to the crate root.
//!
//! Usage:
//! ```no_run
//! use sicario_cli::embedded_rules::iter_embedded_rules;
//! for (path, content) in iter_embedded_rules() {
//!     println!("{}: {} bytes", path, content.len());
//! }
//! ```

use rust_embed::RustEmbed;

/// All YAML files under `sicario-cli/rules/` embedded at compile time.
///
/// The `folder` path is relative to the crate root (`sicario-cli/`).
/// Only `.yaml` and `.yml` files are included; everything else is excluded.
#[derive(RustEmbed)]
#[folder = "rules/"]
#[include = "**/*.yaml"]
#[include = "**/*.yml"]
pub struct EmbeddedRules;

/// Returns an iterator of `(path, yaml_content)` for every embedded rule file.
///
/// The path is the relative path within the `rules/` directory, e.g.
/// `"javascript/sql_injection.yaml"`. It is used only for error messages.
pub fn iter_embedded_rules() -> impl Iterator<Item = (String, String)> {
    EmbeddedRules::iter().filter_map(|path| {
        let path_str = path.to_string();
        let file = EmbeddedRules::get(&path_str)?;
        let content = std::str::from_utf8(file.data.as_ref()).ok()?.to_string();
        Some((path_str, content))
    })
}

/// Returns the total number of embedded rule files.
pub fn embedded_rule_file_count() -> usize {
    EmbeddedRules::iter().count()
}

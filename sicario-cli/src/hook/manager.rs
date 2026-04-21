//! Pre-commit hook management — install, uninstall, and status.
//!
//! The hook script uses marker comments (`# BEGIN SICARIO HOOK` / `# END SICARIO HOOK`)
//! to delimit the Sicario section, allowing safe append and removal without
//! disturbing other hook content.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

// ── Marker constants ──────────────────────────────────────────────────────────

const BEGIN_MARKER: &str = "# BEGIN SICARIO HOOK";
const END_MARKER: &str = "# END SICARIO HOOK";
const SHEBANG: &str = "#!/bin/sh";

const SICARIO_HOOK_BLOCK: &str = "\
# BEGIN SICARIO HOOK
if [ \"$SICARIO_SKIP_HOOK\" = \"1\" ]; then
  exit 0
fi
sicario scan --staged --severity-threshold high --quiet
# END SICARIO HOOK";

// ── Public types ──────────────────────────────────────────────────────────────

/// Status of the Sicario pre-commit hook.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HookStatus {
    /// Whether the Sicario hook section is present in the pre-commit script.
    pub installed: bool,
    /// The command line embedded in the hook, if installed.
    pub command: Option<String>,
}

/// Trait for managing the Git pre-commit hook.
pub trait HookManagement {
    fn install(&self) -> Result<()>;
    fn uninstall(&self) -> Result<()>;
    fn status(&self) -> Result<HookStatus>;
}

/// Concrete implementation backed by a Git repository path.
pub struct HookManager {
    /// Path to the `.git/hooks` directory.
    hooks_dir: PathBuf,
}

impl HookManager {
    /// Create a `HookManager` for the repository containing `working_dir`.
    ///
    /// Uses `git2::Repository::discover` to locate the `.git` directory.
    pub fn new(working_dir: &Path) -> Result<Self> {
        let repo = git2::Repository::discover(working_dir).with_context(|| {
            format!(
                "Not a git repository (or any parent): {}",
                working_dir.display()
            )
        })?;
        let git_dir = repo.path().to_path_buf(); // e.g. /repo/.git/
        let hooks_dir = git_dir.join("hooks");
        Ok(Self { hooks_dir })
    }

    /// Build a `HookManager` pointing at an explicit hooks directory (useful for tests).
    #[cfg(test)]
    fn with_hooks_dir(hooks_dir: PathBuf) -> Self {
        Self { hooks_dir }
    }

    /// Path to the pre-commit hook script.
    fn pre_commit_path(&self) -> PathBuf {
        self.hooks_dir.join("pre-commit")
    }
}

impl HookManagement for HookManager {
    fn install(&self) -> Result<()> {
        let path = self.pre_commit_path();

        // Ensure hooks directory exists.
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let content = if path.exists() {
            let existing = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;

            if existing.contains(BEGIN_MARKER) {
                // Already installed — nothing to do.
                return Ok(());
            }

            // Append to existing hook.
            format!("{}\n{}\n", existing.trim_end(), SICARIO_HOOK_BLOCK)
        } else {
            // Create a new hook file.
            format!("{}\n{}\n", SHEBANG, SICARIO_HOOK_BLOCK)
        };

        std::fs::write(&path, &content)
            .with_context(|| format!("Failed to write {}", path.display()))?;

        // Make executable on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o755);
            std::fs::set_permissions(&path, perms)?;
        }

        Ok(())
    }

    fn uninstall(&self) -> Result<()> {
        let path = self.pre_commit_path();

        if !path.exists() {
            return Ok(());
        }

        let existing = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {}", path.display()))?;

        let cleaned = remove_sicario_block(&existing);

        // If only the shebang (or whitespace) remains, delete the file.
        let trimmed = cleaned.trim();
        if trimmed.is_empty() || trimmed == SHEBANG {
            std::fs::remove_file(&path)?;
        } else {
            std::fs::write(&path, &cleaned)?;
        }

        Ok(())
    }

    fn status(&self) -> Result<HookStatus> {
        let path = self.pre_commit_path();

        if !path.exists() {
            return Ok(HookStatus {
                installed: false,
                command: None,
            });
        }

        let content = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {}", path.display()))?;

        if let Some(cmd) = extract_sicario_command(&content) {
            Ok(HookStatus {
                installed: true,
                command: Some(cmd),
            })
        } else {
            Ok(HookStatus {
                installed: false,
                command: None,
            })
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Remove everything between (and including) the BEGIN/END markers.
fn remove_sicario_block(content: &str) -> String {
    let mut result = String::new();
    let mut inside_block = false;

    for line in content.lines() {
        if line.trim() == BEGIN_MARKER {
            inside_block = true;
            continue;
        }
        if line.trim() == END_MARKER {
            inside_block = false;
            continue;
        }
        if !inside_block {
            result.push_str(line);
            result.push('\n');
        }
    }

    result
}

/// Extract the sicario command line from within the markers, if present.
fn extract_sicario_command(content: &str) -> Option<String> {
    let mut inside = false;
    for line in content.lines() {
        if line.trim() == BEGIN_MARKER {
            inside = true;
            continue;
        }
        if line.trim() == END_MARKER {
            break;
        }
        if inside {
            let trimmed = line.trim();
            if trimmed.starts_with("sicario ") {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn setup() -> (TempDir, HookManager) {
        let tmp = TempDir::new().unwrap();
        let hooks_dir = tmp.path().join("hooks");
        std::fs::create_dir_all(&hooks_dir).unwrap();
        let mgr = HookManager::with_hooks_dir(hooks_dir);
        (tmp, mgr)
    }

    #[test]
    fn install_creates_new_hook() {
        let (_tmp, mgr) = setup();
        mgr.install().unwrap();

        let content = std::fs::read_to_string(mgr.pre_commit_path()).unwrap();
        assert!(content.starts_with(SHEBANG));
        assert!(content.contains(BEGIN_MARKER));
        assert!(content.contains(END_MARKER));
        assert!(content.contains("sicario scan --staged --severity-threshold high --quiet"));
        assert!(content.contains("SICARIO_SKIP_HOOK"));
    }

    #[test]
    fn install_appends_to_existing_hook() {
        let (_tmp, mgr) = setup();
        let path = mgr.pre_commit_path();
        std::fs::write(&path, "#!/bin/sh\necho 'existing hook'\n").unwrap();

        mgr.install().unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("echo 'existing hook'"));
        assert!(content.contains(BEGIN_MARKER));
        assert!(content.contains("sicario scan --staged"));
    }

    #[test]
    fn install_is_idempotent() {
        let (_tmp, mgr) = setup();
        mgr.install().unwrap();
        mgr.install().unwrap();

        let content = std::fs::read_to_string(mgr.pre_commit_path()).unwrap();
        // Should only contain one BEGIN marker.
        assert_eq!(content.matches(BEGIN_MARKER).count(), 1);
    }

    #[test]
    fn uninstall_removes_sicario_block() {
        let (_tmp, mgr) = setup();
        let path = mgr.pre_commit_path();
        let content = format!(
            "#!/bin/sh\necho 'before'\n{}\necho 'after'\n",
            SICARIO_HOOK_BLOCK
        );
        std::fs::write(&path, &content).unwrap();

        mgr.uninstall().unwrap();

        let result = std::fs::read_to_string(&path).unwrap();
        assert!(!result.contains(BEGIN_MARKER));
        assert!(!result.contains(END_MARKER));
        assert!(result.contains("echo 'before'"));
        assert!(result.contains("echo 'after'"));
    }

    #[test]
    fn uninstall_deletes_file_when_only_shebang_remains() {
        let (_tmp, mgr) = setup();
        mgr.install().unwrap();
        assert!(mgr.pre_commit_path().exists());

        mgr.uninstall().unwrap();
        assert!(!mgr.pre_commit_path().exists());
    }

    #[test]
    fn uninstall_noop_when_no_file() {
        let (_tmp, mgr) = setup();
        // Should not error.
        mgr.uninstall().unwrap();
    }

    #[test]
    fn status_reports_not_installed_when_no_file() {
        let (_tmp, mgr) = setup();
        let st = mgr.status().unwrap();
        assert!(!st.installed);
        assert!(st.command.is_none());
    }

    #[test]
    fn status_reports_installed_with_command() {
        let (_tmp, mgr) = setup();
        mgr.install().unwrap();

        let st = mgr.status().unwrap();
        assert!(st.installed);
        assert_eq!(
            st.command.as_deref(),
            Some("sicario scan --staged --severity-threshold high --quiet")
        );
    }

    #[test]
    fn status_reports_not_installed_when_markers_absent() {
        let (_tmp, mgr) = setup();
        std::fs::write(mgr.pre_commit_path(), "#!/bin/sh\necho hello\n").unwrap();

        let st = mgr.status().unwrap();
        assert!(!st.installed);
    }

    #[test]
    fn remove_sicario_block_preserves_surrounding() {
        let input = format!(
            "#!/bin/sh\necho before\n{}\necho after\n",
            SICARIO_HOOK_BLOCK
        );
        let result = remove_sicario_block(&input);
        assert!(!result.contains(BEGIN_MARKER));
        assert!(result.contains("echo before"));
        assert!(result.contains("echo after"));
    }

    #[test]
    fn remove_sicario_block_noop_when_absent() {
        let input = "#!/bin/sh\necho hello\n";
        let result = remove_sicario_block(input);
        assert_eq!(result, input);
    }

    #[cfg(unix)]
    #[test]
    fn install_sets_executable_permission() {
        use std::os::unix::fs::PermissionsExt;
        let (_tmp, mgr) = setup();
        mgr.install().unwrap();

        let meta = std::fs::metadata(mgr.pre_commit_path()).unwrap();
        let mode = meta.permissions().mode();
        assert!(mode & 0o111 != 0, "hook should be executable");
    }
}

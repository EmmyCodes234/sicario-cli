//! Suppression pattern learning and auto-suppression suggestions.
//!
//! Records suppression patterns (rule ID + AST context) and, after 3+
//! suppressions for the same pattern, flags subsequent matches as
//! "suggested suppression". When `--auto-suppress` is active, matching
//! findings are excluded from results entirely.
//!
//! Learned patterns persist in `.sicario/learned_suppressions.json`.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

use crate::engine::vulnerability::Finding;

// ── Threshold ─────────────────────────────────────────────────────────────────

/// Minimum number of recorded suppressions before a pattern triggers
/// automatic suggestions.
const SUGGESTION_THRESHOLD: usize = 3;

// ── Data model ────────────────────────────────────────────────────────────────

/// A single learned suppression pattern persisted across scans.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedSuppression {
    pub rule_id: String,
    pub ast_node_type: String,
    pub context_hash: String,
    pub match_count: usize,
    pub example_snippet: String,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

/// Suggestion returned when a finding matches a learned pattern.
#[derive(Debug, Clone)]
pub struct SuppressionSuggestion {
    pub rule_id: String,
    pub match_count: usize,
    pub example_snippet: String,
}

// ── Trait ──────────────────────────────────────────────────────────────────────

/// Core interface for the suppression learner.
pub trait SuppressionLearning {
    /// Record a suppression event for the given finding and AST context.
    fn record(&mut self, finding: &Finding, ast_context: &str) -> Result<()>;

    /// Check whether a finding matches a learned pattern that has reached
    /// the suggestion threshold.
    fn suggest(&self, finding: &Finding) -> Option<SuppressionSuggestion>;

    /// Filter findings: when auto-suppress is active, exclude those matching
    /// learned patterns above the threshold. Returns the kept findings.
    fn auto_suppress(&self, findings: &[Finding]) -> Vec<Finding>;
}

// ── Implementation ────────────────────────────────────────────────────────────

/// Concrete suppression learner backed by a JSON file.
#[derive(Debug, Clone)]
pub struct SuppressionLearner {
    patterns: Vec<LearnedSuppression>,
    storage_path: PathBuf,
}

impl SuppressionLearner {
    // ── Construction / persistence ────────────────────────────────────────

    /// Create a new learner that persists to the given directory.
    /// The file `.sicario/learned_suppressions.json` is resolved relative
    /// to `project_root`.
    pub fn new(project_root: &Path) -> Self {
        let storage_path = project_root
            .join(".sicario")
            .join("learned_suppressions.json");
        Self {
            patterns: Vec::new(),
            storage_path,
        }
    }

    /// Load previously persisted patterns from disk. If the file does not
    /// exist, the learner starts empty (not an error).
    pub fn load(project_root: &Path) -> Result<Self> {
        let mut learner = Self::new(project_root);
        if learner.storage_path.exists() {
            let data = std::fs::read_to_string(&learner.storage_path)
                .with_context(|| {
                    format!(
                        "Failed to read learned suppressions from {:?}",
                        learner.storage_path
                    )
                })?;
            learner.patterns = serde_json::from_str(&data).with_context(|| {
                format!(
                    "Failed to parse learned suppressions from {:?}",
                    learner.storage_path
                )
            })?;
        }
        Ok(learner)
    }

    /// Persist current patterns to disk.
    pub fn save(&self) -> Result<()> {
        if let Some(parent) = self.storage_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("Failed to create directory {:?}", parent)
            })?;
        }
        let json = serde_json::to_string_pretty(&self.patterns)
            .context("Failed to serialize learned suppressions")?;
        std::fs::write(&self.storage_path, json).with_context(|| {
            format!(
                "Failed to write learned suppressions to {:?}",
                self.storage_path
            )
        })?;
        Ok(())
    }

    // ── Query helpers ─────────────────────────────────────────────────────

    /// Return all learned patterns (for `suppressions list`).
    pub fn list(&self) -> &[LearnedSuppression] {
        &self.patterns
    }

    /// Clear all learned patterns (for `suppressions reset`).
    pub fn reset(&mut self) {
        self.patterns.clear();
    }

    /// Count of findings that would be auto-suppressed from the given list.
    pub fn auto_suppressed_count(&self, findings: &[Finding]) -> usize {
        findings
            .iter()
            .filter(|f| self.suggest(f).is_some())
            .count()
    }
}

// ── Context hashing ───────────────────────────────────────────────────────────

/// Compute a context hash from the AST node type and a normalised snippet.
///
/// Normalisation strips whitespace and lowercases so that minor formatting
/// differences don't create separate patterns.
fn context_hash(ast_context: &str, snippet: &str) -> String {
    let normalised: String = snippet
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>()
        .to_lowercase();

    let mut hasher = Sha256::new();
    hasher.update(ast_context.as_bytes());
    hasher.update(b"|");
    hasher.update(normalised.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Derive a context hash for a finding (used when checking suggestions).
/// When we don't have an explicit AST context string we fall back to
/// the snippet itself as the AST context proxy.
fn finding_context_hash(finding: &Finding) -> String {
    context_hash(&finding.snippet, &finding.snippet)
}

// ── Trait implementation ──────────────────────────────────────────────────────

impl SuppressionLearning for SuppressionLearner {
    fn record(&mut self, finding: &Finding, ast_context: &str) -> Result<()> {
        let hash = context_hash(ast_context, &finding.snippet);
        let now = Utc::now();

        if let Some(existing) = self
            .patterns
            .iter_mut()
            .find(|p| p.rule_id == finding.rule_id && p.context_hash == hash)
        {
            existing.match_count += 1;
            existing.last_seen = now;
        } else {
            self.patterns.push(LearnedSuppression {
                rule_id: finding.rule_id.clone(),
                ast_node_type: ast_context.to_string(),
                context_hash: hash,
                match_count: 1,
                example_snippet: finding.snippet.clone(),
                first_seen: now,
                last_seen: now,
            });
        }

        self.save()?;
        Ok(())
    }

    fn suggest(&self, finding: &Finding) -> Option<SuppressionSuggestion> {
        let hash = finding_context_hash(finding);

        self.patterns
            .iter()
            .find(|p| {
                p.rule_id == finding.rule_id
                    && p.context_hash == hash
                    && p.match_count >= SUGGESTION_THRESHOLD
            })
            .map(|p| SuppressionSuggestion {
                rule_id: p.rule_id.clone(),
                match_count: p.match_count,
                example_snippet: p.example_snippet.clone(),
            })
    }

    fn auto_suppress(&self, findings: &[Finding]) -> Vec<Finding> {
        findings
            .iter()
            .filter(|f| self.suggest(f).is_none())
            .cloned()
            .collect()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::vulnerability::Severity;
    use std::path::PathBuf;
    use uuid::Uuid;

    /// Helper to build a minimal `Finding` for testing.
    fn make_finding(rule_id: &str, snippet: &str) -> Finding {
        Finding {
            id: Uuid::new_v4(),
            rule_id: rule_id.to_string(),
            rule_name: String::new(),
            file_path: PathBuf::from("test.js"),
            line: 1,
            column: 1,
            end_line: None,
            end_column: None,
            snippet: snippet.to_string(),
            severity: Severity::High,
            confidence_score: 0.9,
            reachable: false,
            cloud_exposed: None,
            cwe_id: None,
            owasp_category: None,
            fingerprint: String::new(),
            dataflow_trace: None,
            suppressed: false,
            suppression_rule: None,
            suggested_suppression: false,
        }
    }

    #[test]
    fn test_record_increments_count() {
        let tmp = tempfile::tempdir().unwrap();
        let mut learner = SuppressionLearner::new(tmp.path());

        let f = make_finding("sql-injection", "query(input)");
        learner.record(&f, "call_expression").unwrap();
        learner.record(&f, "call_expression").unwrap();

        assert_eq!(learner.list().len(), 1);
        assert_eq!(learner.list()[0].match_count, 2);
    }

    #[test]
    fn test_suggest_below_threshold_returns_none() {
        let tmp = tempfile::tempdir().unwrap();
        let mut learner = SuppressionLearner::new(tmp.path());

        let f = make_finding("sql-injection", "query(input)");
        learner.record(&f, "query(input)").unwrap();
        learner.record(&f, "query(input)").unwrap();

        assert!(learner.suggest(&f).is_none());
    }

    #[test]
    fn test_suggest_at_threshold_returns_some() {
        let tmp = tempfile::tempdir().unwrap();
        let mut learner = SuppressionLearner::new(tmp.path());

        let f = make_finding("sql-injection", "query(input)");
        for _ in 0..3 {
            learner.record(&f, "query(input)").unwrap();
        }

        let suggestion = learner.suggest(&f);
        assert!(suggestion.is_some());
        assert_eq!(suggestion.unwrap().match_count, 3);
    }

    #[test]
    fn test_auto_suppress_excludes_matching() {
        let tmp = tempfile::tempdir().unwrap();
        let mut learner = SuppressionLearner::new(tmp.path());

        let f = make_finding("sql-injection", "query(input)");
        for _ in 0..3 {
            learner.record(&f, "query(input)").unwrap();
        }

        let other = make_finding("xss", "innerHTML = data");
        let findings = vec![f.clone(), other.clone()];
        let kept = learner.auto_suppress(&findings);

        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].rule_id, "xss");
    }

    #[test]
    fn test_persistence_round_trip() {
        let tmp = tempfile::tempdir().unwrap();

        {
            let mut learner = SuppressionLearner::new(tmp.path());
            let f = make_finding("cmd-injection", "exec(cmd)");
            for _ in 0..4 {
                learner.record(&f, "exec(cmd)").unwrap();
            }
        }

        let loaded = SuppressionLearner::load(tmp.path()).unwrap();
        assert_eq!(loaded.list().len(), 1);
        assert_eq!(loaded.list()[0].match_count, 4);
        assert_eq!(loaded.list()[0].rule_id, "cmd-injection");
    }

    #[test]
    fn test_reset_clears_patterns() {
        let tmp = tempfile::tempdir().unwrap();
        let mut learner = SuppressionLearner::new(tmp.path());

        let f = make_finding("xss", "innerHTML = data");
        learner.record(&f, "assignment_expression").unwrap();
        assert_eq!(learner.list().len(), 1);

        learner.reset();
        assert!(learner.list().is_empty());
    }

    #[test]
    fn test_load_missing_file_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let learner = SuppressionLearner::load(tmp.path()).unwrap();
        assert!(learner.list().is_empty());
    }

    #[test]
    fn test_different_rules_tracked_separately() {
        let tmp = tempfile::tempdir().unwrap();
        let mut learner = SuppressionLearner::new(tmp.path());

        let f1 = make_finding("sql-injection", "query(input)");
        let f2 = make_finding("xss", "query(input)");

        for _ in 0..3 {
            learner.record(&f1, "query(input)").unwrap();
        }
        learner.record(&f2, "query(input)").unwrap();

        assert!(learner.suggest(&f1).is_some());
        assert!(learner.suggest(&f2).is_none());
    }

    #[test]
    fn test_auto_suppressed_count() {
        let tmp = tempfile::tempdir().unwrap();
        let mut learner = SuppressionLearner::new(tmp.path());

        let f = make_finding("sql-injection", "query(input)");
        for _ in 0..3 {
            learner.record(&f, "query(input)").unwrap();
        }

        let other = make_finding("xss", "innerHTML = data");
        let findings = vec![f.clone(), other.clone()];
        assert_eq!(learner.auto_suppressed_count(&findings), 1);
    }
}

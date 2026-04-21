//! Sicario LSP Server — JSON-RPC over stdin/stdout.
//!
//! Provides real-time security diagnostics in editors that support the
//! Language Server Protocol. Findings are mapped to `Diagnostic` objects
//! with severity-appropriate levels and quick-fix code actions.

use std::collections::HashMap;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::Result;
use lsp_server::{Connection, Message, Notification, Request, RequestId, Response};
use lsp_types::notification::{
    DidChangeTextDocument, DidCloseTextDocument, DidOpenTextDocument, DidSaveTextDocument,
    Notification as _, PublishDiagnostics,
};
use lsp_types::request::{CodeActionRequest, Request as _};
use lsp_types::{
    CodeAction, CodeActionKind, CodeActionOptions, CodeActionOrCommand, CodeActionParams,
    CodeActionProviderCapability, CodeActionResponse, Diagnostic, DiagnosticSeverity,
    DidChangeTextDocumentParams, DidCloseTextDocumentParams, DidOpenTextDocumentParams,
    DidSaveTextDocumentParams, InitializeParams, NumberOrString, Position, PublishDiagnosticsParams,
    Range, ServerCapabilities, TextDocumentSyncCapability, TextDocumentSyncKind, TextEdit, Url,
    WorkspaceEdit,
};
use serde_json::Value;

use crate::engine::vulnerability::{Finding, Severity};
use crate::engine::SastEngine;
use crate::scanner::SuppressionParser;

/// Default debounce interval in milliseconds.
const DEBOUNCE_MS: u64 = 500;

/// Sicario LSP server state.
pub struct SicarioLspServer {
    /// Project root directory.
    project_root: PathBuf,
    /// Rule file paths to load.
    rule_paths: Vec<PathBuf>,
    /// Debounce interval for scan requests.
    debounce_ms: u64,
    /// Tracks the last change timestamp per document URI for debouncing.
    pending_scans: HashMap<Url, Instant>,
    /// Cached diagnostics per document URI.
    diagnostics_cache: HashMap<Url, Vec<Diagnostic>>,
    /// Open document contents (for unsaved buffers).
    open_documents: HashMap<Url, String>,
}

impl SicarioLspServer {
    /// Create a new LSP server for the given project root.
    pub fn new(project_root: PathBuf, rule_paths: Vec<PathBuf>) -> Self {
        Self {
            project_root,
            rule_paths,
            debounce_ms: DEBOUNCE_MS,
            pending_scans: HashMap::new(),
            diagnostics_cache: HashMap::new(),
            open_documents: HashMap::new(),
        }
    }

    /// Run the LSP server on stdin/stdout. Blocks until the client disconnects.
    pub fn run(mut self) -> Result<()> {
        let (connection, io_threads) = Connection::stdio();

        let server_capabilities = serde_json::to_value(Self::capabilities())?;
        connection.initialize(server_capabilities)?;

        self.main_loop(&connection)?;

        io_threads.join()?;
        Ok(())
    }

    /// Advertised server capabilities.
    fn capabilities() -> ServerCapabilities {
        ServerCapabilities {
            text_document_sync: Some(TextDocumentSyncCapability::Kind(
                TextDocumentSyncKind::FULL,
            )),
            code_action_provider: Some(CodeActionProviderCapability::Options(
                CodeActionOptions {
                    code_action_kinds: Some(vec![CodeActionKind::QUICKFIX]),
                    ..Default::default()
                },
            )),
            ..Default::default()
        }
    }

    /// Main message loop — reads JSON-RPC messages and dispatches them.
    fn main_loop(&mut self, connection: &Connection) -> Result<()> {
        for msg in &connection.receiver {
            match msg {
                Message::Request(req) => {
                    if connection.handle_shutdown(&req)? {
                        return Ok(());
                    }
                    self.handle_request(req, connection)?;
                }
                Message::Notification(notif) => {
                    self.handle_notification(notif, connection)?;
                }
                Message::Response(_resp) => {
                    // We don't send requests to the client that need responses.
                }
            }

            // Process any pending debounced scans.
            self.flush_pending_scans(connection)?;
        }
        Ok(())
    }

    // ── Request handling ──────────────────────────────────────────────────

    fn handle_request(&mut self, req: Request, connection: &Connection) -> Result<()> {
        if req.method == CodeActionRequest::METHOD {
            let (id, params): (RequestId, CodeActionParams) =
                req.extract(CodeActionRequest::METHOD)?;
            let actions = self.handle_code_action(params);
            let result = serde_json::to_value(actions)?;
            connection
                .sender
                .send(Message::Response(Response::new_ok(id, result)))?;
        }
        Ok(())
    }

    // ── Notification handling ─────────────────────────────────────────────

    fn handle_notification(
        &mut self,
        notif: Notification,
        connection: &Connection,
    ) -> Result<()> {
        match notif.method.as_str() {
            DidOpenTextDocument::METHOD => {
                let params: DidOpenTextDocumentParams =
                    serde_json::from_value(notif.params)?;
                let uri = params.text_document.uri.clone();
                self.open_documents
                    .insert(uri.clone(), params.text_document.text);
                // Scan immediately on open.
                self.scan_and_publish(&uri, connection)?;
            }
            DidChangeTextDocument::METHOD => {
                let params: DidChangeTextDocumentParams =
                    serde_json::from_value(notif.params)?;
                let uri = params.text_document.uri.clone();
                // Full sync — take the last content change.
                if let Some(change) = params.content_changes.into_iter().last() {
                    self.open_documents.insert(uri.clone(), change.text);
                }
                // Debounce: record the time, actual scan happens in flush.
                self.pending_scans.insert(uri, Instant::now());
            }
            DidSaveTextDocument::METHOD => {
                let params: DidSaveTextDocumentParams =
                    serde_json::from_value(notif.params)?;
                let uri = params.text_document.uri;
                // On save, scan immediately (bypass debounce).
                self.pending_scans.remove(&uri);
                self.scan_and_publish(&uri, connection)?;
            }
            DidCloseTextDocument::METHOD => {
                let params: DidCloseTextDocumentParams =
                    serde_json::from_value(notif.params)?;
                let uri = params.text_document.uri;
                self.open_documents.remove(&uri);
                self.pending_scans.remove(&uri);
                // Clear diagnostics for the closed document.
                self.diagnostics_cache.remove(&uri);
                self.publish_diagnostics(&uri, vec![], connection)?;
            }
            _ => {}
        }
        Ok(())
    }

    // ── Debounce flush ────────────────────────────────────────────────────

    fn flush_pending_scans(&mut self, connection: &Connection) -> Result<()> {
        let debounce = Duration::from_millis(self.debounce_ms);
        let now = Instant::now();

        let ready: Vec<Url> = self
            .pending_scans
            .iter()
            .filter(|(_, ts)| now.duration_since(**ts) >= debounce)
            .map(|(uri, _)| uri.clone())
            .collect();

        for uri in ready {
            self.pending_scans.remove(&uri);
            self.scan_and_publish(&uri, connection)?;
        }
        Ok(())
    }

    // ── Scanning & diagnostics ────────────────────────────────────────────

    /// Scan a single document and publish diagnostics to the client.
    fn scan_and_publish(&mut self, uri: &Url, connection: &Connection) -> Result<()> {
        let file_path = match uri_to_path(uri) {
            Some(p) => p,
            None => return Ok(()),
        };

        // Skip files that aren't in a supported language.
        if crate::parser::Language::from_path(&file_path).is_none() {
            return Ok(());
        }

        let findings = self.scan_file(&file_path)?;
        let diagnostics = self.findings_to_diagnostics(&findings, &file_path);

        self.diagnostics_cache
            .insert(uri.clone(), diagnostics.clone());
        self.publish_diagnostics(uri, diagnostics, connection)?;
        Ok(())
    }

    /// Run the SAST engine on a single file and return findings.
    fn scan_file(&self, path: &Path) -> Result<Vec<Finding>> {
        let mut engine = SastEngine::new(&self.project_root)?;
        for rule_path in &self.rule_paths {
            if rule_path.exists() {
                let _ = engine.load_rules(rule_path);
            }
        }

        let vulns = engine.scan_file(path)?;
        let suppression_parser = SuppressionParser::new();
        let source = std::fs::read_to_string(path).unwrap_or_default();

        let findings: Vec<Finding> = vulns
            .into_iter()
            .map(|v| {
                let rule_name = engine
                    .get_rule(&v.rule_id)
                    .map(|r| r.name.clone())
                    .unwrap_or_else(|| v.rule_id.clone());
                let mut f = Finding::from_vulnerability(&v, &rule_name);

                // Apply inline suppression check.
                let result = suppression_parser.is_sast_suppressed(&source, f.line, &f.rule_id);
                f.suppressed = result.suppressed;
                f.suppression_rule = result.rule_id;
                f
            })
            .filter(|f| !f.suppressed)
            .collect();

        Ok(findings)
    }

    /// Convert findings to LSP diagnostics.
    fn findings_to_diagnostics(&self, findings: &[Finding], _path: &Path) -> Vec<Diagnostic> {
        findings
            .iter()
            .map(|f| {
                let severity = match f.severity {
                    Severity::Critical | Severity::High => DiagnosticSeverity::ERROR,
                    Severity::Medium => DiagnosticSeverity::WARNING,
                    Severity::Low | Severity::Info => DiagnosticSeverity::INFORMATION,
                };

                let line = if f.line > 0 { f.line - 1 } else { 0 } as u32;
                let col = if f.column > 0 { f.column - 1 } else { 0 } as u32;
                let end_line = f.end_line.map(|l| if l > 0 { l - 1 } else { 0 } as u32).unwrap_or(line);
                let end_col = f.end_column.map(|c| c as u32).unwrap_or(col + 1);

                let range = Range {
                    start: Position::new(line, col),
                    end: Position::new(end_line, end_col),
                };

                let cwe_part = f
                    .cwe_id
                    .as_ref()
                    .map(|c| format!(" [{}]", c))
                    .unwrap_or_default();
                let confidence_pct = (f.confidence_score * 100.0) as u32;

                let message = format!(
                    "{}: {}{} ({}% confidence)",
                    f.rule_id, f.rule_name, cwe_part, confidence_pct
                );

                // Pack extra data for code actions.
                let data = serde_json::json!({
                    "ruleId": f.rule_id,
                    "ruleName": f.rule_name,
                    "cweId": f.cwe_id,
                    "confidence": f.confidence_score,
                    "snippet": f.snippet,
                });

                Diagnostic {
                    range,
                    severity: Some(severity),
                    code: Some(NumberOrString::String(f.rule_id.clone())),
                    code_description: None,
                    source: Some("sicario".to_string()),
                    message,
                    related_information: None,
                    tags: None,
                    data: Some(data),
                }
            })
            .collect()
    }

    /// Send a `textDocument/publishDiagnostics` notification to the client.
    fn publish_diagnostics(
        &self,
        uri: &Url,
        diagnostics: Vec<Diagnostic>,
        connection: &Connection,
    ) -> Result<()> {
        let params = PublishDiagnosticsParams {
            uri: uri.clone(),
            diagnostics,
            version: None,
        };
        let notif = Notification::new(
            PublishDiagnostics::METHOD.to_string(),
            serde_json::to_value(params)?,
        );
        connection.sender.send(Message::Notification(notif))?;
        Ok(())
    }

    // ── Code actions ──────────────────────────────────────────────────────

    /// Handle `textDocument/codeAction` — provide quick-fix actions for findings.
    fn handle_code_action(&self, params: CodeActionParams) -> CodeActionResponse {
        let uri = &params.text_document.uri;
        let cached = match self.diagnostics_cache.get(uri) {
            Some(d) => d,
            None => return vec![],
        };

        let mut actions: Vec<CodeActionOrCommand> = Vec::new();

        for diag in cached {
            // Only offer actions for diagnostics that overlap the requested range.
            if !ranges_overlap(&diag.range, &params.range) {
                continue;
            }

            let rule_id = diag
                .code
                .as_ref()
                .map(|c| match c {
                    NumberOrString::String(s) => s.clone(),
                    NumberOrString::Number(n) => n.to_string(),
                })
                .unwrap_or_default();

            // Quick-fix: add a suppression comment on the line above.
            let suppress_action = self.make_suppress_action(uri, diag, &rule_id);
            actions.push(CodeActionOrCommand::CodeAction(suppress_action));
        }

        actions
    }

    /// Build a code action that inserts a `// sicario-ignore:<rule-id>` comment
    /// on the line above the diagnostic.
    fn make_suppress_action(
        &self,
        uri: &Url,
        diag: &Diagnostic,
        rule_id: &str,
    ) -> CodeAction {
        let insert_line = diag.range.start.line;
        let comment = format!("// sicario-ignore:{}\n", rule_id);

        let edit = TextEdit {
            range: Range {
                start: Position::new(insert_line, 0),
                end: Position::new(insert_line, 0),
            },
            new_text: comment,
        };

        let mut changes = HashMap::new();
        changes.insert(uri.clone(), vec![edit]);

        CodeAction {
            title: format!("Suppress Sicario finding: {}", rule_id),
            kind: Some(CodeActionKind::QUICKFIX),
            diagnostics: Some(vec![diag.clone()]),
            edit: Some(WorkspaceEdit {
                changes: Some(changes),
                ..Default::default()
            }),
            is_preferred: Some(false),
            ..Default::default()
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

/// Convert an LSP `Url` to a filesystem `PathBuf`.
fn uri_to_path(uri: &Url) -> Option<PathBuf> {
    uri.to_file_path().ok()
}

/// Check whether two LSP ranges overlap.
fn ranges_overlap(a: &Range, b: &Range) -> bool {
    !(a.end.line < b.start.line
        || (a.end.line == b.start.line && a.end.character < b.start.character)
        || b.end.line < a.start.line
        || (b.end.line == a.start.line && b.end.character < a.start.character))
}

/// Discover bundled rule files relative to the executable.
pub fn discover_rule_paths(project_root: &Path) -> Vec<PathBuf> {
    let rules_dir = project_root.join("rules");
    if !rules_dir.is_dir() {
        // Try relative to the binary location.
        if let Ok(exe) = std::env::current_exe() {
            if let Some(exe_dir) = exe.parent() {
                let alt = exe_dir.join("rules");
                if alt.is_dir() {
                    return collect_yaml_files(&alt);
                }
            }
        }
        return vec![];
    }
    collect_yaml_files(&rules_dir)
}

fn collect_yaml_files(dir: &Path) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if p.extension().map(|e| e == "yaml" || e == "yml").unwrap_or(false) {
                paths.push(p);
            }
        }
    }
    paths
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_severity_mapping_critical() {
        let finding = make_test_finding(Severity::Critical);
        let server = make_test_server();
        let diags = server.findings_to_diagnostics(&[finding], Path::new("test.js"));
        assert_eq!(diags[0].severity, Some(DiagnosticSeverity::ERROR));
    }

    #[test]
    fn test_severity_mapping_high() {
        let finding = make_test_finding(Severity::High);
        let server = make_test_server();
        let diags = server.findings_to_diagnostics(&[finding], Path::new("test.js"));
        assert_eq!(diags[0].severity, Some(DiagnosticSeverity::ERROR));
    }

    #[test]
    fn test_severity_mapping_medium() {
        let finding = make_test_finding(Severity::Medium);
        let server = make_test_server();
        let diags = server.findings_to_diagnostics(&[finding], Path::new("test.js"));
        assert_eq!(diags[0].severity, Some(DiagnosticSeverity::WARNING));
    }

    #[test]
    fn test_severity_mapping_low() {
        let finding = make_test_finding(Severity::Low);
        let server = make_test_server();
        let diags = server.findings_to_diagnostics(&[finding], Path::new("test.js"));
        assert_eq!(diags[0].severity, Some(DiagnosticSeverity::INFORMATION));
    }

    #[test]
    fn test_severity_mapping_info() {
        let finding = make_test_finding(Severity::Info);
        let server = make_test_server();
        let diags = server.findings_to_diagnostics(&[finding], Path::new("test.js"));
        assert_eq!(diags[0].severity, Some(DiagnosticSeverity::INFORMATION));
    }

    #[test]
    fn test_diagnostic_contains_rule_id_and_cwe() {
        let mut finding = make_test_finding(Severity::High);
        finding.cwe_id = Some("CWE-89".to_string());
        let server = make_test_server();
        let diags = server.findings_to_diagnostics(&[finding], Path::new("test.js"));
        assert!(diags[0].message.contains("sql-injection"));
        assert!(diags[0].message.contains("CWE-89"));
    }

    #[test]
    fn test_diagnostic_contains_confidence() {
        let mut finding = make_test_finding(Severity::High);
        finding.confidence_score = 0.92;
        let server = make_test_server();
        let diags = server.findings_to_diagnostics(&[finding], Path::new("test.js"));
        assert!(diags[0].message.contains("92% confidence"));
    }

    #[test]
    fn test_diagnostic_data_field() {
        let finding = make_test_finding(Severity::High);
        let server = make_test_server();
        let diags = server.findings_to_diagnostics(&[finding], Path::new("test.js"));
        let data = diags[0].data.as_ref().unwrap();
        assert_eq!(data["ruleId"], "sql-injection");
    }

    #[test]
    fn test_diagnostic_source_is_sicario() {
        let finding = make_test_finding(Severity::Medium);
        let server = make_test_server();
        let diags = server.findings_to_diagnostics(&[finding], Path::new("test.js"));
        assert_eq!(diags[0].source, Some("sicario".to_string()));
    }

    #[test]
    fn test_ranges_overlap_same() {
        let r = Range {
            start: Position::new(5, 0),
            end: Position::new(5, 10),
        };
        assert!(ranges_overlap(&r, &r));
    }

    #[test]
    fn test_ranges_no_overlap() {
        let a = Range {
            start: Position::new(1, 0),
            end: Position::new(1, 5),
        };
        let b = Range {
            start: Position::new(3, 0),
            end: Position::new(3, 5),
        };
        assert!(!ranges_overlap(&a, &b));
    }

    #[test]
    fn test_suppress_action_inserts_comment() {
        let server = make_test_server();
        let uri = Url::parse("file:///test.js").unwrap();
        let diag = Diagnostic {
            range: Range {
                start: Position::new(10, 0),
                end: Position::new(10, 20),
            },
            severity: Some(DiagnosticSeverity::ERROR),
            code: Some(NumberOrString::String("sql-injection".into())),
            source: Some("sicario".into()),
            message: "sql-injection: SQL Injection".into(),
            ..Default::default()
        };
        let action = server.make_suppress_action(&uri, &diag, "sql-injection");
        assert_eq!(action.title, "Suppress Sicario finding: sql-injection");
        assert!(action.kind == Some(CodeActionKind::QUICKFIX));
        let edit = action.edit.unwrap();
        let changes = edit.changes.unwrap();
        let edits = changes.get(&uri).unwrap();
        assert_eq!(edits[0].new_text, "// sicario-ignore:sql-injection\n");
        assert_eq!(edits[0].range.start.line, 10);
    }

    #[test]
    fn test_line_conversion_1indexed_to_0indexed() {
        let mut finding = make_test_finding(Severity::High);
        finding.line = 10;
        finding.column = 5;
        let server = make_test_server();
        let diags = server.findings_to_diagnostics(&[finding], Path::new("test.js"));
        // LSP uses 0-indexed, findings use 1-indexed.
        assert_eq!(diags[0].range.start.line, 9);
        assert_eq!(diags[0].range.start.character, 4);
    }

    #[test]
    fn test_empty_findings_produce_empty_diagnostics() {
        let server = make_test_server();
        let diags = server.findings_to_diagnostics(&[], Path::new("test.js"));
        assert!(diags.is_empty());
    }

    // ── Test helpers ──────────────────────────────────────────────────────

    fn make_test_server() -> SicarioLspServer {
        SicarioLspServer::new(PathBuf::from("."), vec![])
    }

    fn make_test_finding(severity: Severity) -> Finding {
        Finding {
            id: uuid::Uuid::new_v4(),
            rule_id: "sql-injection".to_string(),
            rule_name: "SQL Injection".to_string(),
            file_path: PathBuf::from("test.js"),
            line: 10,
            column: 5,
            end_line: None,
            end_column: None,
            snippet: "db.query(input)".to_string(),
            severity,
            confidence_score: 0.85,
            reachable: false,
            cloud_exposed: None,
            cwe_id: None,
            owasp_category: None,
            fingerprint: "abc123".to_string(),
            dataflow_trace: None,
            suppressed: false,
            suppression_rule: None,
            suggested_suppression: false,
        }
    }
}

#![allow(dead_code)]
#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(unused_doc_comments)]
#![allow(unused_mut)]

mod auth;
mod cloud;
mod engine;
mod mcp;
mod onboarding;
mod parser;
mod remediation;
mod reporting;
mod scanner;
mod tui;

// New modules added by CLI overhaul
mod baseline;
mod benchmark;
mod cache;
mod cli;
mod confidence;
mod diff;
mod hook;
mod key_manager;
mod lsp;
mod output;
mod publish;
mod rule_harness;
mod suppression_learner;
mod verification;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;

use cli::exit_code::ExitCode;
use cli::{Command, CompletionsArgs, SicarioCli};

fn main() {
    // Silence tracing noise — only show warnings+
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::WARN)
        .init();

    let cli = SicarioCli::parse();

    let result = run(cli);

    match result {
        Ok(code) => std::process::exit(code as i32),
        Err(e) => {
            eprintln!("sicario: {e}");
            std::process::exit(ExitCode::InternalError as i32);
        }
    }
}

fn run(cli: SicarioCli) -> Result<ExitCode> {
    match cli.command {
        None => {
            // Default: launch TUI for backward compatibility
            let scan_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            run_interactive_tui(scan_dir)?;
            Ok(ExitCode::Clean)
        }
        Some(cmd) => dispatch(cmd),
    }
}

fn dispatch(cmd: Command) -> Result<ExitCode> {
    match cmd {
        Command::Scan(args) => cmd_scan(*args),
        Command::Init => {
            eprintln!("sicario init: not yet implemented");
            Ok(ExitCode::Clean)
        }
        Command::Report(args) => {
            cmd_report_handler(&args.dir, args.output.as_deref())?;
            Ok(ExitCode::Clean)
        }
        Command::Fix(_args) => {
            eprintln!("sicario fix: not yet implemented");
            Ok(ExitCode::Clean)
        }
        Command::Baseline(_args) => {
            eprintln!("sicario baseline: not yet implemented");
            Ok(ExitCode::Clean)
        }
        Command::Config(_args) => {
            eprintln!("sicario config: not yet implemented");
            Ok(ExitCode::Clean)
        }
        Command::Suppressions(args) => cmd_suppressions(args),
        Command::Completions(args) => {
            cmd_completions(args);
            Ok(ExitCode::Clean)
        }
        Command::Login => cmd_cloud_login(),
        Command::Logout => cmd_cloud_logout(),
        Command::Publish => cmd_cloud_publish(),
        Command::Whoami => cmd_cloud_whoami(),
        Command::Tui(args) => {
            let scan_dir = PathBuf::from(&args.dir);
            run_interactive_tui(scan_dir)?;
            Ok(ExitCode::Clean)
        }
        Command::Hook(args) => cmd_hook(args),
        Command::Lsp(_args) => {
            let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
            let rule_paths = crate::lsp::discover_rule_paths(&project_root);
            let server = crate::lsp::SicarioLspServer::new(project_root, rule_paths);
            server.run()?;
            Ok(ExitCode::Clean)
        }
        Command::Benchmark(args) => cmd_benchmark(args),
        Command::Rules(args) => cmd_rules(args),
        Command::Cache(_args) => {
            eprintln!("sicario cache: not yet implemented");
            Ok(ExitCode::Clean)
        }
    }
}

// ─── Scan command ─────────────────────────────────────────────────────────────

fn cmd_scan(args: cli::scan::ScanArgs) -> Result<ExitCode> {
    use cli::exit_code::FindingSummary;
    use cli::scan::OutputFormat;
    use engine::sast_engine::SastEngine;
    use engine::vulnerability::Severity;
    use output::branded::{print_scan_summary, ScanSummary};
    use output::formatter::{render_finding_text, render_findings_table, FormatterConfig};
    use output::sarif::emit_sarif;

    let scan_start = std::time::Instant::now();
    let dir = PathBuf::from(&args.dir);

    let formatter_config = FormatterConfig::from_flags(
        args.no_color,
        args.force_color,
        args.max_lines_per_finding,
        args.max_chars_per_line,
    );

    let explicit: Vec<PathBuf> = args.rules.iter().map(PathBuf::from).collect();
    let rule_files = if explicit.is_empty() {
        discover_bundled_rules()
    } else {
        explicit
    };

    let mut eng = SastEngine::new(&dir)?;
    let mut rules_loaded = 0usize;
    for f in &rule_files {
        if let Err(e) = eng.load_rules(f) {
            eprintln!("warning: could not load {:?}: {e}", f);
        } else {
            rules_loaded += 1;
        }
    }

    let vulns = eng.scan_directory(&dir)?;
    let scan_duration = scan_start.elapsed();

    // Emit primary output in the requested format
    let mut stdout = std::io::stdout();
    match args.format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&vulns)?);
        }
        OutputFormat::Text => {
            if args.quiet {
                // Quiet mode: just the summary line
            } else {
                render_findings_table(&vulns, &formatter_config, &mut stdout)?;
            }
            let summary = ScanSummary::from_vulns(&vulns, scan_duration, 0, rules_loaded);
            print_scan_summary(
                &summary,
                formatter_config.unicode_enabled,
                formatter_config.color_enabled,
                &mut stdout,
            )?;
        }
        OutputFormat::Sarif => {
            let tool_version = env!("CARGO_PKG_VERSION");
            let sarif_doc = emit_sarif(&vulns, tool_version);
            println!("{}", serde_json::to_string_pretty(&sarif_doc)?);
        }
    }

    // Write simultaneous multi-format output to files
    if let Some(ref json_path) = args.json_output {
        let json_str = serde_json::to_string_pretty(&vulns)?;
        std::fs::write(json_path, json_str)?;
        if !args.quiet {
            eprintln!("JSON output written to {json_path}");
        }
    }

    if let Some(ref sarif_path) = args.sarif_output {
        let tool_version = env!("CARGO_PKG_VERSION");
        let sarif_doc = emit_sarif(&vulns, tool_version);
        let sarif_str = serde_json::to_string_pretty(&sarif_doc)?;
        std::fs::write(sarif_path, sarif_str)?;
        if !args.quiet {
            eprintln!("SARIF output written to {sarif_path}");
        }
    }

    if let Some(ref text_path) = args.text_output {
        let mut buf = Vec::new();
        for v in &vulns {
            render_finding_text(v, &formatter_config, &mut buf)?;
        }
        let summary = ScanSummary::from_vulns(&vulns, scan_duration, 0, rules_loaded);
        print_scan_summary(
            &summary, false, // no unicode in file output
            false, // no color in file output
            &mut buf,
        )?;
        std::fs::write(text_path, buf)?;
        if !args.quiet {
            eprintln!("Text output written to {text_path}");
        }
    }

    // Auto-publish to Sicario Cloud if --publish flag is set
    if args.publish {
        publish_scan_results(&vulns, scan_duration, rules_loaded);
    }

    // Compute exit code
    let severity_threshold: Severity = args.severity_threshold.into();
    let summaries: Vec<FindingSummary> = vulns
        .iter()
        .map(|v| FindingSummary {
            severity: v.severity,
            confidence_score: 1.0, // confidence scoring not yet wired
            suppressed: false,     // suppression not yet wired
        })
        .collect();

    Ok(ExitCode::from_findings(
        &summaries,
        severity_threshold,
        args.confidence_threshold,
    ))
}

/// Helper: publish scan results to Sicario Cloud (best-effort, never fails the scan).
fn publish_scan_results(
    vulns: &[engine::vulnerability::Vulnerability],
    scan_duration: std::time::Duration,
    rules_loaded: usize,
) {
    use publish::{collect_git_metadata, resolve_cloud_url, PublishClient, ScanMetadata, ScanReport};

    // Check for cloud auth token — silently skip if not authenticated
    let client_id = std::env::var("SICARIO_CLOUD_CLIENT_ID")
        .unwrap_or_else(|_| "sicario-cli".to_string());
    let auth_url = std::env::var("SICARIO_CLOUD_AUTH_URL")
        .unwrap_or_else(|_| "https://auth.sicario.dev".to_string());

    let auth_module = match auth::auth_module::AuthModule::new(client_id, auth_url) {
        Ok(m) => m,
        Err(_) => {
            eprintln!("warning: --publish skipped (could not initialize auth module)");
            return;
        }
    };

    let token = match auth_module.get_cloud_token() {
        Ok(t) => t,
        Err(_) => {
            eprintln!("warning: --publish skipped (not logged in). Run `sicario login` first.");
            return;
        }
    };

    let (repository, branch, commit_sha) = collect_git_metadata();

    let findings: Vec<engine::vulnerability::Finding> = vulns
        .iter()
        .map(|v| engine::vulnerability::Finding::from_vulnerability(v, &v.rule_id))
        .collect();

    let metadata = ScanMetadata {
        repository,
        branch,
        commit_sha,
        timestamp: chrono::Utc::now(),
        duration_ms: scan_duration.as_millis() as u64,
        rules_loaded,
        files_scanned: 0,
        language_breakdown: std::collections::HashMap::new(),
        tags: Vec::new(),
    };

    let report = ScanReport { findings, metadata };
    let cloud_url = resolve_cloud_url();

    let client = match PublishClient::new(cloud_url, token) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("warning: --publish skipped ({e})");
            return;
        }
    };

    match client.publish(&report) {
        Ok(resp) => {
            eprintln!("Scan published to Sicario Cloud (scan ID: {}).", resp.scan_id);
            if let Some(url) = resp.dashboard_url {
                eprintln!("  Dashboard: {url}");
            }
        }
        Err(e) => {
            eprintln!("warning: --publish failed: {e}");
        }
    }
}

// ─── Suppressions command ──────────────────────────────────────────────────────

fn cmd_suppressions(args: cli::suppressions::SuppressionsCommand) -> Result<ExitCode> {
    use cli::suppressions::SuppressionsAction;
    use suppression_learner::SuppressionLearner;

    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));

    match args.action {
        SuppressionsAction::List => {
            let learner = SuppressionLearner::load(&project_root)?;
            let patterns = learner.list();
            if patterns.is_empty() {
                println!("No learned suppression patterns.");
            } else {
                println!(
                    "{:<30} {:<8} {}",
                    "Rule ID", "Count", "Example Snippet"
                );
                println!("{}", "-".repeat(70));
                for p in patterns {
                    let snippet_preview: String =
                        p.example_snippet.chars().take(40).collect();
                    println!("{:<30} {:<8} {}", p.rule_id, p.match_count, snippet_preview);
                }
            }
        }
        SuppressionsAction::Reset => {
            let mut learner = SuppressionLearner::load(&project_root)?;
            learner.reset();
            learner.save()?;
            println!("All learned suppression patterns have been cleared.");
        }
    }

    Ok(ExitCode::Clean)
}

// ─── Shell completions ────────────────────────────────────────────────────────

fn cmd_completions(args: CompletionsArgs) {
    use clap::CommandFactory;
    use clap_complete::generate;

    let mut cmd = SicarioCli::command();
    generate(args.shell, &mut cmd, "sicario", &mut std::io::stdout());
}

// ─── Hook command ─────────────────────────────────────────────────────────────

fn cmd_hook(args: cli::hook::HookCommand) -> Result<ExitCode> {
    use cli::hook::HookAction;
    use hook::manager::{HookManagement, HookManager};

    let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mgr = HookManager::new(&cwd)?;

    match args.action {
        HookAction::Install => {
            mgr.install()?;
            eprintln!("sicario: pre-commit hook installed");
        }
        HookAction::Uninstall => {
            mgr.uninstall()?;
            eprintln!("sicario: pre-commit hook uninstalled");
        }
        HookAction::Status => {
            let st = mgr.status()?;
            if st.installed {
                eprintln!("sicario: pre-commit hook is installed");
                if let Some(cmd) = &st.command {
                    eprintln!("  command: {cmd}");
                }
            } else {
                eprintln!("sicario: pre-commit hook is not installed");
            }
        }
    }

    Ok(ExitCode::Clean)
}

// ─── Cloud auth commands ──────────────────────────────────────────────────────

fn cmd_cloud_login() -> Result<ExitCode> {
    let client_id = std::env::var("SICARIO_CLOUD_CLIENT_ID")
        .unwrap_or_else(|_| "sicario-cli".to_string());
    let auth_url = std::env::var("SICARIO_CLOUD_AUTH_URL")
        .unwrap_or_else(|_| "https://auth.sicario.dev".to_string());

    let auth_module = auth::auth_module::AuthModule::new(client_id, auth_url)?;
    auth_module.cloud_login()?;
    Ok(ExitCode::Clean)
}

fn cmd_cloud_logout() -> Result<ExitCode> {
    let client_id = std::env::var("SICARIO_CLOUD_CLIENT_ID")
        .unwrap_or_else(|_| "sicario-cli".to_string());
    let auth_url = std::env::var("SICARIO_CLOUD_AUTH_URL")
        .unwrap_or_else(|_| "https://auth.sicario.dev".to_string());

    let auth_module = auth::auth_module::AuthModule::new(client_id, auth_url)?;
    auth_module.cloud_logout()?;
    eprintln!("Logged out of Sicario Cloud.");
    Ok(ExitCode::Clean)
}

fn cmd_cloud_whoami() -> Result<ExitCode> {
    let client_id = std::env::var("SICARIO_CLOUD_CLIENT_ID")
        .unwrap_or_else(|_| "sicario-cli".to_string());
    let auth_url = std::env::var("SICARIO_CLOUD_AUTH_URL")
        .unwrap_or_else(|_| "https://auth.sicario.dev".to_string());

    let auth_module = auth::auth_module::AuthModule::new(client_id, auth_url)?;
    match auth_module.cloud_whoami() {
        Ok(info) => {
            println!("User:         {}", info.username);
            println!("Email:        {}", info.email);
            println!("Organization: {}", info.organization);
            println!("Plan:         {}", info.plan_tier);
            Ok(ExitCode::Clean)
        }
        Err(e) => {
            eprintln!("sicario whoami: {e}");
            Ok(ExitCode::Clean)
        }
    }
}

fn cmd_cloud_publish() -> Result<ExitCode> {
    use publish::{collect_git_metadata, resolve_cloud_url, PublishClient, ScanMetadata, ScanReport};

    // Check authentication
    let client_id = std::env::var("SICARIO_CLOUD_CLIENT_ID")
        .unwrap_or_else(|_| "sicario-cli".to_string());
    let auth_url = std::env::var("SICARIO_CLOUD_AUTH_URL")
        .unwrap_or_else(|_| "https://auth.sicario.dev".to_string());

    let auth_module = auth::auth_module::AuthModule::new(client_id, auth_url)?;
    let token = match auth_module.get_cloud_token() {
        Ok(t) => t,
        Err(_) => {
            eprintln!("Not logged in to Sicario Cloud. Run `sicario login` first.");
            return Ok(ExitCode::Clean);
        }
    };

    // Run a scan to get findings
    let scan_start = std::time::Instant::now();
    let dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let rule_files = discover_bundled_rules();

    let mut eng = engine::sast_engine::SastEngine::new(&dir)?;
    let mut rules_loaded = 0usize;
    for f in &rule_files {
        if eng.load_rules(f).is_ok() {
            rules_loaded += 1;
        }
    }

    let vulns = eng.scan_directory(&dir)?;
    let scan_duration = scan_start.elapsed();

    let (repository, branch, commit_sha) = collect_git_metadata();

    let findings: Vec<engine::vulnerability::Finding> = vulns
        .iter()
        .map(|v| engine::vulnerability::Finding::from_vulnerability(v, &v.rule_id))
        .collect();

    let metadata = ScanMetadata {
        repository,
        branch,
        commit_sha,
        timestamp: chrono::Utc::now(),
        duration_ms: scan_duration.as_millis() as u64,
        rules_loaded,
        files_scanned: 0,
        language_breakdown: std::collections::HashMap::new(),
        tags: Vec::new(),
    };

    let report = ScanReport { findings, metadata };
    let cloud_url = resolve_cloud_url();
    let client = PublishClient::new(cloud_url, token)?;

    match client.publish(&report) {
        Ok(resp) => {
            eprintln!("Scan published to Sicario Cloud (scan ID: {}).", resp.scan_id);
            if let Some(url) = resp.dashboard_url {
                eprintln!("  Dashboard: {url}");
            }
        }
        Err(e) => {
            eprintln!("sicario publish: {e}");
        }
    }

    Ok(ExitCode::Clean)
}

// ─── Interactive TUI ──────────────────────────────────────────────────────────

fn run_interactive_tui(scan_dir: PathBuf) -> Result<()> {
    use tui::app::{create_tui_channel, SicarioTui};
    use tui::worker::{spawn_scan_worker, ScanJob};

    let (tx, rx) = create_tui_channel();
    let mut app = SicarioTui::new(rx)?;

    // Wire the patch sender so the TUI can apply patches from worker threads
    app.patch_tx = Some(tx.clone());

    // Kick off a background scan immediately so the user sees results fast
    let rule_files = discover_bundled_rules();
    let job = ScanJob {
        directory: scan_dir.clone(),
        rule_files,
    };
    spawn_scan_worker(job, tx.clone());

    // Transition straight to Scanning state — skip the static Welcome screen
    app.state = tui::app::AppState::Scanning {
        progress: 0.0,
        files_scanned: 0,
        total_files: 0,
    };

    // Run the blocking TUI event loop
    let result = app.run();

    // Always restore the terminal even on error
    if let Err(ref e) = result {
        eprintln!("sicario: {e}");
    }

    result
}

// ─── Bundled rule discovery ───────────────────────────────────────────────────

/// Find YAML rule files shipped alongside the binary.
///
/// Search order:
///   1. `<binary_dir>/rules/`
///   2. `<cwd>/sicario-cli/rules/`   (source-tree / dev mode)
///   3. `<cwd>/rules/`
fn discover_bundled_rules() -> Vec<PathBuf> {
    let mut candidates: Vec<PathBuf> = Vec::new();

    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            candidates.push(parent.join("rules"));
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        candidates.push(cwd.join("sicario-cli").join("rules"));
        candidates.push(cwd.join("rules"));
    }

    for dir in candidates {
        if dir.is_dir() {
            let files: Vec<PathBuf> = std::fs::read_dir(&dir)
                .into_iter()
                .flatten()
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| {
                    p.extension()
                        .and_then(|e| e.to_str())
                        .map(|e| e == "yaml" || e == "yml")
                        .unwrap_or(false)
                })
                .collect();
            if !files.is_empty() {
                return files;
            }
        }
    }
    Vec::new()
}

// ─── Benchmark command ─────────────────────────────────────────────────────────

fn cmd_benchmark(args: cli::benchmark::BenchmarkArgs) -> Result<ExitCode> {
    use benchmark::BenchmarkRunner;

    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let rule_files = discover_bundled_rules();
    let runner = BenchmarkRunner::new(&project_root, rule_files);

    let result = runner.run(&project_root)?;

    // Compare against baseline if requested
    if let Some(ref baseline_name) = args.compare_baseline {
        let baseline = if baseline_name == "latest" {
            runner.load_latest_baseline()?
        } else {
            runner.load_baseline(baseline_name)?
        };

        if let Some(baseline) = baseline {
            let comparison = BenchmarkRunner::compare(&baseline, &result);
            if args.format == "json" {
                println!("{}", serde_json::to_string_pretty(&comparison)?);
            } else {
                print!("{}", comparison.display_text());
            }
            return Ok(ExitCode::Clean);
        } else {
            eprintln!("warning: no baseline found for comparison");
        }
    }

    // Output result
    if args.format == "json" {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        print!("{}", result.display_text());
    }

    Ok(ExitCode::Clean)
}

// ─── Rules command ────────────────────────────────────────────────────────────

fn cmd_rules(args: cli::rules::RulesCommand) -> Result<ExitCode> {
    use cli::rules::RulesAction;
    use engine::sast_engine::SastEngine;
    use rule_harness::{RuleQualityValidation, RuleTestHarness};

    let project_root = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let rule_files = discover_bundled_rules();

    // Load all rules
    let mut engine = SastEngine::new(&project_root)?;
    for f in &rule_files {
        if let Err(e) = engine.load_rules(f) {
            eprintln!("warning: could not load {:?}: {e}", f);
        }
    }
    let rules = engine.get_rules().to_vec();
    let harness = RuleTestHarness::new(&project_root);

    match args.action {
        RulesAction::Test(test_args) => {
            eprintln!("Running rule test cases for {} rules...", rules.len());
            let report = harness.validate_all(&rules)?;

            if test_args.report {
                if report.aggregate_fp_rate >= 0.15 {
                    eprintln!(
                        "⚠ Aggregate FP rate {:.1}% exceeds 15% threshold",
                        report.aggregate_fp_rate * 100.0
                    );
                }
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", report.display_text());
            }

            if report.invalid_rules > 0 {
                return Ok(ExitCode::FindingsDetected);
            }
        }
        RulesAction::Validate(validate_args) => {
            eprintln!("Validating {} rules...", rules.len());
            let report = harness.validate_all_syntax(&rules);

            if validate_args.report {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                print!("{}", report.display_text());
            }

            if report.invalid_rules > 0 {
                return Ok(ExitCode::FindingsDetected);
            }
        }
    }

    Ok(ExitCode::Clean)
}

// ─── Report handler (preserved from original) ────────────────────────────────

fn cmd_report_handler(dir_str: &str, output: Option<&str>) -> Result<()> {
    use engine::sast_engine::SastEngine;
    use reporting::{generate_compliance_report, write_compliance_reports};

    let dir = PathBuf::from(dir_str);
    let output_dir = output
        .map(PathBuf::from)
        .unwrap_or_else(|| dir.join(".sicario").join("reports"));

    let mut eng = SastEngine::new(&dir)?;
    for f in discover_bundled_rules() {
        if let Err(e) = eng.load_rules(&f) {
            eprintln!("warning: could not load {:?}: {e}", f);
        }
    }

    let vulns = eng.scan_directory(&dir)?;
    let report = generate_compliance_report(&vulns);
    let (json_path, md_path) = write_compliance_reports(&report, &output_dir)?;

    println!("OWASP report: {}", json_path.display());
    println!("Markdown:     {}", md_path.display());
    println!(
        "Total: {}  |  Categories affected: {}/10",
        report.total_vulnerabilities, report.categories_affected
    );
    Ok(())
}

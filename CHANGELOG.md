# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Multi-language SAST engine with tree-sitter parsing (Go, Java, JavaScript/TypeScript, Python, Rust)
- YAML-based security rule system with 500+ built-in rules (100+ per language)
- Secret scanning with regex, entropy detection, and provider-specific verifiers
- SCA module with OSV and GHSA advisory database integration
- Data-flow reachability analysis to reduce false positives
- Multi-provider AI remediation engine (any OpenAI-compatible LLM endpoint)
- Template-based fallback fixes for SQL injection, XSS, and command injection
- Post-fix verification scanning to confirm vulnerability resolution
- Safe backup/rollback system for automated code fixes
- Interactive TUI dashboard built with Ratatui
- Professional CLI with Clap (scan, fix, report, baseline, rules, config, hook, lsp, benchmark, cache, suppressions, completions, login/logout/whoami, publish)
- SARIF v2.1.0 output for GitHub Code Scanning integration
- OWASP Top 10 compliance report generation (JSON + Markdown)
- Per-finding confidence scoring (reachability + pattern specificity + context)
- Baseline management with delta comparison (new/resolved/unchanged)
- Git-aware diff scanning for PR workflows (`--diff`, `--staged`)
- Inline suppression comments (`sicario-ignore`, `sicario-ignore:<rule-id>`)
- Learning suppressions with auto-suggest for recurring false positives
- Incremental scan caching (content-addressable, SHA-256)
- Language Server Protocol server for IDE integration
- VS Code extension scaffolding
- Git pre-commit hook management (install/uninstall/status)
- Performance benchmarking suite with per-language breakdown
- Rule quality test harness with TP/TN validation
- BYOK key management via OS keyring with precedence resolution
- OAuth 2.0 device flow authentication with PKCE
- MCP (Model Context Protocol) server for AI assistant integration
- Cloud priority scoring with internet exposure analysis
- Sicario Cloud platform: Convex backend, Axum REST API, Next.js dashboard
- Cloud publish command for uploading scan results
- GitHub Action for CI integration (`action.yml`)
- `.sicarioignore` file support (`.gitignore` syntax)
- Shell completions (bash, zsh, fish, PowerShell)
- Cross-platform builds: Linux (musl static), macOS (Intel + Apple Silicon), Windows (MSVC)
- Homebrew formula for macOS/Linux installation
- Curl-based installer script
- GitHub Actions CI/CD pipeline with cross-compilation and automated releases

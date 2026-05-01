//! Trait-based template registry for deterministic vulnerability remediation.
//!
//! The `TemplateRegistry` maps Rule IDs and CWE numbers to `PatchTemplate`
//! implementations. When a vulnerability is found, the engine queries the
//! registry first. If a static template exists it applies it directly —
//! bypassing the LLM entirely to prevent semantic drift and eliminate latency.
//! Only unmatched vulnerabilities fall through to the LLM verification loop.
//!
//! # Adding a new template
//!
//! 1. Define a unit struct (e.g. `pub struct MyTemplate;`).
//! 2. Implement `PatchTemplate` for it.
//! 3. Register it in `TemplateRegistry::default()` via
//!    `registry.register_rule(...)` or `registry.register_cwe(...)`.
//!
//! Requirements: 3.1–3.7, 13.5

use std::collections::HashMap;

pub mod auth;
pub mod crypto;
pub mod helpers;
pub mod iac_cloud;
pub mod injection;
pub mod input_file;
pub mod sql;
pub mod web_frameworks;
pub mod web_headers;

// Re-export all templates for convenience
pub use auth::*;
pub use crypto::*;
pub use iac_cloud::*;
pub use injection::*;
pub use input_file::*;
pub use sql::*;
pub use web_frameworks::*;
pub use web_headers::*;

use crate::parser::Language;

// ── Core trait ────────────────────────────────────────────────────────────────

/// A deterministic, LLM-free patch generator for a specific vulnerability class.
///
/// `generate_patch` receives the **single vulnerable line** (already extracted
/// by the engine) and the detected language. It returns `Some(replacement)`
/// when it can handle the case, or `None` to signal that the LLM loop should
/// be used instead.
///
/// The returned string is the replacement for the vulnerable line only — it
/// must NOT include surrounding context. Indentation is re-applied by
/// `splice_patch` in the engine.
pub trait PatchTemplate: Send + Sync {
    /// Attempt to generate a replacement for `vulnerable_line`.
    ///
    /// Returns `Some(fixed_line)` on success, `None` if this template cannot
    /// handle the given input (e.g. wrong language or unrecognised pattern).
    fn generate_patch(&self, vulnerable_line: &str, lang: Language) -> Option<String>;

    /// Human-readable name for diagnostics and logging.
    fn name(&self) -> &'static str;
}

// ── Registry ──────────────────────────────────────────────────────────────────

/// Maps Rule IDs and CWE numbers to their `PatchTemplate` implementations.
///
/// Lookup order:
/// 1. Exact Rule ID match (highest priority — most specific)
/// 2. CWE number match (e.g. "338" for CWE-338)
pub struct TemplateRegistry {
    /// rule_id → template
    by_rule: HashMap<String, Box<dyn PatchTemplate>>,
    /// CWE number string (e.g. "338") → template
    by_cwe: HashMap<String, Box<dyn PatchTemplate>>,
}

impl TemplateRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self {
            by_rule: HashMap::new(),
            by_cwe: HashMap::new(),
        }
    }

    /// Register a template for an exact Rule ID.
    pub fn register_rule(&mut self, rule_id: &str, template: Box<dyn PatchTemplate>) {
        self.by_rule.insert(rule_id.to_string(), template);
    }

    /// Register a template for a CWE number (just the digits, e.g. `"338"`).
    pub fn register_cwe(&mut self, cwe_num: &str, template: Box<dyn PatchTemplate>) {
        self.by_cwe.insert(cwe_num.to_string(), template);
    }

    /// Look up a template for the given rule_id and optional CWE string.
    ///
    /// Returns a reference to the best matching template, or `None` if no
    /// static template is registered for this vulnerability.
    pub fn lookup(&self, rule_id: &str, cwe_id: Option<&str>) -> Option<&dyn PatchTemplate> {
        // 1. Exact rule ID match
        if let Some(t) = self.by_rule.get(rule_id) {
            return Some(t.as_ref());
        }

        // 2. CWE match — extract numeric part from "CWE-338" → "338"
        if let Some(cwe) = cwe_id {
            let cwe_num = cwe
                .to_lowercase()
                .trim_start_matches("cwe-")
                .trim()
                .to_string();
            if let Some(t) = self.by_cwe.get(&cwe_num) {
                return Some(t.as_ref());
            }
        }

        None
    }

    /// Apply the best matching template for a vulnerability, if one exists.
    ///
    /// `vulnerable_line` is the single source line that triggered the finding.
    /// `lang` is the detected language of the file.
    ///
    /// Returns `Some(fixed_line)` when a template matched and produced output,
    /// `None` when no template is registered or the template declined.
    pub fn apply(
        &self,
        rule_id: &str,
        cwe_id: Option<&str>,
        vulnerable_line: &str,
        lang: Language,
    ) -> Option<String> {
        self.lookup(rule_id, cwe_id)?
            .generate_patch(vulnerable_line, lang)
    }
}

impl Default for TemplateRegistry {
    /// Build the default registry with all "Sicario 100" templates registered.
    fn default() -> Self {
        let mut r = Self::new();

        // ── Crypto ────────────────────────────────────────────────────────────
        r.register_cwe("328", Box::new(CryptoWeakHashTemplate)); // Weak hash (MD5/SHA1)
        r.register_cwe("338", Box::new(CryptoMathRandomTemplate)); // Insecure PRNG
        r.register_cwe("327", Box::new(CryptoEcbModeTemplate)); // Weak cipher mode (ECB)
        r.register_cwe("759", Box::new(AuthMissingSaltTemplate)); // Missing salt

        // Rule-ID aliases for the PRNG template (our own rules use these IDs)
        r.register_rule("js-crypto-math-random", Box::new(CryptoMathRandomTemplate));
        r.register_rule("js-math-random-crypto", Box::new(CryptoMathRandomTemplate));

        // Rule-ID aliases for ECB mode
        r.register_rule("crypto-ecb-mode", Box::new(CryptoEcbModeTemplate));
        r.register_rule("js-crypto-ecb", Box::new(CryptoEcbModeTemplate));
        r.register_rule("py-crypto-ecb", Box::new(CryptoEcbModeTemplate));

        // Rule-ID aliases for hardcoded JWT secret (CWE-798 is also used by
        // hardcoded-creds, so we register by rule ID to avoid collision)
        r.register_rule(
            "js-jwt-hardcoded-secret",
            Box::new(CryptoHardcodedJwtTemplate),
        );
        r.register_rule(
            "py-jwt-hardcoded-secret",
            Box::new(CryptoHardcodedJwtTemplate),
        );
        r.register_rule("jwt-hardcoded-secret", Box::new(CryptoHardcodedJwtTemplate));

        // Rule-ID aliases for missing bcrypt salt
        r.register_rule("js-bcrypt-missing-salt", Box::new(AuthMissingSaltTemplate));
        r.register_rule("bcrypt-missing-rounds", Box::new(AuthMissingSaltTemplate));

        // ── DOM / XSS ─────────────────────────────────────────────────────────
        r.register_rule("js-innerhtml", Box::new(DomInnerHtmlTemplate));
        r.register_rule(
            "js-xss-innerhtml-assignment",
            Box::new(DomInnerHtmlTemplate),
        );
        r.register_rule("js-document-write", Box::new(DomDocumentWriteTemplate));
        r.register_rule("js-xss-document-write", Box::new(DomDocumentWriteTemplate));

        // postMessage wildcard origin
        r.register_cwe("345", Box::new(DomPostMessageWildcardTemplate));
        r.register_rule(
            "js-postmessage-wildcard",
            Box::new(DomPostMessageWildcardTemplate),
        );
        r.register_rule(
            "dom-postmessage-wildcard",
            Box::new(DomPostMessageWildcardTemplate),
        );

        // ── CORS ──────────────────────────────────────────────────────────────
        r.register_rule("cors-wildcard", Box::new(WebCorsWildcardTemplate));
        r.register_rule("js-cors-wildcard", Box::new(WebCorsWildcardTemplate));

        // ── Cookie security ───────────────────────────────────────────────────
        r.register_cwe("614", Box::new(WebCookieInsecureTemplate)); // Missing Secure flag
        r.register_cwe("1004", Box::new(WebCookieInsecureTemplate)); // Missing HttpOnly flag
        r.register_rule("js-cookie-no-httponly", Box::new(WebCookieInsecureTemplate));
        r.register_rule("js-cookie-no-secure", Box::new(WebCookieInsecureTemplate));
        r.register_rule(
            "express-cookie-insecure",
            Box::new(WebCookieInsecureTemplate),
        );

        // ── Express security headers ──────────────────────────────────────────
        r.register_cwe("200", Box::new(WebExpressXPoweredByTemplate)); // Info exposure
        r.register_rule(
            "express-x-powered-by",
            Box::new(WebExpressXPoweredByTemplate),
        );
        r.register_rule(
            "js-express-xpoweredby",
            Box::new(WebExpressXPoweredByTemplate),
        );

        // ── Python unsafe deserialization ─────────────────────────────────────
        r.register_rule("py-unsafe-yaml", Box::new(PyUnsafeDeserializeTemplate));
        r.register_rule("py-pickle-loads", Box::new(PyUnsafeDeserializeTemplate));
        r.register_rule(
            "python-unsafe-deserialization",
            Box::new(PyUnsafeDeserializeTemplate),
        );

        // ── Python TLS verification disabled ─────────────────────────────────
        r.register_cwe("295", Box::new(PyRequestsVerifyFalseTemplate)); // Improper cert validation
        r.register_rule(
            "py-requests-verify-false",
            Box::new(PyRequestsVerifyFalseTemplate),
        );
        r.register_rule(
            "python-ssl-verify-false",
            Box::new(PyRequestsVerifyFalseTemplate),
        );

        // ── Go resource leak ──────────────────────────────────────────────────
        r.register_rule("go-defer-close", Box::new(GoDeferCloseTemplate));
        r.register_rule("go-missing-defer-close", Box::new(GoDeferCloseTemplate));

        // ── Injection ─────────────────────────────────────────────────────────
        r.register_cwe("94", Box::new(InjectEvalTemplate)); // Code injection via eval
        r.register_rule("js-eval-injection", Box::new(InjectEvalTemplate));
        r.register_rule("py-eval-injection", Box::new(InjectEvalTemplate));

        r.register_rule("js-child-process-exec", Box::new(InjectOsExecTemplate));
        r.register_rule("node-exec-injection", Box::new(InjectOsExecTemplate));

        r.register_cwe("943", Box::new(InjectNoSqlTypeCastTemplate)); // NoSQL injection
        r.register_rule("js-nosql-injection", Box::new(InjectNoSqlTypeCastTemplate));
        r.register_rule(
            "mongoose-nosql-injection",
            Box::new(InjectNoSqlTypeCastTemplate),
        );

        r.register_rule(
            "react-dangerously-set-innerhtml",
            Box::new(ReactDangerouslySetInnerHtmlTemplate),
        );
        r.register_rule(
            "js-react-xss",
            Box::new(ReactDangerouslySetInnerHtmlTemplate),
        );

        // ── IaC / Dockerfile ──────────────────────────────────────────────────
        r.register_cwe("269", Box::new(IacDockerRootUserTemplate)); // Privilege escalation
        r.register_rule("dockerfile-root-user", Box::new(IacDockerRootUserTemplate));
        r.register_rule("iac-docker-root", Box::new(IacDockerRootUserTemplate));

        // ── Sprint 1: Cryptography & Secrets ─────────────────────────────────
        r.register_cwe("916", Box::new(CryptoPbkdf2LowIterationsTemplate)); // Weak KDF iterations
        r.register_rule(
            "js-pbkdf2-low-iterations",
            Box::new(CryptoPbkdf2LowIterationsTemplate),
        );
        r.register_rule(
            "py-pbkdf2-low-iterations",
            Box::new(CryptoPbkdf2LowIterationsTemplate),
        );
        r.register_rule(
            "crypto-pbkdf2-iterations",
            Box::new(CryptoPbkdf2LowIterationsTemplate),
        );

        r.register_cwe("326", Box::new(CryptoRsaKeyTooShortTemplate)); // Inadequate key strength
        r.register_rule(
            "js-rsa-key-too-short",
            Box::new(CryptoRsaKeyTooShortTemplate),
        );
        r.register_rule(
            "py-rsa-key-too-short",
            Box::new(CryptoRsaKeyTooShortTemplate),
        );
        r.register_rule(
            "crypto-rsa-weak-key",
            Box::new(CryptoRsaKeyTooShortTemplate),
        );

        r.register_cwe("321", Box::new(CryptoHardcodedAesKeyTemplate)); // Hardcoded crypto key
        r.register_rule(
            "js-hardcoded-aes-key",
            Box::new(CryptoHardcodedAesKeyTemplate),
        );
        r.register_rule(
            "py-hardcoded-aes-key",
            Box::new(CryptoHardcodedAesKeyTemplate),
        );
        r.register_rule(
            "crypto-hardcoded-key",
            Box::new(CryptoHardcodedAesKeyTemplate),
        );

        r.register_cwe("335", Box::new(CryptoInsecureRandomSeedTemplate)); // Predictable seed
        r.register_rule(
            "py-random-seed-fixed",
            Box::new(CryptoInsecureRandomSeedTemplate),
        );
        r.register_rule(
            "py-insecure-random-seed",
            Box::new(CryptoInsecureRandomSeedTemplate),
        );

        // CWE-916 is shared with PBKDF2; register md5-password by rule ID only
        r.register_rule(
            "js-md5-password-hash",
            Box::new(CryptoMd5PasswordHashTemplate),
        );
        r.register_rule(
            "py-md5-password-hash",
            Box::new(CryptoMd5PasswordHashTemplate),
        );
        r.register_rule(
            "go-md5-password-hash",
            Box::new(CryptoMd5PasswordHashTemplate),
        );
        r.register_rule(
            "crypto-md5-password",
            Box::new(CryptoMd5PasswordHashTemplate),
        );

        r.register_cwe("347", Box::new(CryptoJwtNoneAlgorithmTemplate)); // Missing signature verification
        r.register_rule(
            "js-jwt-none-algorithm",
            Box::new(CryptoJwtNoneAlgorithmTemplate),
        );
        r.register_rule(
            "py-jwt-none-algorithm",
            Box::new(CryptoJwtNoneAlgorithmTemplate),
        );
        r.register_rule(
            "jwt-algorithm-none",
            Box::new(CryptoJwtNoneAlgorithmTemplate),
        );

        // CWE-327 is shared with ECB; register weak-jwt by rule ID only
        r.register_rule(
            "js-jwt-weak-algorithm",
            Box::new(CryptoJwtWeakAlgorithmTemplate),
        );
        r.register_rule(
            "py-jwt-weak-algorithm",
            Box::new(CryptoJwtWeakAlgorithmTemplate),
        );
        r.register_rule(
            "jwt-weak-algorithm",
            Box::new(CryptoJwtWeakAlgorithmTemplate),
        );

        r.register_cwe("760", Box::new(CryptoHardcodedSaltTemplate)); // Hardcoded salt
        r.register_rule(
            "py-bcrypt-hardcoded-salt",
            Box::new(CryptoHardcodedSaltTemplate),
        );
        r.register_rule(
            "crypto-hardcoded-salt",
            Box::new(CryptoHardcodedSaltTemplate),
        );

        // ── Sprint 2: Auth & Session ──────────────────────────────────────────
        r.register_cwe("1004", Box::new(AuthSessionNoHttpOnlyTemplate));
        r.register_rule(
            "express-session-no-httponly",
            Box::new(AuthSessionNoHttpOnlyTemplate),
        );
        r.register_rule(
            "js-session-cookie-httponly",
            Box::new(AuthSessionNoHttpOnlyTemplate),
        );

        r.register_cwe("614", Box::new(AuthSessionNoSecureFlagTemplate));
        r.register_rule(
            "express-session-no-secure",
            Box::new(AuthSessionNoSecureFlagTemplate),
        );
        r.register_rule(
            "js-session-cookie-secure",
            Box::new(AuthSessionNoSecureFlagTemplate),
        );

        r.register_cwe("384", Box::new(AuthSessionFixationTemplate));
        r.register_rule("js-session-fixation", Box::new(AuthSessionFixationTemplate));
        r.register_rule(
            "express-session-fixation",
            Box::new(AuthSessionFixationTemplate),
        );

        r.register_cwe("532", Box::new(AuthPasswordInLogTemplate));
        r.register_rule("js-password-in-log", Box::new(AuthPasswordInLogTemplate));
        r.register_rule("py-password-in-log", Box::new(AuthPasswordInLogTemplate));
        r.register_rule("log-sensitive-data", Box::new(AuthPasswordInLogTemplate));

        r.register_cwe("523", Box::new(AuthBasicAuthOverHttpTemplate));
        r.register_rule(
            "js-basic-auth-over-http",
            Box::new(AuthBasicAuthOverHttpTemplate),
        );

        r.register_cwe("613", Box::new(AuthJwtNoExpiryTemplate));
        r.register_rule("js-jwt-no-expiry", Box::new(AuthJwtNoExpiryTemplate));
        r.register_rule("py-jwt-no-expiry", Box::new(AuthJwtNoExpiryTemplate));
        r.register_rule("jwt-missing-expiry", Box::new(AuthJwtNoExpiryTemplate));

        // ── Sprint 2: Injection (continued) ──────────────────────────────────
        r.register_rule(
            "js-child-process-shell-true",
            Box::new(InjectChildProcessShellTrueTemplate),
        );
        r.register_rule(
            "node-spawn-shell-true",
            Box::new(InjectChildProcessShellTrueTemplate),
        );

        r.register_rule(
            "py-subprocess-shell-true",
            Box::new(InjectPythonSubprocessShellTemplate),
        );
        r.register_rule(
            "python-shell-injection",
            Box::new(InjectPythonSubprocessShellTemplate),
        );

        r.register_rule("py-ssti-render-template", Box::new(InjectSstiTemplate));
        r.register_rule("flask-ssti", Box::new(InjectSstiTemplate));

        r.register_cwe("90", Box::new(InjectLdapTemplate));
        r.register_rule("js-ldap-injection", Box::new(InjectLdapTemplate));
        r.register_rule("py-ldap-injection", Box::new(InjectLdapTemplate));

        r.register_cwe("643", Box::new(InjectXpathTemplate));
        r.register_rule("js-xpath-injection", Box::new(InjectXpathTemplate));
        r.register_rule("py-xpath-injection", Box::new(InjectXpathTemplate));

        // ── Sprint 3: Web Headers ─────────────────────────────────────────────
        r.register_rule("express-helmet-missing", Box::new(WebHelmetMissingTemplate));
        r.register_rule("js-helmet-missing", Box::new(WebHelmetMissingTemplate));

        r.register_rule("express-csp-missing", Box::new(WebCspMissingTemplate));
        r.register_rule("js-csp-missing", Box::new(WebCspMissingTemplate));

        r.register_cwe("319", Box::new(WebHstsDisabledTemplate));
        r.register_rule("express-hsts-disabled", Box::new(WebHstsDisabledTemplate));
        r.register_rule("js-hsts-disabled", Box::new(WebHstsDisabledTemplate));

        r.register_cwe("942", Box::new(WebCorsCredentialsWildcardTemplate));
        r.register_rule(
            "js-cors-credentials-wildcard",
            Box::new(WebCorsCredentialsWildcardTemplate),
        );

        r.register_rule(
            "express-referrer-policy",
            Box::new(WebReferrerPolicyMissingTemplate),
        );
        r.register_rule(
            "js-referrer-policy-missing",
            Box::new(WebReferrerPolicyMissingTemplate),
        );

        r.register_cwe("1021", Box::new(WebClickjackingTemplate));
        r.register_rule(
            "express-frameguard-disabled",
            Box::new(WebClickjackingTemplate),
        );
        r.register_rule("js-clickjacking", Box::new(WebClickjackingTemplate));

        r.register_cwe("525", Box::new(WebCacheControlMissingTemplate));
        r.register_rule(
            "express-no-cache-control",
            Box::new(WebCacheControlMissingTemplate),
        );
        r.register_rule(
            "js-cache-control-missing",
            Box::new(WebCacheControlMissingTemplate),
        );

        // ── Sprint 3: Input Validation ────────────────────────────────────────
        r.register_cwe("1321", Box::new(PrototypePollutionMergeTemplate));
        r.register_rule(
            "js-prototype-pollution-merge",
            Box::new(PrototypePollutionMergeTemplate),
        );

        r.register_rule(
            "js-prototype-pollution-set",
            Box::new(PrototypePollutionSetTemplate),
        );

        r.register_cwe("1333", Box::new(InputRegexDosTemplate));
        r.register_rule("js-redos", Box::new(InputRegexDosTemplate));
        r.register_rule("js-regex-dos", Box::new(InputRegexDosTemplate));

        r.register_cwe("755", Box::new(InputJsonParseNoTryCatchTemplate));
        r.register_rule(
            "js-json-parse-no-try-catch",
            Box::new(InputJsonParseNoTryCatchTemplate),
        );

        r.register_cwe("22", Box::new(InputPathTraversalTemplate));
        r.register_rule("js-path-traversal", Box::new(InputPathTraversalTemplate));
        r.register_rule("node-path-traversal", Box::new(InputPathTraversalTemplate));

        r.register_cwe("20", Box::new(InputReqBodyNoValidationTemplate));
        r.register_rule(
            "js-req-body-no-validation",
            Box::new(InputReqBodyNoValidationTemplate),
        );
        r.register_rule(
            "express-no-input-validation",
            Box::new(InputReqBodyNoValidationTemplate),
        );

        // ── Sprint 3: File & Resource ─────────────────────────────────────────
        r.register_cwe("434", Box::new(FileUploadNoMimeCheckTemplate));
        r.register_rule(
            "js-multer-no-mime-check",
            Box::new(FileUploadNoMimeCheckTemplate),
        );
        r.register_rule(
            "express-file-upload-unsafe",
            Box::new(FileUploadNoMimeCheckTemplate),
        );

        r.register_cwe("377", Box::new(FileTempFileInsecureTemplate));
        r.register_rule("py-tempfile-mktemp", Box::new(FileTempFileInsecureTemplate));

        r.register_cwe("732", Box::new(FilePermissionsWorldWritableTemplate));
        r.register_rule(
            "py-world-writable-file",
            Box::new(FilePermissionsWorldWritableTemplate),
        );
        r.register_rule(
            "py-chmod-world-writable",
            Box::new(FilePermissionsWorldWritableTemplate),
        );

        r.register_cwe("390", Box::new(GoFileCloseErrorIgnoredTemplate));
        r.register_rule(
            "go-close-error-ignored",
            Box::new(GoFileCloseErrorIgnoredTemplate),
        );
        r.register_rule(
            "go-defer-close-unchecked",
            Box::new(GoFileCloseErrorIgnoredTemplate),
        );

        r.register_cwe("400", Box::new(FileReadSyncTemplate));
        r.register_rule("js-readfilesync-user-input", Box::new(FileReadSyncTemplate));
        r.register_rule("node-sync-file-read", Box::new(FileReadSyncTemplate));

        // ── Sprint 4: SQL + TLS/SSRF + Django/Flask + Cloud/IaC + React ──────
        r.register_rule("js-sql-string-concat", Box::new(SqlStringConcatTemplate));
        r.register_rule("py-sql-string-concat", Box::new(SqlStringConcatTemplate));
        r.register_rule("go-sql-string-concat", Box::new(SqlStringConcatTemplate));
        r.register_rule("sql-string-concat", Box::new(SqlStringConcatTemplate));

        r.register_rule(
            "js-sql-template-string",
            Box::new(SqlTemplateStringTemplate),
        );
        r.register_rule(
            "node-sql-template-literal",
            Box::new(SqlTemplateStringTemplate),
        );

        // TLS
        r.register_rule("js-tls-min-version", Box::new(TlsMinVersionTemplate));
        r.register_rule("go-tls-min-version", Box::new(TlsMinVersionTemplate));
        r.register_rule("tls-insecure-version", Box::new(TlsMinVersionTemplate));

        r.register_rule(
            "js-tls-reject-unauthorized",
            Box::new(TlsCertVerifyDisabledNodeTemplate),
        );
        r.register_rule(
            "node-tls-verify-disabled",
            Box::new(TlsCertVerifyDisabledNodeTemplate),
        );

        r.register_rule(
            "go-tls-insecure-skip-verify",
            Box::new(TlsCertVerifyDisabledGoTemplate),
        );
        r.register_rule(
            "go-insecure-skip-verify",
            Box::new(TlsCertVerifyDisabledGoTemplate),
        );

        // SSRF
        r.register_rule("js-ssrf-axios", Box::new(SsrfHttpGetUserInputTemplate));
        r.register_rule("py-ssrf-requests", Box::new(SsrfHttpGetUserInputTemplate));
        r.register_rule("ssrf-http-get", Box::new(SsrfHttpGetUserInputTemplate));

        r.register_rule("js-ssrf-fetch", Box::new(SsrfFetchUserInputTemplate));
        r.register_rule("node-fetch-ssrf", Box::new(SsrfFetchUserInputTemplate));

        // Django
        r.register_rule("django-debug-true", Box::new(DjangoDebugTrueTemplate));
        r.register_rule("py-django-debug", Box::new(DjangoDebugTrueTemplate));

        r.register_rule(
            "django-secret-key-hardcoded",
            Box::new(DjangoSecretKeyHardcodedTemplate),
        );
        r.register_rule(
            "py-django-secret-key",
            Box::new(DjangoSecretKeyHardcodedTemplate),
        );

        r.register_cwe("183", Box::new(DjangoAllowedHostsWildcardTemplate));
        r.register_rule(
            "django-allowed-hosts-wildcard",
            Box::new(DjangoAllowedHostsWildcardTemplate),
        );

        r.register_cwe("352", Box::new(DjangoCsrfExemptTemplate));
        r.register_rule("django-csrf-exempt", Box::new(DjangoCsrfExemptTemplate));
        r.register_rule("py-csrf-exempt", Box::new(DjangoCsrfExemptTemplate));

        r.register_cwe("215", Box::new(FlaskDebugTrueTemplate));
        r.register_rule("flask-debug-true", Box::new(FlaskDebugTrueTemplate));
        r.register_rule("py-flask-debug", Box::new(FlaskDebugTrueTemplate));

        r.register_rule(
            "flask-secret-key-hardcoded",
            Box::new(FlaskSecretKeyHardcodedTemplate),
        );
        r.register_rule(
            "py-flask-secret-key",
            Box::new(FlaskSecretKeyHardcodedTemplate),
        );

        r.register_rule(
            "flask-sqlalchemy-uri-hardcoded",
            Box::new(FlaskSqlAlchemyUriHardcodedTemplate),
        );
        r.register_rule(
            "py-sqlalchemy-uri",
            Box::new(FlaskSqlAlchemyUriHardcodedTemplate),
        );

        // Cloud / IaC
        r.register_rule(
            "aws-hardcoded-access-key",
            Box::new(AwsHardcodedAccessKeyTemplate),
        );
        r.register_rule(
            "js-aws-hardcoded-key",
            Box::new(AwsHardcodedAccessKeyTemplate),
        );
        r.register_rule(
            "py-aws-hardcoded-key",
            Box::new(AwsHardcodedAccessKeyTemplate),
        );

        r.register_rule(
            "aws-s3-public-read-acl",
            Box::new(AwsS3PublicReadAclTemplate),
        );
        r.register_rule("js-s3-public-acl", Box::new(AwsS3PublicReadAclTemplate));

        r.register_cwe("1104", Box::new(IacDockerLatestTagTemplate));
        r.register_rule(
            "dockerfile-latest-tag",
            Box::new(IacDockerLatestTagTemplate),
        );
        r.register_rule("iac-docker-latest", Box::new(IacDockerLatestTagTemplate));

        r.register_cwe("706", Box::new(IacDockerAddInsteadOfCopyTemplate));
        r.register_rule(
            "dockerfile-add-instead-of-copy",
            Box::new(IacDockerAddInsteadOfCopyTemplate),
        );
        r.register_rule(
            "iac-docker-add",
            Box::new(IacDockerAddInsteadOfCopyTemplate),
        );

        // IacEnvFileHardcoded — registered by rule ID only (no CWE-798 collision with other templates)
        r.register_rule(
            "env-file-hardcoded-secret",
            Box::new(IacEnvFileHardcodedTemplate),
        );
        r.register_rule(
            "dotenv-hardcoded-value",
            Box::new(IacEnvFileHardcodedTemplate),
        );

        // React / Frontend
        r.register_rule(
            "react-href-javascript",
            Box::new(ReactHrefJavascriptTemplate),
        );
        r.register_rule("js-href-user-input", Box::new(ReactHrefJavascriptTemplate));

        r.register_cwe("601", Box::new(ReactWindowLocationTemplate));
        r.register_rule(
            "js-window-location-redirect",
            Box::new(ReactWindowLocationTemplate),
        );
        r.register_rule("react-open-redirect", Box::new(ReactWindowLocationTemplate));

        r.register_cwe("922", Box::new(ReactLocalStorageTokenTemplate));
        r.register_rule(
            "js-localstorage-token",
            Box::new(ReactLocalStorageTokenTemplate),
        );
        r.register_rule(
            "react-localstorage-auth",
            Box::new(ReactLocalStorageTokenTemplate),
        );

        r.register_cwe("362", Box::new(ReactUseEffectMissingDepTemplate));
        r.register_rule(
            "react-useeffect-missing-dep",
            Box::new(ReactUseEffectMissingDepTemplate),
        );
        r.register_rule(
            "js-useeffect-stale-closure",
            Box::new(ReactUseEffectMissingDepTemplate),
        );

        r
    }
}

// ── Template implementations ──────────────────────────────────────────────────

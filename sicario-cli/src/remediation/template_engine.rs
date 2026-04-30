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

        // ── Sprint 1: Cryptography & Secrets ─────────────────────────────────        r.register_cwe("916", Box::new(CryptoPbkdf2LowIterationsTemplate)); // Weak KDF iterations
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
        r.register_rule("express-session-no-httponly",  Box::new(AuthSessionNoHttpOnlyTemplate));
        r.register_rule("js-session-cookie-httponly",   Box::new(AuthSessionNoHttpOnlyTemplate));

        r.register_cwe("614",  Box::new(AuthSessionNoSecureFlagTemplate));
        r.register_rule("express-session-no-secure",    Box::new(AuthSessionNoSecureFlagTemplate));
        r.register_rule("js-session-cookie-secure",     Box::new(AuthSessionNoSecureFlagTemplate));

        r.register_cwe("384",  Box::new(AuthSessionFixationTemplate));
        r.register_rule("js-session-fixation",          Box::new(AuthSessionFixationTemplate));
        r.register_rule("express-session-fixation",     Box::new(AuthSessionFixationTemplate));

        r.register_cwe("532",  Box::new(AuthPasswordInLogTemplate));
        r.register_rule("js-password-in-log",           Box::new(AuthPasswordInLogTemplate));
        r.register_rule("py-password-in-log",           Box::new(AuthPasswordInLogTemplate));
        r.register_rule("log-sensitive-data",           Box::new(AuthPasswordInLogTemplate));

        r.register_cwe("523",  Box::new(AuthBasicAuthOverHttpTemplate));
        r.register_rule("js-basic-auth-over-http",      Box::new(AuthBasicAuthOverHttpTemplate));

        r.register_cwe("613",  Box::new(AuthJwtNoExpiryTemplate));
        r.register_rule("js-jwt-no-expiry",             Box::new(AuthJwtNoExpiryTemplate));
        r.register_rule("py-jwt-no-expiry",             Box::new(AuthJwtNoExpiryTemplate));
        r.register_rule("jwt-missing-expiry",           Box::new(AuthJwtNoExpiryTemplate));

        // ── Sprint 2: Injection (continued) ──────────────────────────────────
        r.register_rule("js-child-process-shell-true",  Box::new(InjectChildProcessShellTrueTemplate));
        r.register_rule("node-spawn-shell-true",        Box::new(InjectChildProcessShellTrueTemplate));

        r.register_rule("py-subprocess-shell-true",     Box::new(InjectPythonSubprocessShellTemplate));
        r.register_rule("python-shell-injection",       Box::new(InjectPythonSubprocessShellTemplate));

        r.register_rule("py-ssti-render-template",      Box::new(InjectSstiTemplate));
        r.register_rule("flask-ssti",                   Box::new(InjectSstiTemplate));

        r.register_cwe("90",   Box::new(InjectLdapTemplate));
        r.register_rule("js-ldap-injection",            Box::new(InjectLdapTemplate));
        r.register_rule("py-ldap-injection",            Box::new(InjectLdapTemplate));

        r.register_cwe("643",  Box::new(InjectXpathTemplate));
        r.register_rule("js-xpath-injection",           Box::new(InjectXpathTemplate));
        r.register_rule("py-xpath-injection",           Box::new(InjectXpathTemplate));

        // ── Sprint 3: Web Headers ─────────────────────────────────────────────
        r.register_rule("express-helmet-missing",       Box::new(WebHelmetMissingTemplate));
        r.register_rule("js-helmet-missing",            Box::new(WebHelmetMissingTemplate));

        r.register_rule("express-csp-missing",          Box::new(WebCspMissingTemplate));
        r.register_rule("js-csp-missing",               Box::new(WebCspMissingTemplate));

        r.register_cwe("319",  Box::new(WebHstsDisabledTemplate));
        r.register_rule("express-hsts-disabled",        Box::new(WebHstsDisabledTemplate));
        r.register_rule("js-hsts-disabled",             Box::new(WebHstsDisabledTemplate));

        r.register_cwe("942",  Box::new(WebCorsCredentialsWildcardTemplate));
        r.register_rule("js-cors-credentials-wildcard", Box::new(WebCorsCredentialsWildcardTemplate));

        r.register_rule("express-referrer-policy",      Box::new(WebReferrerPolicyMissingTemplate));
        r.register_rule("js-referrer-policy-missing",   Box::new(WebReferrerPolicyMissingTemplate));

        r.register_cwe("1021", Box::new(WebClickjackingTemplate));
        r.register_rule("express-frameguard-disabled",  Box::new(WebClickjackingTemplate));
        r.register_rule("js-clickjacking",              Box::new(WebClickjackingTemplate));

        r.register_cwe("525",  Box::new(WebCacheControlMissingTemplate));
        r.register_rule("express-no-cache-control",     Box::new(WebCacheControlMissingTemplate));
        r.register_rule("js-cache-control-missing",     Box::new(WebCacheControlMissingTemplate));

        // ── Sprint 3: Input Validation ────────────────────────────────────────
        r.register_cwe("1321", Box::new(PrototypePollutionMergeTemplate));
        r.register_rule("js-prototype-pollution-merge", Box::new(PrototypePollutionMergeTemplate));

        r.register_rule("js-prototype-pollution-set",   Box::new(PrototypePollutionSetTemplate));

        r.register_cwe("1333", Box::new(InputRegexDosTemplate));
        r.register_rule("js-redos",                     Box::new(InputRegexDosTemplate));
        r.register_rule("js-regex-dos",                 Box::new(InputRegexDosTemplate));

        r.register_cwe("755",  Box::new(InputJsonParseNoTryCatchTemplate));
        r.register_rule("js-json-parse-no-try-catch",   Box::new(InputJsonParseNoTryCatchTemplate));

        r.register_cwe("22",   Box::new(InputPathTraversalTemplate));
        r.register_rule("js-path-traversal",            Box::new(InputPathTraversalTemplate));
        r.register_rule("node-path-traversal",          Box::new(InputPathTraversalTemplate));

        r.register_cwe("20",   Box::new(InputReqBodyNoValidationTemplate));
        r.register_rule("js-req-body-no-validation",    Box::new(InputReqBodyNoValidationTemplate));
        r.register_rule("express-no-input-validation",  Box::new(InputReqBodyNoValidationTemplate));

        // ── Sprint 3: File & Resource ─────────────────────────────────────────
        r.register_cwe("434",  Box::new(FileUploadNoMimeCheckTemplate));
        r.register_rule("js-multer-no-mime-check",      Box::new(FileUploadNoMimeCheckTemplate));
        r.register_rule("express-file-upload-unsafe",   Box::new(FileUploadNoMimeCheckTemplate));

        r.register_cwe("377",  Box::new(FileTempFileInsecureTemplate));
        r.register_rule("py-tempfile-mktemp",           Box::new(FileTempFileInsecureTemplate));

        r.register_cwe("732",  Box::new(FilePermissionsWorldWritableTemplate));
        r.register_rule("py-world-writable-file",       Box::new(FilePermissionsWorldWritableTemplate));
        r.register_rule("py-chmod-world-writable",      Box::new(FilePermissionsWorldWritableTemplate));

        r.register_cwe("390",  Box::new(GoFileCloseErrorIgnoredTemplate));
        r.register_rule("go-close-error-ignored",       Box::new(GoFileCloseErrorIgnoredTemplate));
        r.register_rule("go-defer-close-unchecked",     Box::new(GoFileCloseErrorIgnoredTemplate));

        r.register_cwe("400",  Box::new(FileReadSyncTemplate));
        r.register_rule("js-readfilesync-user-input",   Box::new(FileReadSyncTemplate));
        r.register_rule("node-sync-file-read",          Box::new(FileReadSyncTemplate));

        // ── Sprint 4: SQL + TLS/SSRF + Django/Flask + Cloud/IaC + React ──────
        r.register_rule("js-sql-string-concat",         Box::new(SqlStringConcatTemplate));
        r.register_rule("py-sql-string-concat",         Box::new(SqlStringConcatTemplate));
        r.register_rule("go-sql-string-concat",         Box::new(SqlStringConcatTemplate));
        r.register_rule("sql-string-concat",            Box::new(SqlStringConcatTemplate));

        r.register_rule("js-sql-template-string",       Box::new(SqlTemplateStringTemplate));
        r.register_rule("node-sql-template-literal",    Box::new(SqlTemplateStringTemplate));

        // TLS
        r.register_rule("js-tls-min-version",           Box::new(TlsMinVersionTemplate));
        r.register_rule("go-tls-min-version",           Box::new(TlsMinVersionTemplate));
        r.register_rule("tls-insecure-version",         Box::new(TlsMinVersionTemplate));

        r.register_rule("js-tls-reject-unauthorized",   Box::new(TlsCertVerifyDisabledNodeTemplate));
        r.register_rule("node-tls-verify-disabled",     Box::new(TlsCertVerifyDisabledNodeTemplate));

        r.register_rule("go-tls-insecure-skip-verify",  Box::new(TlsCertVerifyDisabledGoTemplate));
        r.register_rule("go-insecure-skip-verify",      Box::new(TlsCertVerifyDisabledGoTemplate));

        // SSRF
        r.register_rule("js-ssrf-axios",                Box::new(SsrfHttpGetUserInputTemplate));
        r.register_rule("py-ssrf-requests",             Box::new(SsrfHttpGetUserInputTemplate));
        r.register_rule("ssrf-http-get",                Box::new(SsrfHttpGetUserInputTemplate));

        r.register_rule("js-ssrf-fetch",                Box::new(SsrfFetchUserInputTemplate));
        r.register_rule("node-fetch-ssrf",              Box::new(SsrfFetchUserInputTemplate));

        // Django
        r.register_rule("django-debug-true",            Box::new(DjangoDebugTrueTemplate));
        r.register_rule("py-django-debug",              Box::new(DjangoDebugTrueTemplate));

        r.register_rule("django-secret-key-hardcoded",  Box::new(DjangoSecretKeyHardcodedTemplate));
        r.register_rule("py-django-secret-key",         Box::new(DjangoSecretKeyHardcodedTemplate));

        r.register_cwe("183",  Box::new(DjangoAllowedHostsWildcardTemplate));
        r.register_rule("django-allowed-hosts-wildcard", Box::new(DjangoAllowedHostsWildcardTemplate));

        r.register_cwe("352",  Box::new(DjangoCsrfExemptTemplate));
        r.register_rule("django-csrf-exempt",           Box::new(DjangoCsrfExemptTemplate));
        r.register_rule("py-csrf-exempt",               Box::new(DjangoCsrfExemptTemplate));

        r.register_cwe("215",  Box::new(FlaskDebugTrueTemplate));
        r.register_rule("flask-debug-true",             Box::new(FlaskDebugTrueTemplate));
        r.register_rule("py-flask-debug",               Box::new(FlaskDebugTrueTemplate));

        r.register_rule("flask-secret-key-hardcoded",   Box::new(FlaskSecretKeyHardcodedTemplate));
        r.register_rule("py-flask-secret-key",          Box::new(FlaskSecretKeyHardcodedTemplate));

        r.register_rule("flask-sqlalchemy-uri-hardcoded", Box::new(FlaskSqlAlchemyUriHardcodedTemplate));
        r.register_rule("py-sqlalchemy-uri",            Box::new(FlaskSqlAlchemyUriHardcodedTemplate));

        // Cloud / IaC
        r.register_rule("aws-hardcoded-access-key",     Box::new(AwsHardcodedAccessKeyTemplate));
        r.register_rule("js-aws-hardcoded-key",         Box::new(AwsHardcodedAccessKeyTemplate));
        r.register_rule("py-aws-hardcoded-key",         Box::new(AwsHardcodedAccessKeyTemplate));

        r.register_rule("aws-s3-public-read-acl",       Box::new(AwsS3PublicReadAclTemplate));
        r.register_rule("js-s3-public-acl",             Box::new(AwsS3PublicReadAclTemplate));

        r.register_cwe("1104", Box::new(IacDockerLatestTagTemplate));
        r.register_rule("dockerfile-latest-tag",        Box::new(IacDockerLatestTagTemplate));
        r.register_rule("iac-docker-latest",            Box::new(IacDockerLatestTagTemplate));

        r.register_cwe("706",  Box::new(IacDockerAddInsteadOfCopyTemplate));
        r.register_rule("dockerfile-add-instead-of-copy", Box::new(IacDockerAddInsteadOfCopyTemplate));
        r.register_rule("iac-docker-add",               Box::new(IacDockerAddInsteadOfCopyTemplate));

        // IacEnvFileHardcoded — registered by rule ID only (no CWE-798 collision with other templates)
        r.register_rule("env-file-hardcoded-secret",    Box::new(IacEnvFileHardcodedTemplate));
        r.register_rule("dotenv-hardcoded-value",       Box::new(IacEnvFileHardcodedTemplate));

        // React / Frontend
        r.register_rule("react-href-javascript",        Box::new(ReactHrefJavascriptTemplate));
        r.register_rule("js-href-user-input",           Box::new(ReactHrefJavascriptTemplate));

        r.register_cwe("601",  Box::new(ReactWindowLocationTemplate));
        r.register_rule("js-window-location-redirect",  Box::new(ReactWindowLocationTemplate));
        r.register_rule("react-open-redirect",          Box::new(ReactWindowLocationTemplate));

        r.register_cwe("922",  Box::new(ReactLocalStorageTokenTemplate));
        r.register_rule("js-localstorage-token",        Box::new(ReactLocalStorageTokenTemplate));
        r.register_rule("react-localstorage-auth",      Box::new(ReactLocalStorageTokenTemplate));

        r.register_cwe("362",  Box::new(ReactUseEffectMissingDepTemplate));
        r.register_rule("react-useeffect-missing-dep",  Box::new(ReactUseEffectMissingDepTemplate));
        r.register_rule("js-useeffect-stale-closure",   Box::new(ReactUseEffectMissingDepTemplate));

        r
    }
}

// ── Template implementations ──────────────────────────────────────────────────

// ── 1. CryptoWeakHashTemplate (CWE-328) ──────────────────────────────────────

/// Replaces weak hash calls (MD5, SHA1) with SHA-256.
///
/// Handles:
/// - `.md5()` → `.sha256()`
/// - `.sha1()` → `.sha256()`
/// - `hashlib.md5(` → `hashlib.sha256(`
/// - `hashlib.sha1(` → `hashlib.sha256(`
/// - `MessageDigest.getInstance("MD5")` → `MessageDigest.getInstance("SHA-256")`
/// - `MessageDigest.getInstance("SHA-1")` → `MessageDigest.getInstance("SHA-256")`
pub struct CryptoWeakHashTemplate;

impl PatchTemplate for CryptoWeakHashTemplate {
    fn name(&self) -> &'static str {
        "CryptoWeakHash"
    }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        if !lower.contains("md5") && !lower.contains("sha1") && !lower.contains("sha-1") {
            return None;
        }

        let fixed = line
            // Java MessageDigest
            .replace("\"MD5\"", "\"SHA-256\"")
            .replace("\"SHA-1\"", "\"SHA-256\"")
            // Python hashlib
            .replace("hashlib.md5(", "hashlib.sha256(")
            .replace("hashlib.sha1(", "hashlib.sha256(")
            // Generic method-call style
            .replace(".md5()", ".sha256()")
            .replace(".sha1()", ".sha256()")
            // Rust ring / sha1 crate
            .replace("sha1::Sha1", "sha2::Sha256")
            .replace("md5::compute", "sha2::Sha256::digest");

        if fixed == line {
            return None; // pattern not matched
        }
        Some(fixed)
    }
}

// ── 2. CryptoMathRandomTemplate (CWE-338) ────────────────────────────────────

/// Replaces `Math.random()` with a cryptographically secure alternative.
///
/// JavaScript/TypeScript only. Produces:
/// `(crypto.getRandomValues(new Uint32Array(1))[0] / 4294967295)`
pub struct CryptoMathRandomTemplate;

impl PatchTemplate for CryptoMathRandomTemplate {
    fn name(&self) -> &'static str {
        "CryptoMathRandom"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("Math.random()") {
            return None;
        }
        Some(line.replace(
            "Math.random()",
            "(crypto.getRandomValues(new Uint32Array(1))[0] / 4294967295)",
        ))
    }
}

// ── 3. DomInnerHtmlTemplate (CWE-79) ─────────────────────────────────────────

/// Replaces `.innerHTML =` assignments with `.textContent =`.
///
/// This is the safest mechanical fix — it prevents HTML injection while
/// preserving the assignment structure. Applies to JS/TS only.
pub struct DomInnerHtmlTemplate;

impl PatchTemplate for DomInnerHtmlTemplate {
    fn name(&self) -> &'static str {
        "DomInnerHTML"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains(".innerHTML") {
            return None;
        }
        // Replace `.innerHTML =` with `.textContent =`
        // Also handle `innerHTML =` without a leading dot (rare but possible)
        let fixed = line
            .replace(".innerHTML =", ".textContent =")
            .replace(".innerHTML=", ".textContent=");
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// ── 4. DomDocumentWriteTemplate (CWE-79) ─────────────────────────────────────

/// Replaces `document.write(expr)` with a safe DOM text-node append.
///
/// Extracts the argument from `document.write(...)` and rewrites it as:
/// `document.body.appendChild(document.createTextNode(expr))`
pub struct DomDocumentWriteTemplate;

impl PatchTemplate for DomDocumentWriteTemplate {
    fn name(&self) -> &'static str {
        "DomDocumentWrite"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("document.write(") {
            return None;
        }

        // Extract the argument between document.write( ... )
        let arg = extract_call_arg(line, "document.write")?;
        let indent = get_indent(line);
        let semicolon = if line.trim_end().ends_with(';') {
            ";"
        } else {
            ""
        };

        Some(format!(
            "{indent}document.body.appendChild(document.createTextNode({arg})){semicolon}"
        ))
    }
}

// ── 5. WebCorsWildcardTemplate ────────────────────────────────────────────────

/// Replaces `Access-Control-Allow-Origin: *` with an env-var-driven value.
///
/// Works in any language since it's a string replacement. Handles both
/// header-string literals and programmatic header-setting calls.
pub struct WebCorsWildcardTemplate;

impl PatchTemplate for WebCorsWildcardTemplate {
    fn name(&self) -> &'static str {
        "WebCorsWildcard"
    }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        // String literal: `"Access-Control-Allow-Origin", "*"`
        // or header value: `Access-Control-Allow-Origin: *`
        if !line.contains("Access-Control-Allow-Origin") {
            return None;
        }

        let fixed = line
            // Express / Node: res.setHeader("Access-Control-Allow-Origin", "*")
            .replace(
                "\"Access-Control-Allow-Origin\", \"*\"",
                "\"Access-Control-Allow-Origin\", process.env.ALLOWED_ORIGIN || \"\"",
            )
            // Python Flask/Django: response["Access-Control-Allow-Origin"] = "*"
            .replace(
                "\"Access-Control-Allow-Origin\"] = \"*\"",
                "\"Access-Control-Allow-Origin\"] = os.environ.get(\"ALLOWED_ORIGIN\", \"\")",
            )
            // Go: w.Header().Set("Access-Control-Allow-Origin", "*")
            .replace(
                "\"Access-Control-Allow-Origin\", \"*\")",
                "\"Access-Control-Allow-Origin\", os.Getenv(\"ALLOWED_ORIGIN\"))",
            )
            // Raw header string (e.g. in config files or string constants)
            .replace(
                "Access-Control-Allow-Origin: *",
                "Access-Control-Allow-Origin: ${ALLOWED_ORIGIN}",
            );

        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// ── 6. PyUnsafeDeserializeTemplate (CWE-502) ─────────────────────────────────

/// Replaces unsafe Python deserialization calls with safe alternatives.
///
/// - `yaml.load(...)` → `yaml.safe_load(...)`
/// - `pickle.loads(...)` → `json.loads(...)`
/// - `pickle.load(...)` → `json.load(...)`
pub struct PyUnsafeDeserializeTemplate;

impl PatchTemplate for PyUnsafeDeserializeTemplate {
    fn name(&self) -> &'static str {
        "PyUnsafeDeserialize"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }

        let fixed = line
            // yaml.load( → yaml.safe_load(  (must come before generic .load( check)
            .replace("yaml.load(", "yaml.safe_load(")
            // pickle.loads( → json.loads(
            .replace("pickle.loads(", "json.loads(")
            // pickle.load( → json.load(
            .replace("pickle.load(", "json.load(");

        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// ── 7. GoDeferCloseTemplate ───────────────────────────────────────────────────

/// Injects a `defer <var>.Close()` statement after a Go resource-open call.
///
/// Detects patterns like:
/// - `f, err := os.Open(...)`
/// - `rows, err := db.Query(...)`
/// - `resp, err := http.Get(...)`
///
/// and inserts `defer <var>.Close()` on the following line, preserving
/// the original indentation.
pub struct GoDeferCloseTemplate;

impl PatchTemplate for GoDeferCloseTemplate {
    fn name(&self) -> &'static str {
        "GoDeferClose"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Go {
            return None;
        }

        // Match patterns: `varName, err := someCall(...)` or `varName := someCall(...)`
        // where the call is a known resource-opening function.
        let resource_openers = [
            "os.Open(",
            "os.Create(",
            "os.OpenFile(",
            "db.Query(",
            "db.QueryRow(",
            "db.Prepare(",
            "db.Begin(",
            "http.Get(",
            "http.Post(",
            "http.Do(",
            "net.Dial(",
            "net.Listen(",
            "sql.Open(",
        ];

        let trimmed = line.trim();
        let is_resource_open = resource_openers.iter().any(|op| line.contains(op));
        if !is_resource_open {
            return None;
        }

        // Extract the variable name: first identifier before `,` or `:=`
        let var_name = trimmed
            .split([',', ' '])
            .next()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && s.chars().all(|c| c.is_alphanumeric() || c == '_'))?;

        let indent = get_indent(line);

        // Return the original line plus the defer on the next line
        Some(format!("{line}\n{indent}defer {var_name}.Close()"))
    }
}

// ── Shared helpers ────────────────────────────────────────────────────────────

/// Get the leading whitespace of a line.
fn get_indent(line: &str) -> &str {
    let trimmed = line.trim_start();
    &line[..line.len() - trimmed.len()]
}

/// Extract the argument string from a simple single-argument function call.
///
/// Given `"  document.write(userInput);"` and `"document.write"`,
/// returns `Some("userInput")`.
///
/// Returns `None` if the call pattern is not found or the argument is empty.
fn extract_call_arg<'a>(line: &'a str, fn_name: &str) -> Option<&'a str> {
    let call = format!("{fn_name}(");
    let start = line.find(&call)? + call.len();
    // Find the matching closing paren — handle one level of nesting
    let rest = &line[start..];
    let mut depth = 1usize;
    let mut end = 0;
    for (i, ch) in rest.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            _ => {}
        }
    }
    let arg = rest[..end].trim();
    if arg.is_empty() {
        None
    } else {
        Some(arg)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// ── 8. CryptoEcbModeTemplate (CWE-327) ───────────────────────────────────────

/// Replaces ECB cipher mode with GCM in cipher algorithm strings.
///
/// ECB (Electronic Codebook) is deterministic and leaks patterns across blocks.
/// GCM (Galois/Counter Mode) provides authenticated encryption.
///
/// Handles:
/// - `"aes-128-ecb"` → `"aes-256-gcm"`
/// - `"AES/ECB/PKCS5Padding"` → `"AES/GCM/NoPadding"` (Java)
/// - `Cipher.getInstance("AES/ECB/...")` → `Cipher.getInstance("AES/GCM/NoPadding")`
/// - `createCipheriv("aes-...-ecb", ...)` → `createCipheriv("aes-256-gcm", ...)`
pub struct CryptoEcbModeTemplate;

impl PatchTemplate for CryptoEcbModeTemplate {
    fn name(&self) -> &'static str {
        "CryptoEcbMode"
    }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        if !lower.contains("ecb") {
            return None;
        }

        let fixed = line
            // Java JCE: "AES/ECB/PKCS5Padding" → "AES/GCM/NoPadding"
            .replace("AES/ECB/PKCS5Padding", "AES/GCM/NoPadding")
            .replace("AES/ECB/PKCS7Padding", "AES/GCM/NoPadding")
            .replace("AES/ECB/NoPadding", "AES/GCM/NoPadding")
            // Node.js crypto: any "aes-NNN-ecb" → "aes-256-gcm"
            .replace("aes-128-ecb", "aes-256-gcm")
            .replace("aes-192-ecb", "aes-256-gcm")
            .replace("aes-256-ecb", "aes-256-gcm")
            // Python PyCryptodome / cryptography: AES.MODE_ECB → AES.MODE_GCM
            .replace("AES.MODE_ECB", "AES.MODE_GCM")
            // Generic uppercase ECB → GCM (catches remaining patterns)
            .replace("ECB", "GCM");

        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// ── 9. CryptoHardcodedJwtTemplate (CWE-798) ──────────────────────────────────

/// Replaces hardcoded JWT signing secrets with environment variable lookups.
///
/// Handles JS/TS `jwt.sign(payload, "literal")` and Python
/// `jwt.encode(payload, "literal", ...)`.
///
/// The replacement preserves the rest of the call — only the secret argument
/// is swapped.
pub struct CryptoHardcodedJwtTemplate;

impl PatchTemplate for CryptoHardcodedJwtTemplate {
    fn name(&self) -> &'static str {
        "CryptoHardcodedJwt"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        // Must contain a JWT sign/encode call with a string literal secret
        let lower = line.to_lowercase();
        if !lower.contains("jwt.sign") && !lower.contains("jwt.encode") {
            return None;
        }

        match lang {
            Language::JavaScript | Language::TypeScript => {
                // Replace any string literal (single or double quoted) that
                // appears as the second argument to jwt.sign(...)
                // Pattern: jwt.sign(<anything>, "<secret>") or jwt.sign(<anything>, '<secret>')
                let fixed = replace_jwt_secret_js(line, "process.env.JWT_SECRET")?;
                Some(fixed)
            }
            Language::Python => {
                let fixed = replace_jwt_secret_py(line, "os.environ.get(\"JWT_SECRET\")")?;
                Some(fixed)
            }
            _ => None,
        }
    }
}

/// Replace the string-literal secret in a JS/TS `jwt.sign(payload, "secret", ...)` call.
fn replace_jwt_secret_js(line: &str, replacement: &str) -> Option<String> {
    // Find jwt.sign( or jwt.verify( then locate the second string argument
    for fn_name in &["jwt.sign(", "jwt.verify("] {
        if let Some(call_start) = line.find(fn_name) {
            let after_fn = &line[call_start + fn_name.len()..];
            // Skip the first argument (up to the first top-level comma)
            if let Some(comma_pos) = find_top_level_comma(after_fn) {
                let after_comma = after_fn[comma_pos + 1..].trim_start();
                // Check if the second arg starts with a string literal
                if let Some((secret_end, quote_char)) = find_string_literal_end(after_comma) {
                    let before_secret = &line[..call_start + fn_name.len() + comma_pos + 1];
                    let after_secret = &after_comma[secret_end..];
                    let indent_len = line.len() - line.trim_start().len();
                    let indent = &line[..indent_len];
                    let _ = quote_char; // consumed
                    return Some(format!("{before_secret} {replacement}{after_secret}"));
                }
            }
        }
    }
    None
}

/// Replace the string-literal secret in a Python `jwt.encode(payload, "secret", ...)` call.
fn replace_jwt_secret_py(line: &str, replacement: &str) -> Option<String> {
    for fn_name in &["jwt.encode(", "jwt.decode("] {
        if let Some(call_start) = line.find(fn_name) {
            let after_fn = &line[call_start + fn_name.len()..];
            if let Some(comma_pos) = find_top_level_comma(after_fn) {
                let after_comma = after_fn[comma_pos + 1..].trim_start();
                if let Some((secret_end, _)) = find_string_literal_end(after_comma) {
                    let before_secret = &line[..call_start + fn_name.len() + comma_pos + 1];
                    let after_secret = &after_comma[secret_end..];
                    return Some(format!("{before_secret} {replacement}{after_secret}"));
                }
            }
        }
    }
    None
}

// ── 10. AuthMissingSaltTemplate (CWE-759) ────────────────────────────────────

/// Injects a secure salt-rounds parameter into bcrypt hash calls missing one.
///
/// `bcrypt.hash(password)` → `bcrypt.hash(password, 12)`
/// `bcrypt.hashSync(password)` → `bcrypt.hashSync(password, 12)`
/// `bcrypt.hashpw(password, ...)` is Python — already requires a salt, so
/// this template targets the JS/TS pattern where the rounds arg is omitted.
pub struct AuthMissingSaltTemplate;

impl PatchTemplate for AuthMissingSaltTemplate {
    fn name(&self) -> &'static str {
        "AuthMissingSalt"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }

        let lower = line.to_lowercase();
        if !lower.contains("bcrypt.hash") {
            return None;
        }

        // Only fix calls that have exactly one argument (missing salt rounds).
        // If there's already a second argument (comma inside the call), leave it.
        for fn_name in &["bcrypt.hashSync(", "bcrypt.hash("] {
            if let Some(start) = line.find(fn_name) {
                let after_fn = &line[start + fn_name.len()..];
                // Find the closing paren
                if let Some(close) = find_matching_paren(after_fn) {
                    let args = &after_fn[..close];
                    // If there's already a top-level comma, salt is present
                    if find_top_level_comma(args).is_some() {
                        return None;
                    }
                    // Inject salt rounds
                    let before = &line[..start + fn_name.len()];
                    let after = &after_fn[close..];
                    return Some(format!("{before}{args}, 12{after}"));
                }
            }
        }
        None
    }
}

// ── 11. DomPostMessageWildcardTemplate (CWE-345) ─────────────────────────────

/// Replaces `postMessage(data, '*')` wildcard origin with an env-var target.
///
/// A wildcard origin allows any page to receive the message, enabling
/// cross-origin data leakage.
pub struct DomPostMessageWildcardTemplate;

impl PatchTemplate for DomPostMessageWildcardTemplate {
    fn name(&self) -> &'static str {
        "DomPostMessageWildcard"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("postMessage") {
            return None;
        }

        // Replace the wildcard origin argument: , '*') or , "*")
        let fixed = line
            .replace(", '*')", ", process.env.EXPECTED_ORIGIN)")
            .replace(", \"*\")", ", process.env.EXPECTED_ORIGIN)");

        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// ── 12. WebCookieInsecureTemplate (CWE-614 / CWE-1004) ───────────────────────

/// Appends secure cookie flags to `res.cookie(...)` calls missing them.
///
/// Detects Express.js `res.cookie('name', value)` calls that don't already
/// include a security options object, and appends
/// `{ httpOnly: true, secure: true, sameSite: 'strict' }`.
pub struct WebCookieInsecureTemplate;

impl PatchTemplate for WebCookieInsecureTemplate {
    fn name(&self) -> &'static str {
        "WebCookieInsecure"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }

        if !line.contains("res.cookie(") && !line.contains(".cookie(") {
            return None;
        }

        // If the call already contains httpOnly or secure flags, leave it
        if line.contains("httpOnly") || line.contains("secure:") || line.contains("sameSite") {
            return None;
        }

        // Find the closing paren of the cookie call and inject options before it
        let call = if line.contains("res.cookie(") {
            "res.cookie("
        } else {
            ".cookie("
        };
        let start = line.find(call)?;
        let after_fn = &line[start + call.len()..];
        let close = find_matching_paren(after_fn)?;

        let args = &after_fn[..close];
        let rest = &after_fn[close + 1..]; // everything after the closing paren
        let before = &line[..start + call.len()];

        // Trim trailing semicolon from rest for clean reconstruction
        let rest_trimmed = rest.trim_end_matches(';').trim_end();
        let semicolon = if rest.trim_end().ends_with(';') || line.trim_end().ends_with(';') {
            ";"
        } else {
            ""
        };

        Some(format!(
            "{before}{args}, {{ httpOnly: true, secure: true, sameSite: 'strict' }}){rest_trimmed}{semicolon}"
        ))
    }
}

// ── 13. WebExpressXPoweredByTemplate (CWE-200) ───────────────────────────────

/// Injects `app.disable('x-powered-by')` after Express app initialisation.
///
/// The `X-Powered-By: Express` header leaks framework information to attackers.
/// Detects `const app = express()` (and variants) and appends the disable call
/// on the following line, preserving indentation.
pub struct WebExpressXPoweredByTemplate;

impl PatchTemplate for WebExpressXPoweredByTemplate {
    fn name(&self) -> &'static str {
        "WebExpressXPoweredBy"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }

        // Match: <var> = express() with optional const/let/var
        let trimmed = line.trim();
        if !trimmed.contains("express()") {
            return None;
        }

        // Extract the app variable name
        let app_var = trimmed
            .trim_start_matches("const ")
            .trim_start_matches("let ")
            .trim_start_matches("var ")
            .split(|c: char| c == '=' || c.is_whitespace())
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())?;

        let indent = get_indent(line);
        let semicolon = if line.trim_end().ends_with(';') {
            ";"
        } else {
            ""
        };

        // Return original line + injected disable call on next line
        Some(format!(
            "{line}\n{indent}{app_var}.disable('x-powered-by'){semicolon}"
        ))
    }
}

// ── 14. PyRequestsVerifyFalseTemplate (CWE-295) ───────────────────────────────

/// Removes `verify=False` from Python `requests` calls, restoring TLS verification.
///
/// `requests.get(url, verify=False)` → `requests.get(url)`
/// `requests.post(url, data=d, verify=False)` → `requests.post(url, data=d)`
///
/// Handles both standalone `verify=False` and `verify=False` mixed with other kwargs.
pub struct PyRequestsVerifyFalseTemplate;

impl PatchTemplate for PyRequestsVerifyFalseTemplate {
    fn name(&self) -> &'static str {
        "PyRequestsVerifyFalse"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }
        if !line.contains("verify=False") && !line.contains("verify = False") {
            return None;
        }

        // Remove ", verify=False" or ", verify = False" (with optional spaces)
        // Also handle the case where it's the only kwarg: "(url, verify=False)"
        let fixed = remove_verify_false(line)?;
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

/// Remove `verify=False` (with surrounding comma/space) from a Python call.
fn remove_verify_false(line: &str) -> Option<String> {
    // Try patterns in order of specificity
    let patterns = [
        ", verify=False",
        ", verify = False",
        ",verify=False",
        ",verify = False",
        // Last-arg with no trailing comma
        " verify=False",
        " verify = False",
    ];
    for pat in &patterns {
        if line.contains(pat) {
            return Some(line.replacen(pat, "", 1));
        }
    }
    // Sole kwarg: (url, verify=False) → already handled above
    // Edge case: verify=False is the only argument after url
    if line.contains("(verify=False)") {
        return Some(line.replace("(verify=False)", "()"));
    }
    None
}

// ── 15. InjectEvalTemplate (CWE-94) ──────────────────────────────────────────

/// Replaces `eval(` with `JSON.parse(` (JS/TS) or `ast.literal_eval(` (Python).
///
/// `eval` executes arbitrary code; `JSON.parse` / `ast.literal_eval` safely
/// parse data without code execution.
pub struct InjectEvalTemplate;

impl PatchTemplate for InjectEvalTemplate {
    fn name(&self) -> &'static str {
        "InjectEval"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {
                if !line.contains("eval(") {
                    return None;
                }
                Some(line.replace("eval(", "JSON.parse("))
            }
            Language::Python => {
                if !line.contains("eval(") {
                    return None;
                }
                Some(line.replace("eval(", "ast.literal_eval("))
            }
            _ => None,
        }
    }
}

// ── 16. InjectOsExecTemplate (CWE-78) ────────────────────────────────────────

/// Replaces standalone `exec(` with `execFile(` in Node.js child_process calls.
///
/// `exec` passes the command string to the shell, enabling injection.
/// `execFile` spawns the executable directly with an argument array,
/// bypassing shell interpretation entirely.
///
/// Does NOT replace `.exec(` (regex method) or `execFile(`/`execSync(`.
pub struct InjectOsExecTemplate;

impl PatchTemplate for InjectOsExecTemplate {
    fn name(&self) -> &'static str {
        "InjectOsExec"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !contains_standalone_exec(line) {
            return None;
        }
        Some(replace_standalone_exec(line))
    }
}

/// Returns true if `line` contains `exec(` that is NOT preceded by a dot
/// and is NOT already `execFile(`, `execSync(`, or `execFileSync(`.
fn contains_standalone_exec(line: &str) -> bool {
    let mut search = line;
    while let Some(pos) = search.find("exec(") {
        let before = &search[..pos];
        let prev_char = before.chars().last();
        let suffix = &search[pos..];
        if prev_char != Some('.')
            && !suffix.starts_with("execFile(")
            && !suffix.starts_with("execSync(")
            && !suffix.starts_with("execFileSync(")
        {
            return true;
        }
        search = &search[pos + 5..];
    }
    false
}

/// Replace the first standalone `exec(` with `execFile(`.
fn replace_standalone_exec(line: &str) -> String {
    let mut result = String::with_capacity(line.len() + 4);
    let mut search = line;
    let mut replaced = false;
    while !search.is_empty() {
        if !replaced {
            if let Some(pos) = search.find("exec(") {
                let before = &search[..pos];
                let prev_char = before.chars().last();
                let suffix = &search[pos..];
                if prev_char != Some('.')
                    && !suffix.starts_with("execFile(")
                    && !suffix.starts_with("execSync(")
                    && !suffix.starts_with("execFileSync(")
                {
                    result.push_str(before);
                    result.push_str("execFile(");
                    search = &search[pos + 5..];
                    replaced = true;
                    continue;
                }
                result.push_str(&search[..pos + 5]);
                search = &search[pos + 5..];
                continue;
            }
        }
        result.push_str(search);
        break;
    }
    result
}

// ── 17. InjectNoSqlTypeCastTemplate (CWE-943) ────────────────────────────────

/// Wraps untyped user-input variables in `String()` casts inside MongoDB queries.
///
/// `User.find({ _id: req.query.id })` → `User.find({ _id: String(req.query.id) })`
///
/// Prevents NoSQL object injection where `req.query.id` could be `{ $gt: "" }`
/// instead of a plain string.
pub struct InjectNoSqlTypeCastTemplate;

impl PatchTemplate for InjectNoSqlTypeCastTemplate {
    fn name(&self) -> &'static str {
        "InjectNoSqlTypeCast"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        let is_query = line.contains(".find(")
            || line.contains(".findOne(")
            || line.contains(".findById(")
            || line.contains(".updateOne(")
            || line.contains(".deleteOne(")
            || line.contains(".countDocuments(");
        if !is_query {
            return None;
        }
        let user_input_patterns = ["req.body.", "req.query.", "req.params."];
        let mut fixed = line.to_string();
        let mut changed = false;
        for pat in &user_input_patterns {
            if fixed.contains(pat) {
                fixed = wrap_nosql_input(&fixed, pat);
                changed = true;
            }
        }
        if !changed || fixed == line {
            return None;
        }
        Some(fixed)
    }
}

/// Wrap occurrences of `req.X.field` that are not already inside `String(...)`.
fn wrap_nosql_input(line: &str, prefix: &str) -> String {
    let mut result = String::with_capacity(line.len() + 16);
    let mut rest = line;
    while let Some(pos) = rest.find(prefix) {
        let before = &rest[..pos];
        let already_wrapped = before.trim_end().ends_with("String(");
        let after_prefix = &rest[pos + prefix.len()..];
        let ident_len = after_prefix
            .find(|c: char| !c.is_alphanumeric() && c != '_')
            .unwrap_or(after_prefix.len());
        let ident = &after_prefix[..ident_len];
        let full_expr = format!("{prefix}{ident}");
        let rest_after = &rest[pos + full_expr.len()..];
        result.push_str(before);
        if already_wrapped || ident.is_empty() {
            result.push_str(&full_expr);
        } else {
            result.push_str(&format!("String({full_expr})"));
        }
        rest = rest_after;
    }
    result.push_str(rest);
    result
}

// ── 18. ReactDangerouslySetInnerHtmlTemplate (CWE-79) ────────────────────────

/// Wraps the `__html` value in `DOMPurify.sanitize(...)` in React JSX.
///
/// `dangerouslySetInnerHTML={{ __html: userInput }}`
/// → `dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }}`
pub struct ReactDangerouslySetInnerHtmlTemplate;

impl PatchTemplate for ReactDangerouslySetInnerHtmlTemplate {
    fn name(&self) -> &'static str {
        "ReactDangerouslySetInnerHTML"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("dangerouslySetInnerHTML") || !line.contains("__html:") {
            return None;
        }
        if line.contains("DOMPurify.sanitize(") || line.contains("sanitize(") {
            return None;
        }
        let fixed = wrap_html_value(line)?;
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

/// Wrap the value after `__html:` in `DOMPurify.sanitize(...)`.
fn wrap_html_value(line: &str) -> Option<String> {
    let marker = "__html:";
    let pos = line.find(marker)?;
    let after_marker = &line[pos + marker.len()..];
    let value_start = after_marker.len() - after_marker.trim_start().len();
    let value_str = after_marker.trim_start();
    let value_end = find_value_end(value_str)?;
    let value = value_str[..value_end].trim();
    let before = &line[..pos + marker.len() + value_start];
    let after = &value_str[value_end..];
    Some(format!("{before}DOMPurify.sanitize({value}){after}"))
}

/// Find the end of a JSX expression value (stops at `}` or `,` at depth 0).
fn find_value_end(s: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_str: Option<char> = None;
    for (i, ch) in s.char_indices() {
        if let Some(q) = in_str {
            if ch == q {
                in_str = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' | '`' => in_str = Some(ch),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' if depth > 0 => {
                depth = depth.saturating_sub(1);
            }
            '}' => {
                if depth == 0 {
                    return Some(i);
                }
                depth -= 1;
            }
            ',' if depth == 0 => return Some(i),
            _ => {}
        }
    }
    Some(s.len())
}

// ── 19. IacDockerRootUserTemplate (CWE-269) ──────────────────────────────────

/// Injects `USER nonroot` before the final `CMD` or `ENTRYPOINT` in a Dockerfile.
///
/// Running containers as root is a privilege escalation risk. This template
/// detects CMD/ENTRYPOINT lines and prepends a USER instruction.
///
/// Accepts any language — Dockerfiles have no entry in the `Language` enum,
/// so the registry matches by rule ID only.
pub struct IacDockerRootUserTemplate;

impl PatchTemplate for IacDockerRootUserTemplate {
    fn name(&self) -> &'static str {
        "IacDockerRootUser"
    }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        let trimmed = line.trim();
        if !trimmed.starts_with("CMD ")
            && !trimmed.starts_with("CMD[")
            && !trimmed.starts_with("ENTRYPOINT ")
            && !trimmed.starts_with("ENTRYPOINT[")
        {
            return None;
        }
        let indent = get_indent(line);
        Some(format!("{indent}USER nonroot\n{line}"))
    }
}

// ── Shared parsing helpers ────────────────────────────────────────────────────
fn find_top_level_comma(s: &str) -> Option<usize> {
    let mut depth = 0usize;
    let mut in_str: Option<char> = None;
    for (i, ch) in s.char_indices() {
        if let Some(q) = in_str {
            if ch == q {
                in_str = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' | '`' => in_str = Some(ch),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => {
                if depth == 0 {
                    return None; // hit closing paren before finding comma
                }
                depth -= 1;
            }
            ',' if depth == 0 => return Some(i),
            _ => {}
        }
    }
    None
}

/// Find the end position of a string literal starting at the beginning of `s`.
///
/// Returns `(end_exclusive, quote_char)` where `end_exclusive` is the index
/// just past the closing quote.
fn find_string_literal_end(s: &str) -> Option<(usize, char)> {
    let mut chars = s.char_indices();
    let (_, quote) = chars.next()?;
    if quote != '"' && quote != '\'' && quote != '`' {
        return None;
    }
    for (i, ch) in chars {
        if ch == quote {
            return Some((i + 1, quote));
        }
    }
    None
}

/// Find the index of the closing `)` that matches the opening of `s`
/// (i.e., `s` starts just after the opening `(`).
fn find_matching_paren(s: &str) -> Option<usize> {
    let mut depth = 1usize;
    let mut in_str: Option<char> = None;
    for (i, ch) in s.char_indices() {
        if let Some(q) = in_str {
            if ch == q {
                in_str = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' | '`' => in_str = Some(ch),
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(i);
                }
            }
            _ => {}
        }
    }
    None
}

// ── Sprint 1: Cryptography & Secrets (7 templates) ───────────────────────────

// ── 20. CryptoPbkdf2LowIterationsTemplate (CWE-916) ──────────────────────────

/// Replaces dangerously low PBKDF2 iteration counts with the OWASP 2023 minimum.
///
/// OWASP recommends ≥ 310,000 iterations for PBKDF2-HMAC-SHA256.
/// Handles Node.js `crypto.pbkdf2Sync(pwd, salt, <N>, ...)` and
/// Python `hashlib.pbkdf2_hmac('sha256', pwd, salt, <N>)`.
///
/// Only fires when the iteration count is a numeric literal < 100,000.
pub struct CryptoPbkdf2LowIterationsTemplate;

impl PatchTemplate for CryptoPbkdf2LowIterationsTemplate {
    fn name(&self) -> &'static str {
        "CryptoPbkdf2LowIterations"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript | Language::Python => {}
            _ => return None,
        }

        let lower = line.to_lowercase();
        if !lower.contains("pbkdf2") {
            return None;
        }

        // Find a numeric literal that looks like an iteration count (3rd positional
        // arg in Node, 4th in Python hashlib). We scan for standalone integers
        // that are < 100_000 and replace the first one found.
        replace_low_iteration_count(line, 310_000)
    }
}

/// Scan `line` for the first integer literal < `threshold` and replace it.
/// Returns `None` if no such literal is found or all literals are already safe.
fn replace_low_iteration_count(line: &str, replacement: u64) -> Option<String> {
    // Walk through the line looking for digit sequences
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            // Make sure this isn't part of a larger identifier (preceded by letter/_)
            let preceded_by_ident =
                i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
            if preceded_by_ident {
                // Skip past this digit run
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                continue;
            }

            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            // Make sure not followed by a letter (e.g. "1000px")
            let followed_by_ident = i < bytes.len()
                && (bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' || bytes[i] == b'.');
            if followed_by_ident {
                continue;
            }

            let num_str = &line[start..i];
            if let Ok(n) = num_str.parse::<u64>() {
                // Only replace values that look like iteration counts:
                // > 100 (avoids key lengths like 32/64) and < 100,000 (unsafe)
                if n > 100 && n < 100_000 {
                    let fixed = format!("{}{}{}", &line[..start], replacement, &line[i..]);
                    return Some(fixed);
                }
            }
        } else {
            i += 1;
        }
    }
    None
}

// ── 21. CryptoRsaKeyTooShortTemplate (CWE-326) ───────────────────────────────

/// Replaces RSA key sizes < 2048 bits with 4096.
///
/// Handles:
/// - Node.js: `generateKeyPair('rsa', { modulusLength: 1024 })`
/// - Python cryptography: `rsa.generate_private_key(key_size=1024, ...)`
/// - Python Crypto: `RSA.generate(1024)`
pub struct CryptoRsaKeyTooShortTemplate;

impl PatchTemplate for CryptoRsaKeyTooShortTemplate {
    fn name(&self) -> &'static str {
        "CryptoRsaKeyTooShort"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript | Language::Python => {}
            _ => return None,
        }

        let lower = line.to_lowercase();
        // Must be an RSA key generation context
        if !lower.contains("rsa") && !lower.contains("moduluslength") && !lower.contains("key_size")
        {
            return None;
        }

        // Replace any integer literal in [512, 2047] with 4096
        replace_rsa_key_size(line, 4096)
    }
}

/// Replace the first RSA key size literal in [512, 2047] with `replacement`.
fn replace_rsa_key_size(line: &str, replacement: u32) -> Option<String> {
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            let preceded_by_ident =
                i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || bytes[i - 1] == b'_');
            if preceded_by_ident {
                while i < bytes.len() && bytes[i].is_ascii_digit() {
                    i += 1;
                }
                continue;
            }
            let start = i;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            let followed_by_ident = i < bytes.len()
                && (bytes[i].is_ascii_alphabetic() || bytes[i] == b'_' || bytes[i] == b'.');
            if followed_by_ident {
                continue;
            }

            let num_str = &line[start..i];
            if let Ok(n) = num_str.parse::<u32>() {
                if (512..2048).contains(&n) {
                    return Some(format!("{}{}{}", &line[..start], replacement, &line[i..]));
                }
            }
        } else {
            i += 1;
        }
    }
    None
}

// ── 22. CryptoHardcodedAesKeyTemplate (CWE-321) ──────────────────────────────

/// Replaces a hardcoded string literal used as an AES key with an env-var lookup.
///
/// Handles:
/// - Node.js: `createCipheriv('aes-256-gcm', 'hardcodedkey', iv)`
///   → `createCipheriv('aes-256-gcm', process.env.AES_KEY, iv)`
/// - Python: `AES.new(b'hardcodedkey', AES.MODE_GCM)`
///   → `AES.new(os.environ.get("AES_KEY").encode(), AES.MODE_GCM)`
pub struct CryptoHardcodedAesKeyTemplate;

impl PatchTemplate for CryptoHardcodedAesKeyTemplate {
    fn name(&self) -> &'static str {
        "CryptoHardcodedAesKey"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        if !lower.contains("aes") {
            return None;
        }

        match lang {
            Language::JavaScript | Language::TypeScript => {
                // createCipheriv / createDecipheriv: second arg is the key
                for fn_name in &["createCipheriv(", "createDecipheriv("] {
                    if let Some(pos) = line.find(fn_name) {
                        let after = &line[pos + fn_name.len()..];
                        // Skip first arg (algorithm string)
                        if let Some(comma) = find_top_level_comma(after) {
                            let after_comma = after[comma + 1..].trim_start();
                            if let Some((end, _)) = find_string_literal_end(after_comma) {
                                let before = &line[..pos + fn_name.len() + comma + 1];
                                let rest = &after_comma[end..];
                                return Some(format!("{before} process.env.AES_KEY{rest}"));
                            }
                        }
                    }
                }
                None
            }
            Language::Python => {
                // AES.new(b'key', ...) or AES.new('key', ...)
                if let Some(pos) = line.find("AES.new(") {
                    let after = &line[pos + "AES.new(".len()..];
                    // The first arg is the key — check for string/bytes literal
                    let trimmed = after.trim_start();
                    // Handle b'...' or b"..." byte literals
                    let (literal_end, is_bytes) =
                        if trimmed.starts_with("b'") || trimmed.starts_with("b\"") {
                            let quote = trimmed.chars().nth(1)?;
                            let inner = &trimmed[2..];
                            let end = inner.find(quote)? + 3; // b + quote + content + quote
                            (end, true)
                        } else if trimmed.starts_with('\'') || trimmed.starts_with('"') {
                            let quote = trimmed.chars().next()?;
                            let inner = &trimmed[1..];
                            let end = inner.find(quote)? + 2;
                            (end, false)
                        } else {
                            return None;
                        };
                    let offset = after.len() - trimmed.len();
                    let before = &line[..pos + "AES.new(".len() + offset];
                    let rest = &trimmed[literal_end..];
                    let _ = is_bytes;
                    return Some(format!(
                        "{before}os.environ.get(\"AES_KEY\").encode(){rest}"
                    ));
                }
                None
            }
            _ => None,
        }
    }
}

// ── 23. CryptoInsecureRandomSeedTemplate (CWE-335) ───────────────────────────

/// Removes deterministic `random.seed(<integer>)` calls in Python.
///
/// A fixed seed makes the PRNG output predictable. The fix replaces the
/// entire call with a comment so the developer is aware of the change.
pub struct CryptoInsecureRandomSeedTemplate;

impl PatchTemplate for CryptoInsecureRandomSeedTemplate {
    fn name(&self) -> &'static str {
        "CryptoInsecureRandomSeed"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }

        if !line.contains("random.seed(") {
            return None;
        }

        // Only fire when the argument is an integer literal (including 0)
        let after_open = line.find("random.seed(")? + "random.seed(".len();
        let rest = &line[after_open..];
        let close = rest.find(')')?;
        let arg = rest[..close].trim();

        // Accept integer literals (possibly negative)
        let is_int_literal = arg
            .trim_start_matches('-')
            .chars()
            .all(|c| c.is_ascii_digit())
            && !arg.is_empty();

        if !is_int_literal {
            return None;
        }

        let indent = get_indent(line);
        Some(format!("{indent}# SICARIO FIX: removed deterministic random.seed({arg}) — PRNG is now seeded from OS entropy"))
    }
}

// ── 24. CryptoMd5PasswordHashTemplate (CWE-916) ──────────────────────────────

/// Replaces MD5-based password hashing with bcrypt.
///
/// MD5 is not a password hashing function — it's a fast hash with no work
/// factor, making it trivially brute-forceable.
///
/// Handles:
/// - JS: `md5(password)` → `await bcrypt.hash(password, 12)`
/// - Python: `hashlib.md5(password.encode())` → `bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))`
/// - Go: `md5.Sum([]byte(password))` → `bcrypt.GenerateFromPassword([]byte(password), 12)`
pub struct CryptoMd5PasswordHashTemplate;

impl PatchTemplate for CryptoMd5PasswordHashTemplate {
    fn name(&self) -> &'static str {
        "CryptoMd5PasswordHash"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        if !lower.contains("md5") {
            return None;
        }

        let indent = get_indent(line);

        match lang {
            Language::JavaScript | Language::TypeScript => {
                if !line.contains("md5(") && !line.contains("md5.hex(") {
                    return None;
                }
                // Replace the md5(...) call with bcrypt.hash(...)
                // Extract the argument
                let call = if line.contains("md5.hex(") {
                    "md5.hex("
                } else {
                    "md5("
                };
                if let Some(pos) = line.find(call) {
                    let after = &line[pos + call.len()..];
                    if let Some(close) = find_matching_paren(after) {
                        let arg = &after[..close];
                        let before = &line[..pos];
                        let rest = &after[close + 1..];
                        return Some(format!("{before}await bcrypt.hash({arg}, 12){rest}"));
                    }
                }
                None
            }
            Language::Python => {
                if !line.contains("hashlib.md5(") {
                    return None;
                }
                if let Some(pos) = line.find("hashlib.md5(") {
                    let after = &line[pos + "hashlib.md5(".len()..];
                    if let Some(close) = find_matching_paren(after) {
                        let arg = &after[..close];
                        let before = &line[..pos];
                        let rest = &after[close + 1..];
                        return Some(format!(
                            "{before}bcrypt.hashpw({arg}, bcrypt.gensalt(12)){rest}"
                        ));
                    }
                }
                None
            }
            Language::Go => {
                if !line.contains("md5.Sum(") && !line.contains("md5.New(") {
                    return None;
                }
                let call = if line.contains("md5.Sum(") {
                    "md5.Sum("
                } else {
                    "md5.New("
                };
                if let Some(pos) = line.find(call) {
                    let after = &line[pos + call.len()..];
                    if let Some(close) = find_matching_paren(after) {
                        let arg = &after[..close];
                        let before = &line[..pos];
                        let rest = &after[close + 1..];
                        return Some(format!(
                            "{before}bcrypt.GenerateFromPassword({arg}, 12){rest}"
                        ));
                    }
                }
                None
            }
            _ => None,
        }
    }
}

// ── 25. CryptoJwtNoneAlgorithmTemplate (CWE-347) ─────────────────────────────

/// Replaces `'none'` / `"none"` in JWT algorithm specifications with `'HS256'`.
///
/// The `none` algorithm disables signature verification entirely, allowing
/// any token to be accepted as valid.
///
/// Handles:
/// - JS: `{ algorithms: ['none'] }` → `{ algorithms: ['HS256'] }`
/// - JS: `jwt.verify(token, secret, { algorithms: ['none'] })`
/// - Python: `algorithm='none'` → `algorithm='HS256'`
pub struct CryptoJwtNoneAlgorithmTemplate;

impl PatchTemplate for CryptoJwtNoneAlgorithmTemplate {
    fn name(&self) -> &'static str {
        "CryptoJwtNoneAlgorithm"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript | Language::Python => {}
            _ => return None,
        }

        let lower = line.to_lowercase();
        if !lower.contains("none") {
            return None;
        }
        // Must be in a JWT context
        if !lower.contains("jwt") && !lower.contains("algorithm") && !lower.contains("algorithms") {
            return None;
        }

        let fixed = line
            .replace("'none'", "'HS256'")
            .replace("\"none\"", "\"HS256\"");

        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// ── 26. CryptoJwtWeakAlgorithmTemplate (CWE-327) ─────────────────────────────

/// Replaces weak JWT signing algorithms (HS1, RS1, none) with HS256.
///
/// Handles both string literal forms in JS/TS and Python keyword arguments.
pub struct CryptoJwtWeakAlgorithmTemplate;

impl PatchTemplate for CryptoJwtWeakAlgorithmTemplate {
    fn name(&self) -> &'static str {
        "CryptoJwtWeakAlgorithm"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript | Language::Python => {}
            _ => return None,
        }

        let lower = line.to_lowercase();
        // Must be in a JWT context
        if !lower.contains("jwt") && !lower.contains("algorithm") {
            return None;
        }

        // Weak algorithms to replace
        let weak = [
            ("'HS1'", "'HS256'"),
            ("\"HS1\"", "\"HS256\""),
            ("'RS1'", "'RS256'"),
            ("\"RS1\"", "\"RS256\""),
            ("'HS0'", "'HS256'"),
            ("\"HS0\"", "\"HS256\""),
        ];

        let mut fixed = line.to_string();
        let mut changed = false;
        for (from, to) in &weak {
            if fixed.contains(from) {
                fixed = fixed.replace(from, to);
                changed = true;
            }
        }

        if !changed {
            return None;
        }
        Some(fixed)
    }
}

// ── 27. CryptoHardcodedSaltTemplate (CWE-760) ────────────────────────────────

/// Replaces hardcoded bcrypt salt literals with `bcrypt.gensalt(12)`.
///
/// A hardcoded salt defeats the purpose of salting — every password gets the
/// same salt, enabling precomputed rainbow table attacks.
///
/// Handles Python: `bcrypt.hashpw(password, b"$2b$12$hardcodedsalt...")`
pub struct CryptoHardcodedSaltTemplate;

impl PatchTemplate for CryptoHardcodedSaltTemplate {
    fn name(&self) -> &'static str {
        "CryptoHardcodedSalt"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }

        if !line.contains("bcrypt.hashpw(") {
            return None;
        }

        // Find the second argument (the salt) — look for a bytes literal b"..." or b'...'
        let fn_start = line.find("bcrypt.hashpw(")? + "bcrypt.hashpw(".len();
        let after_fn = &line[fn_start..];

        // Skip first argument
        let comma = find_top_level_comma(after_fn)?;
        let after_comma = after_fn[comma + 1..].trim_start();

        // Check if the second arg is a bytes literal (b'...' or b"...")
        if !after_comma.starts_with("b'") && !after_comma.starts_with("b\"") {
            return None;
        }

        let quote = after_comma.chars().nth(1)?;
        let inner = &after_comma[2..];
        let close = inner.find(quote)?;
        let literal_end = close + 3; // b + quote + content + quote

        let before = &line[..fn_start + comma + 1];
        let rest = &after_comma[literal_end..];

        Some(format!("{before} bcrypt.gensalt(12){rest}"))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn js() -> Language {
        Language::JavaScript
    }
    fn ts() -> Language {
        Language::TypeScript
    }
    fn py() -> Language {
        Language::Python
    }
    fn go() -> Language {
        Language::Go
    }

    // ── Registry ──────────────────────────────────────────────────────────────

    #[test]
    fn test_registry_lookup_by_rule_id() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("js-innerhtml", None).is_some());
        assert!(reg.lookup("js-crypto-math-random", None).is_some());
        assert!(reg.lookup("nonexistent-rule", None).is_none());
    }

    #[test]
    fn test_registry_lookup_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown-rule", Some("CWE-338")).is_some());
        assert!(reg.lookup("unknown-rule", Some("cwe-328")).is_some());
        assert!(reg.lookup("unknown-rule", Some("CWE-999")).is_none());
    }

    #[test]
    fn test_registry_rule_takes_priority_over_cwe() {
        let reg = TemplateRegistry::default();
        // js-innerhtml is registered by rule; CWE-79 is not registered by CWE
        let t = reg.lookup("js-innerhtml", Some("CWE-79")).unwrap();
        assert_eq!(t.name(), "DomInnerHTML");
    }

    // ── CryptoWeakHashTemplate ────────────────────────────────────────────────

    #[test]
    fn test_weak_hash_md5_python() {
        let t = CryptoWeakHashTemplate;
        let line = "    h = hashlib.md5(data)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("hashlib.sha256("));
        assert!(!result.contains("md5"));
    }

    #[test]
    fn test_weak_hash_sha1_java() {
        let t = CryptoWeakHashTemplate;
        let line = "    MessageDigest md = MessageDigest.getInstance(\"SHA-1\");";
        let result = t.generate_patch(line, Language::Java).unwrap();
        assert!(result.contains("\"SHA-256\""));
    }

    #[test]
    fn test_weak_hash_no_match() {
        let t = CryptoWeakHashTemplate;
        assert!(t
            .generate_patch("    let x = sha256(data);", js())
            .is_none());
    }

    // ── CryptoMathRandomTemplate ──────────────────────────────────────────────

    #[test]
    fn test_math_random_replaced() {
        let t = CryptoMathRandomTemplate;
        let line = "    const token = Math.random().toString(36);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("crypto.getRandomValues"));
        assert!(!result.contains("Math.random()"));
    }

    #[test]
    fn test_math_random_wrong_lang() {
        let t = CryptoMathRandomTemplate;
        assert!(t.generate_patch("x = Math.random()", py()).is_none());
    }

    #[test]
    fn test_math_random_no_match() {
        let t = CryptoMathRandomTemplate;
        assert!(t.generate_patch("    const x = 42;", js()).is_none());
    }

    // ── DomInnerHtmlTemplate ──────────────────────────────────────────────────

    #[test]
    fn test_innerhtml_replaced() {
        let t = DomInnerHtmlTemplate;
        let line = "    document.getElementById(\"output\").innerHTML = userInput;";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains(".textContent ="));
        assert!(!result.contains(".innerHTML"));
    }

    #[test]
    fn test_innerhtml_wrong_lang() {
        let t = DomInnerHtmlTemplate;
        assert!(t.generate_patch("el.innerHTML = x", py()).is_none());
    }

    // ── DomDocumentWriteTemplate ──────────────────────────────────────────────

    #[test]
    fn test_document_write_replaced() {
        let t = DomDocumentWriteTemplate;
        let line = "    document.write(userInput);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("document.body.appendChild"));
        assert!(result.contains("document.createTextNode"));
        assert!(result.contains("userInput"));
        assert!(!result.contains("document.write("));
    }

    #[test]
    fn test_document_write_preserves_semicolon() {
        let t = DomDocumentWriteTemplate;
        let line = "    document.write(x);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.ends_with(';'));
    }

    #[test]
    fn test_document_write_no_semicolon() {
        let t = DomDocumentWriteTemplate;
        let line = "    document.write(x)";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(!result.ends_with(';'));
    }

    // ── WebCorsWildcardTemplate ───────────────────────────────────────────────

    #[test]
    fn test_cors_wildcard_node() {
        let t = WebCorsWildcardTemplate;
        let line = "    res.setHeader(\"Access-Control-Allow-Origin\", \"*\");";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("process.env.ALLOWED_ORIGIN"));
        assert!(!result.contains(", \"*\""));
    }

    #[test]
    fn test_cors_no_match() {
        let t = WebCorsWildcardTemplate;
        assert!(t
            .generate_patch("    res.setHeader(\"Content-Type\", \"*\");", js())
            .is_none());
    }

    // ── PyUnsafeDeserializeTemplate ───────────────────────────────────────────

    #[test]
    fn test_yaml_load_replaced() {
        let t = PyUnsafeDeserializeTemplate;
        let line = "    data = yaml.load(stream)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("yaml.safe_load("));
        assert!(!result.contains("yaml.load("));
    }

    #[test]
    fn test_pickle_loads_replaced() {
        let t = PyUnsafeDeserializeTemplate;
        let line = "    obj = pickle.loads(data)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("json.loads("));
        assert!(!result.contains("pickle.loads("));
    }

    #[test]
    fn test_py_deserialize_wrong_lang() {
        let t = PyUnsafeDeserializeTemplate;
        assert!(t.generate_patch("yaml.load(x)", js()).is_none());
    }

    // ── GoDeferCloseTemplate ──────────────────────────────────────────────────

    #[test]
    fn test_go_defer_close_os_open() {
        let t = GoDeferCloseTemplate;
        let line = "\tf, err := os.Open(filename)";
        let result = t.generate_patch(line, go()).unwrap();
        assert!(result.contains("defer f.Close()"));
        // Original line must be preserved
        assert!(result.contains("os.Open(filename)"));
    }

    #[test]
    fn test_go_defer_close_db_query() {
        let t = GoDeferCloseTemplate;
        let line = "\trows, err := db.Query(query, args...)";
        let result = t.generate_patch(line, go()).unwrap();
        assert!(result.contains("defer rows.Close()"));
    }

    #[test]
    fn test_go_defer_close_wrong_lang() {
        let t = GoDeferCloseTemplate;
        assert!(t.generate_patch("\tf, err := os.Open(x)", js()).is_none());
    }

    #[test]
    fn test_go_defer_close_no_match() {
        let t = GoDeferCloseTemplate;
        assert!(t.generate_patch("\tx := someOtherCall()", go()).is_none());
    }

    // ── extract_call_arg ──────────────────────────────────────────────────────

    #[test]
    fn test_extract_call_arg_simple() {
        assert_eq!(
            extract_call_arg("document.write(userInput)", "document.write"),
            Some("userInput")
        );
    }

    #[test]
    fn test_extract_call_arg_nested() {
        assert_eq!(
            extract_call_arg("document.write(foo(bar))", "document.write"),
            Some("foo(bar)")
        );
    }

    #[test]
    fn test_extract_call_arg_with_semicolon() {
        assert_eq!(
            extract_call_arg("    document.write(x);", "document.write"),
            Some("x")
        );
    }

    // ── CryptoEcbModeTemplate ─────────────────────────────────────────────────

    #[test]
    fn test_ecb_node_cipher() {
        let t = CryptoEcbModeTemplate;
        let line = "    const cipher = crypto.createCipheriv('aes-128-ecb', key, iv);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("aes-256-gcm"));
        assert!(!result.contains("ecb"));
    }

    #[test]
    fn test_ecb_java_jce() {
        let t = CryptoEcbModeTemplate;
        let line = "    Cipher c = Cipher.getInstance(\"AES/ECB/PKCS5Padding\");";
        let result = t.generate_patch(line, Language::Java).unwrap();
        assert!(result.contains("AES/GCM/NoPadding"));
        assert!(!result.contains("ECB"));
    }

    #[test]
    fn test_ecb_python_pycryptodome() {
        let t = CryptoEcbModeTemplate;
        let line = "    cipher = AES.new(key, AES.MODE_ECB)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("AES.MODE_GCM"));
    }

    #[test]
    fn test_ecb_no_match() {
        let t = CryptoEcbModeTemplate;
        assert!(t
            .generate_patch("    const x = 'aes-256-gcm';", js())
            .is_none());
    }

    // ── CryptoHardcodedJwtTemplate ────────────────────────────────────────────

    #[test]
    fn test_jwt_hardcoded_js() {
        let t = CryptoHardcodedJwtTemplate;
        let line = "    const token = jwt.sign(payload, \"mysecret\");";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("process.env.JWT_SECRET"));
        assert!(!result.contains("\"mysecret\""));
    }

    #[test]
    fn test_jwt_hardcoded_single_quote() {
        let t = CryptoHardcodedJwtTemplate;
        let line = "    const token = jwt.sign(payload, 'mysecret', { expiresIn: '1h' });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("process.env.JWT_SECRET"));
    }

    #[test]
    fn test_jwt_hardcoded_python() {
        let t = CryptoHardcodedJwtTemplate;
        let line = "    token = jwt.encode(payload, \"secret\", algorithm=\"HS256\")";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("os.environ.get(\"JWT_SECRET\")"));
        assert!(!result.contains("\"secret\""));
    }

    #[test]
    fn test_jwt_no_match() {
        let t = CryptoHardcodedJwtTemplate;
        assert!(t
            .generate_patch("    const x = jwt.verify(token, pubKey);", js())
            .is_none());
    }

    // ── AuthMissingSaltTemplate ───────────────────────────────────────────────

    #[test]
    fn test_bcrypt_missing_rounds() {
        let t = AuthMissingSaltTemplate;
        let line = "    const hash = await bcrypt.hash(password);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("bcrypt.hash(password, 12)"));
    }

    #[test]
    fn test_bcrypt_sync_missing_rounds() {
        let t = AuthMissingSaltTemplate;
        let line = "    const hash = bcrypt.hashSync(password);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("bcrypt.hashSync(password, 12)"));
    }

    #[test]
    fn test_bcrypt_already_has_rounds() {
        let t = AuthMissingSaltTemplate;
        // Already has salt rounds — should not modify
        assert!(t
            .generate_patch("    bcrypt.hash(password, 10);", js())
            .is_none());
    }

    #[test]
    fn test_bcrypt_wrong_lang() {
        let t = AuthMissingSaltTemplate;
        assert!(t.generate_patch("bcrypt.hash(password)", py()).is_none());
    }

    // ── DomPostMessageWildcardTemplate ────────────────────────────────────────

    #[test]
    fn test_postmessage_wildcard_single_quote() {
        let t = DomPostMessageWildcardTemplate;
        let line = "    window.postMessage(data, '*');";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("process.env.EXPECTED_ORIGIN"));
        assert!(!result.contains("'*'"));
    }

    #[test]
    fn test_postmessage_wildcard_double_quote() {
        let t = DomPostMessageWildcardTemplate;
        let line = "    iframe.contentWindow.postMessage(msg, \"*\");";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("process.env.EXPECTED_ORIGIN"));
    }

    #[test]
    fn test_postmessage_no_wildcard() {
        let t = DomPostMessageWildcardTemplate;
        // Already has a specific origin
        assert!(t
            .generate_patch("    window.postMessage(data, 'https://example.com');", js())
            .is_none());
    }

    // ── WebCookieInsecureTemplate ─────────────────────────────────────────────

    #[test]
    fn test_cookie_missing_flags() {
        let t = WebCookieInsecureTemplate;
        let line = "    res.cookie('session', token);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("httpOnly: true"));
        assert!(result.contains("secure: true"));
        assert!(result.contains("sameSite: 'strict'"));
    }

    #[test]
    fn test_cookie_already_secure() {
        let t = WebCookieInsecureTemplate;
        let line = "    res.cookie('session', token, { httpOnly: true });";
        assert!(t.generate_patch(line, js()).is_none());
    }

    #[test]
    fn test_cookie_wrong_lang() {
        let t = WebCookieInsecureTemplate;
        assert!(t.generate_patch("    res.cookie('s', t);", py()).is_none());
    }

    // ── WebExpressXPoweredByTemplate ──────────────────────────────────────────

    #[test]
    fn test_express_xpoweredby_const() {
        let t = WebExpressXPoweredByTemplate;
        let line = "const app = express();";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("app.disable('x-powered-by')"));
        // Original line must be preserved
        assert!(result.contains("express()"));
    }

    #[test]
    fn test_express_xpoweredby_custom_var() {
        let t = WebExpressXPoweredByTemplate;
        let line = "  const server = express();";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("server.disable('x-powered-by')"));
    }

    #[test]
    fn test_express_no_match() {
        let t = WebExpressXPoweredByTemplate;
        assert!(t
            .generate_patch("    const router = express.Router();", js())
            .is_none());
    }

    // ── PyRequestsVerifyFalseTemplate ─────────────────────────────────────────

    #[test]
    fn test_requests_verify_false_get() {
        let t = PyRequestsVerifyFalseTemplate;
        let line = "    resp = requests.get(url, verify=False)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(!result.contains("verify=False"));
        assert!(result.contains("requests.get(url)"));
    }

    #[test]
    fn test_requests_verify_false_with_other_kwargs() {
        let t = PyRequestsVerifyFalseTemplate;
        let line = "    resp = requests.post(url, data=payload, verify=False)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(!result.contains("verify=False"));
        assert!(result.contains("data=payload"));
    }

    #[test]
    fn test_requests_verify_true_untouched() {
        let t = PyRequestsVerifyFalseTemplate;
        // verify=True is the default — no match
        assert!(t
            .generate_patch("    resp = requests.get(url, verify=True)", py())
            .is_none());
    }

    #[test]
    fn test_requests_verify_wrong_lang() {
        let t = PyRequestsVerifyFalseTemplate;
        assert!(t
            .generate_patch("requests.get(url, verify=False)", js())
            .is_none());
    }
}

#[cfg(test)]
mod injection_tests {
    use super::*;

    fn js() -> Language {
        Language::JavaScript
    }
    fn ts() -> Language {
        Language::TypeScript
    }
    fn py() -> Language {
        Language::Python
    }
    fn go() -> Language {
        Language::Go
    }

    // ── InjectEvalTemplate ────────────────────────────────────────────────────

    #[test]
    fn test_eval_js_replaced() {
        let t = InjectEvalTemplate;
        let line = "    eval(userInput);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("JSON.parse("));
        assert!(!result.contains("eval("));
    }

    #[test]
    fn test_eval_ts_replaced() {
        let t = InjectEvalTemplate;
        let result = t.generate_patch("    eval(data);", ts()).unwrap();
        assert!(result.contains("JSON.parse("));
    }

    #[test]
    fn test_eval_python_replaced() {
        let t = InjectEvalTemplate;
        let line = "    result = eval(user_input)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("ast.literal_eval("));
        // The bare `eval(` call must be gone — only ast.literal_eval( remains
        assert!(!result.contains(" eval("), "bare eval( should be replaced");
    }

    #[test]
    fn test_eval_wrong_lang() {
        let t = InjectEvalTemplate;
        assert!(t.generate_patch("eval(x)", go()).is_none());
    }

    #[test]
    fn test_eval_no_match() {
        let t = InjectEvalTemplate;
        assert!(t.generate_patch("    const x = 42;", js()).is_none());
    }

    // ── InjectOsExecTemplate ──────────────────────────────────────────────────

    #[test]
    fn test_exec_replaced() {
        let t = InjectOsExecTemplate;
        let line = "    exec(userCommand, callback);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("execFile("));
        assert!(!result.contains("exec("));
    }

    #[test]
    fn test_exec_dot_exec_not_replaced() {
        let t = InjectOsExecTemplate;
        // regex.exec() must NOT be replaced
        assert!(t
            .generate_patch("    const m = pattern.exec(input);", js())
            .is_none());
    }

    #[test]
    fn test_exec_already_execfile_not_replaced() {
        let t = InjectOsExecTemplate;
        assert!(t
            .generate_patch("    execFile(cmd, args, cb);", js())
            .is_none());
    }

    #[test]
    fn test_exec_wrong_lang() {
        let t = InjectOsExecTemplate;
        assert!(t.generate_patch("exec(cmd)", py()).is_none());
    }

    // ── InjectNoSqlTypeCastTemplate ───────────────────────────────────────────

    #[test]
    fn test_nosql_req_query_wrapped() {
        let t = InjectNoSqlTypeCastTemplate;
        let line = "    const user = await User.find({ _id: req.query.id });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("String(req.query.id)"));
        assert!(!result.contains("{ _id: req.query.id }"));
    }

    #[test]
    fn test_nosql_req_body_wrapped() {
        let t = InjectNoSqlTypeCastTemplate;
        let line = "    const doc = await Item.findOne({ name: req.body.name });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("String(req.body.name)"));
    }

    #[test]
    fn test_nosql_already_cast_not_double_wrapped() {
        let t = InjectNoSqlTypeCastTemplate;
        let line = "    User.find({ _id: String(req.query.id) });";
        // Already wrapped — should return None
        assert!(t.generate_patch(line, js()).is_none());
    }

    #[test]
    fn test_nosql_not_a_query() {
        let t = InjectNoSqlTypeCastTemplate;
        assert!(t
            .generate_patch("    const x = req.query.id;", js())
            .is_none());
    }

    #[test]
    fn test_nosql_wrong_lang() {
        let t = InjectNoSqlTypeCastTemplate;
        assert!(t
            .generate_patch("User.find({ _id: req.query.id })", py())
            .is_none());
    }

    // ── ReactDangerouslySetInnerHtmlTemplate ──────────────────────────────────

    #[test]
    fn test_react_dangerous_wrapped() {
        let t = ReactDangerouslySetInnerHtmlTemplate;
        let line = "    <div dangerouslySetInnerHTML={{ __html: userContent }} />";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("DOMPurify.sanitize(userContent)"));
        assert!(!result.contains("__html: userContent }"));
    }

    #[test]
    fn test_react_dangerous_already_sanitized() {
        let t = ReactDangerouslySetInnerHtmlTemplate;
        let line = "    <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(x) }} />";
        assert!(t.generate_patch(line, js()).is_none());
    }

    #[test]
    fn test_react_dangerous_no_match() {
        let t = ReactDangerouslySetInnerHtmlTemplate;
        assert!(t
            .generate_patch("    <div className=\"foo\" />", js())
            .is_none());
    }

    #[test]
    fn test_react_dangerous_wrong_lang() {
        let t = ReactDangerouslySetInnerHtmlTemplate;
        assert!(t
            .generate_patch("dangerouslySetInnerHTML={{ __html: x }}", py())
            .is_none());
    }

    // ── IacDockerRootUserTemplate ─────────────────────────────────────────────

    #[test]
    fn test_docker_cmd_gets_user_injected() {
        let t = IacDockerRootUserTemplate;
        let line = "CMD [\"node\", \"server.js\"]";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("USER nonroot"));
        // USER must come BEFORE CMD
        let user_pos = result.find("USER nonroot").unwrap();
        let cmd_pos = result.find("CMD").unwrap();
        assert!(user_pos < cmd_pos, "USER must precede CMD");
    }

    #[test]
    fn test_docker_entrypoint_gets_user_injected() {
        let t = IacDockerRootUserTemplate;
        let line = "ENTRYPOINT [\"/app/start.sh\"]";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("USER nonroot"));
        assert!(result.contains("ENTRYPOINT"));
    }

    #[test]
    fn test_docker_run_not_matched() {
        let t = IacDockerRootUserTemplate;
        assert!(t.generate_patch("RUN npm install", js()).is_none());
    }

    #[test]
    fn test_docker_from_not_matched() {
        let t = IacDockerRootUserTemplate;
        assert!(t.generate_patch("FROM node:18-alpine", js()).is_none());
    }

    #[test]
    fn test_docker_preserves_indentation() {
        let t = IacDockerRootUserTemplate;
        let line = "  CMD [\"start\"]";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.starts_with("  USER nonroot"));
    }

    // ── Registry integration ──────────────────────────────────────────────────

    #[test]
    fn test_registry_eval_injection_registered() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("js-eval-injection", None).is_some());
        assert_eq!(
            reg.lookup("js-eval-injection", None).unwrap().name(),
            "InjectEval"
        );
    }

    #[test]
    fn test_registry_nosql_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-943")).is_some());
    }

    #[test]
    fn test_registry_docker_root_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-269")).is_some());
    }

    #[test]
    fn test_registry_exec_injection_registered() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("js-child-process-exec", None).is_some());
    }

    #[test]
    fn test_registry_react_xss_registered() {
        let reg = TemplateRegistry::default();
        assert!(reg
            .lookup("react-dangerously-set-innerhtml", None)
            .is_some());
    }
}

// ── Sprint 1 tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod sprint1_tests {
    use super::*;

    fn js() -> Language {
        Language::JavaScript
    }
    fn ts() -> Language {
        Language::TypeScript
    }
    fn py() -> Language {
        Language::Python
    }
    fn go() -> Language {
        Language::Go
    }

    // ── CryptoPbkdf2LowIterationsTemplate ─────────────────────────────────────

    #[test]
    fn test_pbkdf2_low_iterations_node() {
        let t = CryptoPbkdf2LowIterationsTemplate;
        let line = "    const key = crypto.pbkdf2Sync(password, salt, 1000, 32, 'sha256');";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("310000"), "should replace 1000 with 310000");
        assert!(!result.contains(", 1000,"), "original count should be gone");
    }

    #[test]
    fn test_pbkdf2_low_iterations_python() {
        let t = CryptoPbkdf2LowIterationsTemplate;
        let line = "    key = hashlib.pbkdf2_hmac('sha256', pwd, salt, 10000)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("310000"));
        assert!(
            !result.contains("10000,") && !result.contains("10000)") || result.contains("310000")
        );
    }

    #[test]
    fn test_pbkdf2_already_safe() {
        let t = CryptoPbkdf2LowIterationsTemplate;
        // 310000 is already safe — should not modify
        let line = "    crypto.pbkdf2Sync(pwd, salt, 310000, 32, 'sha256');";
        assert!(t.generate_patch(line, js()).is_none());
    }

    #[test]
    fn test_pbkdf2_no_match() {
        let t = CryptoPbkdf2LowIterationsTemplate;
        assert!(t
            .generate_patch("    const x = sha256(data);", js())
            .is_none());
    }

    #[test]
    fn test_pbkdf2_wrong_lang() {
        let t = CryptoPbkdf2LowIterationsTemplate;
        assert!(t.generate_patch("pbkdf2(pwd, salt, 1000)", go()).is_none());
    }

    // ── CryptoRsaKeyTooShortTemplate ──────────────────────────────────────────

    #[test]
    fn test_rsa_key_1024_replaced() {
        let t = CryptoRsaKeyTooShortTemplate;
        let line = "    crypto.generateKeyPair('rsa', { modulusLength: 1024 }, cb);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("4096"));
        assert!(!result.contains("1024"));
    }

    #[test]
    fn test_rsa_key_512_replaced() {
        let t = CryptoRsaKeyTooShortTemplate;
        let line = "    key_size=512";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("4096"));
    }

    #[test]
    fn test_rsa_key_2048_not_replaced() {
        let t = CryptoRsaKeyTooShortTemplate;
        // 2048 is the minimum — should not be replaced
        let line = "    crypto.generateKeyPair('rsa', { modulusLength: 2048 }, cb);";
        assert!(t.generate_patch(line, js()).is_none());
    }

    #[test]
    fn test_rsa_key_4096_not_replaced() {
        let t = CryptoRsaKeyTooShortTemplate;
        let line = "    modulusLength: 4096";
        assert!(t.generate_patch(line, js()).is_none());
    }

    #[test]
    fn test_rsa_key_wrong_lang() {
        let t = CryptoRsaKeyTooShortTemplate;
        assert!(t.generate_patch("modulusLength: 1024", go()).is_none());
    }

    // ── CryptoHardcodedAesKeyTemplate ─────────────────────────────────────────

    #[test]
    fn test_aes_hardcoded_key_node() {
        let t = CryptoHardcodedAesKeyTemplate;
        let line =
            "    const cipher = crypto.createCipheriv('aes-256-gcm', 'mysecretkey12345', iv);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("process.env.AES_KEY"));
        assert!(!result.contains("'mysecretkey12345'"));
    }

    #[test]
    fn test_aes_hardcoded_key_python_bytes() {
        let t = CryptoHardcodedAesKeyTemplate;
        let line = "    cipher = AES.new(b'hardcodedkey1234', AES.MODE_GCM)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("os.environ.get(\"AES_KEY\")"));
        assert!(!result.contains("b'hardcodedkey1234'"));
    }

    #[test]
    fn test_aes_no_match_no_aes() {
        let t = CryptoHardcodedAesKeyTemplate;
        assert!(t
            .generate_patch("    const x = encrypt(key, data);", js())
            .is_none());
    }

    #[test]
    fn test_aes_wrong_lang() {
        let t = CryptoHardcodedAesKeyTemplate;
        assert!(t
            .generate_patch("AES.new(b'key', AES.MODE_GCM)", go())
            .is_none());
    }

    // ── CryptoInsecureRandomSeedTemplate ──────────────────────────────────────

    #[test]
    fn test_random_seed_zero() {
        let t = CryptoInsecureRandomSeedTemplate;
        let line = "    random.seed(0)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("# SICARIO FIX"));
        assert!(result.contains("random.seed(0)"));
        assert!(!result.starts_with("    random.seed(0)"));
    }

    #[test]
    fn test_random_seed_integer() {
        let t = CryptoInsecureRandomSeedTemplate;
        let line = "random.seed(42)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("# SICARIO FIX"));
    }

    #[test]
    fn test_random_seed_variable_not_replaced() {
        let t = CryptoInsecureRandomSeedTemplate;
        // Variable seed — not deterministic, don't touch
        assert!(t.generate_patch("    random.seed(entropy)", py()).is_none());
    }

    #[test]
    fn test_random_seed_wrong_lang() {
        let t = CryptoInsecureRandomSeedTemplate;
        assert!(t.generate_patch("random.seed(0)", js()).is_none());
    }

    #[test]
    fn test_random_seed_preserves_indentation() {
        let t = CryptoInsecureRandomSeedTemplate;
        let line = "        random.seed(1)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.starts_with("        #"));
    }

    // ── CryptoMd5PasswordHashTemplate ─────────────────────────────────────────

    #[test]
    fn test_md5_password_js() {
        let t = CryptoMd5PasswordHashTemplate;
        let line = "    const hash = md5(password);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("bcrypt.hash(password, 12)"));
        assert!(!result.contains("md5("));
    }

    #[test]
    fn test_md5_password_python() {
        let t = CryptoMd5PasswordHashTemplate;
        let line = "    hashed = hashlib.md5(password.encode())";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("bcrypt.hashpw("));
        assert!(result.contains("bcrypt.gensalt(12)"));
    }

    #[test]
    fn test_md5_password_go() {
        let t = CryptoMd5PasswordHashTemplate;
        let line = "\thash := md5.Sum([]byte(password))";
        let result = t.generate_patch(line, go()).unwrap();
        assert!(result.contains("bcrypt.GenerateFromPassword("));
    }

    #[test]
    fn test_md5_no_match() {
        let t = CryptoMd5PasswordHashTemplate;
        assert!(t
            .generate_patch("    const x = sha256(data);", js())
            .is_none());
    }

    // ── CryptoJwtNoneAlgorithmTemplate ────────────────────────────────────────

    #[test]
    fn test_jwt_none_algorithm_js_single_quote() {
        let t = CryptoJwtNoneAlgorithmTemplate;
        let line = "    jwt.verify(token, secret, { algorithms: ['none'] });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("'HS256'"));
        assert!(!result.contains("'none'"));
    }

    #[test]
    fn test_jwt_none_algorithm_js_double_quote() {
        let t = CryptoJwtNoneAlgorithmTemplate;
        let line = "    jwt.verify(token, secret, { algorithms: [\"none\"] });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("\"HS256\""));
    }

    #[test]
    fn test_jwt_none_algorithm_python() {
        let t = CryptoJwtNoneAlgorithmTemplate;
        let line = "    payload = jwt.decode(token, options={'verify_signature': False}, algorithms=['none'])";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("'HS256'"));
    }

    #[test]
    fn test_jwt_none_no_match() {
        let t = CryptoJwtNoneAlgorithmTemplate;
        // 'none' not in a JWT context
        assert!(t.generate_patch("    const x = 'none';", js()).is_none());
    }

    #[test]
    fn test_jwt_none_wrong_lang() {
        let t = CryptoJwtNoneAlgorithmTemplate;
        assert!(t.generate_patch("algorithms: ['none']", go()).is_none());
    }

    // ── CryptoJwtWeakAlgorithmTemplate ────────────────────────────────────────

    #[test]
    fn test_jwt_weak_hs1_replaced() {
        let t = CryptoJwtWeakAlgorithmTemplate;
        let line = "    const token = jwt.sign(payload, secret, { algorithm: 'HS1' });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("'HS256'"));
        assert!(!result.contains("'HS1'"));
    }

    #[test]
    fn test_jwt_weak_rs1_replaced() {
        let t = CryptoJwtWeakAlgorithmTemplate;
        let line = "    jwt.sign(payload, key, { algorithm: 'RS1' });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("'RS256'"));
    }

    #[test]
    fn test_jwt_weak_double_quote() {
        let t = CryptoJwtWeakAlgorithmTemplate;
        let line = "    jwt.sign(payload, secret, { algorithm: \"HS1\" });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("\"HS256\""));
    }

    #[test]
    fn test_jwt_weak_hs256_not_replaced() {
        let t = CryptoJwtWeakAlgorithmTemplate;
        assert!(t
            .generate_patch(
                "    jwt.sign(payload, secret, { algorithm: 'HS256' });",
                js()
            )
            .is_none());
    }

    #[test]
    fn test_jwt_weak_wrong_lang() {
        let t = CryptoJwtWeakAlgorithmTemplate;
        assert!(t.generate_patch("algorithm: 'HS1'", go()).is_none());
    }

    // ── CryptoHardcodedSaltTemplate ───────────────────────────────────────────

    #[test]
    fn test_hardcoded_salt_bytes_single_quote() {
        let t = CryptoHardcodedSaltTemplate;
        let line = "    hashed = bcrypt.hashpw(password, b'$2b$12$hardcodedsaltvalue')";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("bcrypt.gensalt(12)"));
        assert!(!result.contains("b'$2b$12$hardcodedsaltvalue'"));
    }

    #[test]
    fn test_hardcoded_salt_bytes_double_quote() {
        let t = CryptoHardcodedSaltTemplate;
        let line = "    hashed = bcrypt.hashpw(pwd, b\"$2b$12$fixedsalt\")";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("bcrypt.gensalt(12)"));
    }

    #[test]
    fn test_hardcoded_salt_gensalt_not_replaced() {
        let t = CryptoHardcodedSaltTemplate;
        // Already using gensalt — no match
        assert!(t
            .generate_patch("    bcrypt.hashpw(pwd, bcrypt.gensalt(12))", py())
            .is_none());
    }

    #[test]
    fn test_hardcoded_salt_wrong_lang() {
        let t = CryptoHardcodedSaltTemplate;
        assert!(t
            .generate_patch("bcrypt.hashpw(pwd, b'salt')", js())
            .is_none());
    }

    // ── Registry integration ──────────────────────────────────────────────────

    #[test]
    fn test_registry_pbkdf2_by_cwe() {
        let reg = TemplateRegistry::default();
        let t = reg.lookup("unknown", Some("CWE-916"));
        assert!(t.is_some());
        // CWE-916 maps to PBKDF2 (first registered)
        assert_eq!(t.unwrap().name(), "CryptoPbkdf2LowIterations");
    }

    #[test]
    fn test_registry_rsa_by_rule_id() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("js-rsa-key-too-short", None).is_some());
        assert_eq!(
            reg.lookup("js-rsa-key-too-short", None).unwrap().name(),
            "CryptoRsaKeyTooShort"
        );
    }

    #[test]
    fn test_registry_jwt_none_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-347")).is_some());
    }

    #[test]
    fn test_registry_hardcoded_salt_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-760")).is_some());
    }

    #[test]
    fn test_registry_insecure_seed_by_rule() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("py-random-seed-fixed", None).is_some());
    }
}

// ── Sprint 2: Auth & Session + Injection (12 templates) ──────────────────────

// ── Domain 2: Authentication & Session Management ────────────────────────────

// ── 28. AuthSessionNoHttpOnlyTemplate (CWE-1004) ─────────────────────────────

/// Injects `httpOnly: true` into express-session / cookie-session cookie options.
///
/// `app.use(session({ cookie: { secure: true } }))` → adds `httpOnly: true`
/// Only fires when `httpOnly` is absent from the cookie options object.
pub struct AuthSessionNoHttpOnlyTemplate;

impl PatchTemplate for AuthSessionNoHttpOnlyTemplate {
    fn name(&self) -> &'static str { "AuthSessionNoHttpOnly" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        // Must be a session/cookie config line
        let lower = line.to_lowercase();
        if !lower.contains("session") && !lower.contains("cookie") { return None; }
        // Already has httpOnly — leave it
        if lower.contains("httponly") { return None; }
        // Must contain a cookie options object opening
        if !line.contains("cookie:") && !line.contains("cookie :") { return None; }
        // Inject httpOnly: true into the cookie object
        let fixed = inject_into_object(line, "cookie:", "httpOnly: true")?;
        if fixed == line { return None; }
        Some(fixed)
    }
}

// ── 29. AuthSessionNoSecureFlagTemplate (CWE-614) ────────────────────────────

/// Injects `secure: process.env.NODE_ENV === 'production'` into session cookie options.
pub struct AuthSessionNoSecureFlagTemplate;

impl PatchTemplate for AuthSessionNoSecureFlagTemplate {
    fn name(&self) -> &'static str { "AuthSessionNoSecureFlag" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        let lower = line.to_lowercase();
        if !lower.contains("session") && !lower.contains("cookie") { return None; }
        if lower.contains("secure:") { return None; }
        if !line.contains("cookie:") && !line.contains("cookie :") { return None; }
        let fixed = inject_into_object(line, "cookie:", "secure: process.env.NODE_ENV === 'production'")?;
        if fixed == line { return None; }
        Some(fixed)
    }
}

// ── 30. AuthSessionFixationTemplate (CWE-384) ────────────────────────────────

/// Prepends `req.session.regenerate(() => {` before a session assignment.
///
/// `req.session.userId = user.id;`
/// → `req.session.regenerate(() => {\n    req.session.userId = user.id;\n});`
pub struct AuthSessionFixationTemplate;

impl PatchTemplate for AuthSessionFixationTemplate {
    fn name(&self) -> &'static str { "AuthSessionFixation" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        // Must be a req.session.X = ... assignment (not .regenerate itself)
        if !line.contains("req.session.") { return None; }
        if line.contains(".regenerate") || line.contains(".destroy") || line.contains(".save") {
            return None;
        }
        // Must be an assignment
        let trimmed = line.trim();
        if !trimmed.contains(" = ") && !trimmed.contains(" =\t") { return None; }

        let indent = get_indent(line);
        let semicolon = if line.trim_end().ends_with(';') { ";" } else { "" };
        Some(format!(
            "{indent}req.session.regenerate(() => {{\n{line}\n{indent}}}){}",
            semicolon
        ))
    }
}

// ── 31. AuthPasswordInLogTemplate (CWE-532) ──────────────────────────────────

/// Replaces log calls that expose sensitive values with a comment.
///
/// Fires when the log argument contains `password`, `passwd`, `secret`, or `token`.
pub struct AuthPasswordInLogTemplate;

impl PatchTemplate for AuthPasswordInLogTemplate {
    fn name(&self) -> &'static str { "AuthPasswordInLog" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        // Must be a log call
        let is_log = lower.contains("console.log") || lower.contains("console.error")
            || lower.contains("console.warn") || lower.contains("console.info")
            || lower.contains("logger.info") || lower.contains("logger.debug")
            || lower.contains("logger.warn") || lower.contains("logger.error")
            || lower.contains("print(") || lower.contains("logging.");
        if !is_log { return None; }
        // Must reference a sensitive name
        let is_sensitive = lower.contains("password") || lower.contains("passwd")
            || lower.contains("secret") || lower.contains("token")
            || lower.contains("api_key") || lower.contains("apikey");
        if !is_sensitive { return None; }

        let indent = get_indent(line);
        let comment = match lang {
            Language::Python => format!("{indent}# SICARIO FIX: removed logging of sensitive value"),
            _ => format!("{indent}// SICARIO FIX: removed logging of sensitive value"),
        };
        Some(comment)
    }
}

// ── 32. AuthBasicAuthOverHttpTemplate (CWE-523) ───────────────────────────────

/// Replaces `http://` with `https://` when used with Basic auth headers.
pub struct AuthBasicAuthOverHttpTemplate;

impl PatchTemplate for AuthBasicAuthOverHttpTemplate {
    fn name(&self) -> &'static str { "AuthBasicAuthOverHttp" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        let lower = line.to_lowercase();
        if !lower.contains("basic ") && !lower.contains("authorization") { return None; }
        if !line.contains("http://") { return None; }
        Some(line.replace("http://", "https://"))
    }
}

// ── 33. AuthJwtNoExpiryTemplate (CWE-613) ────────────────────────────────────

/// Injects `{ expiresIn: '1h' }` into `jwt.sign()` calls missing an expiry.
///
/// JS: `jwt.sign(payload, secret)` → `jwt.sign(payload, secret, { expiresIn: '1h' })`
/// Python: adds `exp` field comment (multi-line fix exceeds trimmer budget, so
/// we inject a comment on the same line instead).
pub struct AuthJwtNoExpiryTemplate;

impl PatchTemplate for AuthJwtNoExpiryTemplate {
    fn name(&self) -> &'static str { "AuthJwtNoExpiry" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        if !lower.contains("jwt.sign") && !lower.contains("jwt.encode") { return None; }
        // Already has expiry
        if lower.contains("expiresin") || lower.contains("expires_in")
            || lower.contains("exp:") || lower.contains("expiry") { return None; }

        match lang {
            Language::JavaScript | Language::TypeScript => {
                // jwt.sign(payload, secret) → jwt.sign(payload, secret, { expiresIn: '1h' })
                if let Some(pos) = line.find("jwt.sign(") {
                    let after = &line[pos + "jwt.sign(".len()..];
                    if let Some(close) = find_matching_paren(after) {
                        let args = &after[..close];
                        // Count top-level commas — if < 2, no options object yet
                        let comma_count = count_top_level_commas(args);
                        if comma_count < 2 {
                            let before = &line[..pos + "jwt.sign(".len()];
                            let rest = &after[close..]; // starts with ')'
                            return Some(format!("{before}{args}, {{ expiresIn: '1h' }}{rest}"));
                        }
                    }
                }
                None
            }
            Language::Python => {
                // Add a comment nudge — full payload injection is multi-line
                let indent = get_indent(line);
                Some(format!("{line}\n{indent}# SICARIO FIX: add exp=datetime.utcnow()+timedelta(hours=1) to payload"))
            }
            _ => None,
        }
    }
}

// ── Domain 3: Injection (continued) ──────────────────────────────────────────

// ── 34. InjectChildProcessShellTrueTemplate (CWE-78) ─────────────────────────

/// Removes `shell: true` from Node.js child_process spawn/execFile options.
pub struct InjectChildProcessShellTrueTemplate;

impl PatchTemplate for InjectChildProcessShellTrueTemplate {
    fn name(&self) -> &'static str { "InjectChildProcessShellTrue" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        if !line.contains("shell: true") && !line.contains("shell:true") { return None; }
        // Only fire on spawn/execFile/exec calls
        let lower = line.to_lowercase();
        if !lower.contains("spawn") && !lower.contains("execfile") && !lower.contains("exec(") {
            return None;
        }
        let fixed = line
            .replace(", shell: true", "")
            .replace(",shell: true", "")
            .replace(", shell:true", "")
            .replace(",shell:true", "")
            .replace("{ shell: true }", "{}")
            .replace("{ shell: true, ", "{ ")
            .replace("{ shell:true }", "{}")
            .replace("{ shell:true, ", "{ ");
        if fixed == line { return None; }
        Some(fixed)
    }
}

// ── 35. InjectPythonSubprocessShellTemplate (CWE-78) ─────────────────────────

/// Replaces `shell=True` with `shell=False` in Python subprocess calls.
pub struct InjectPythonSubprocessShellTemplate;

impl PatchTemplate for InjectPythonSubprocessShellTemplate {
    fn name(&self) -> &'static str { "InjectPythonSubprocessShell" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python { return None; }
        if !line.contains("shell=True") && !line.contains("shell = True") { return None; }
        let lower = line.to_lowercase();
        if !lower.contains("subprocess.") { return None; }
        let fixed = line
            .replace("shell=True", "shell=False")
            .replace("shell = True", "shell = False");
        if fixed == line { return None; }
        Some(fixed)
    }
}

// ── 36. InjectSstiTemplate (CWE-94) ──────────────────────────────────────────

/// Wraps `render_template_string(user_input)` with `escape()`.
pub struct InjectSstiTemplate;

impl PatchTemplate for InjectSstiTemplate {
    fn name(&self) -> &'static str { "InjectSsti" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python { return None; }
        if !line.contains("render_template_string(") { return None; }
        // Extract the argument and wrap it
        if let Some(pos) = line.find("render_template_string(") {
            let after = &line[pos + "render_template_string(".len()..];
            if let Some(close) = find_matching_paren(after) {
                let arg = &after[..close];
                let before = &line[..pos + "render_template_string(".len()];
                let rest = &after[close..];
                // Don't double-wrap
                if arg.trim_start().starts_with("escape(") { return None; }
                return Some(format!("{before}escape({arg}){rest}"));
            }
        }
        None
    }
}

// ── 37. InjectLdapTemplate (CWE-90) ──────────────────────────────────────────

/// Wraps user-controlled variables in LDAP filter strings with an escape helper.
pub struct InjectLdapTemplate;

impl PatchTemplate for InjectLdapTemplate {
    fn name(&self) -> &'static str { "InjectLdap" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        if !lower.contains("ldap") { return None; }
        // Must contain user input concatenation
        if !line.contains("req.body.") && !line.contains("req.query.")
            && !line.contains("req.params.") && !line.contains("user_input")
            && !line.contains("userInput") { return None; }

        match lang {
            Language::JavaScript | Language::TypeScript => {
                // wrap_nosql_input handles full `req.body.field` / `req.query.field` identifiers
                let fixed = wrap_nosql_input(line, "req.body.");
                let fixed = wrap_nosql_input(&fixed, "req.query.");
                let fixed = wrap_nosql_input(&fixed, "req.params.");
                // Replace the String() wrapper with ldap.escape()
                let fixed = fixed
                    .replace("String(req.body.", "ldap.escape(req.body.")
                    .replace("String(req.query.", "ldap.escape(req.query.")
                    .replace("String(req.params.", "ldap.escape(req.params.");
                // Also handle bare userInput
                let fixed = if fixed.contains("userInput") && !fixed.contains("ldap.escape(userInput)") {
                    fixed.replace("userInput", "ldap.escape(userInput)")
                } else { fixed };
                if fixed == line { return None; }
                Some(fixed)
            }
            Language::Python => {
                let fixed = if line.contains("user_input") && !line.contains("escape_filter_chars(user_input)") {
                    line.replace("user_input", "ldap3.utils.conv.escape_filter_chars(user_input)")
                } else { line.to_string() };
                if fixed == line { return None; }
                Some(fixed)
            }
            _ => None,
        }
    }
}

// ── 38. InjectXpathTemplate (CWE-643) ────────────────────────────────────────

/// Replaces user-controlled XPath string concatenation with a comment nudge.
///
/// Full parameterized XPath rewrite is context-dependent (varies by library),
/// so we insert a targeted comment on the vulnerable line.
pub struct InjectXpathTemplate;

impl PatchTemplate for InjectXpathTemplate {
    fn name(&self) -> &'static str { "InjectXpath" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        if !lower.contains("xpath") { return None; }
        // Must contain user input
        if !line.contains("req.body.") && !line.contains("req.query.")
            && !line.contains("user_input") && !line.contains("userInput") { return None; }
        // Must be a string concatenation or f-string
        if !line.contains(" + ") && !line.contains("f\"") && !line.contains("f'")
            && !line.contains('`') { return None; }

        let indent = get_indent(line);
        let comment = match lang {
            Language::Python => format!("{indent}# SICARIO FIX: use parameterized XPath — avoid string concatenation with user input"),
            _ => format!("{indent}// SICARIO FIX: use parameterized XPath — avoid string concatenation with user input"),
        };
        Some(format!("{comment}\n{line}"))
    }
}

// ── Sprint 2 shared helpers ───────────────────────────────────────────────────

/// Inject a key-value pair into the first object literal after `marker` in `line`.
///
/// e.g. `inject_into_object("cookie: { secure: true }", "cookie:", "httpOnly: true")`
/// → `"cookie: { httpOnly: true, secure: true }"`
fn inject_into_object(line: &str, marker: &str, kv: &str) -> Option<String> {
    let pos = line.find(marker)?;
    let after_marker = &line[pos + marker.len()..];
    // Find the opening brace
    let brace_offset = after_marker.find('{')?;
    let after_brace = &after_marker[brace_offset + 1..];
    let insert_pos = pos + marker.len() + brace_offset + 1;
    // Insert after the opening brace, before any existing content
    let trimmed_after = after_brace.trim_start();
    let space = if trimmed_after.starts_with('}') { "" } else { " " };
    let sep = if trimmed_after.starts_with('}') { "" } else { ", " };
    Some(format!(
        "{}{{ {kv}{sep}{}",
        &line[..insert_pos - 1], // everything up to and including the brace position
        &line[insert_pos..]      // everything after the opening brace
    ))
}

/// Count the number of top-level commas in a string (not inside nested parens/brackets/braces).
fn count_top_level_commas(s: &str) -> usize {
    let mut depth = 0usize;
    let mut count = 0usize;
    let mut in_str: Option<char> = None;
    for ch in s.chars() {
        if let Some(q) = in_str {
            if ch == q { in_str = None; }
            continue;
        }
        match ch {
            '"' | '\'' | '`' => in_str = Some(ch),
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => { if depth > 0 { depth -= 1; } }
            ',' if depth == 0 => count += 1,
            _ => {}
        }
    }
    count
}

/// Wrap occurrences of `target` (that are not already wrapped) with `fn_name(target)`.
fn wrap_with_fn(line: &str, target: &str, fn_name: &str) -> String {
    let already_wrapped = format!("{fn_name}({target}");
    if line.contains(&already_wrapped) {
        return line.to_string();
    }
    line.replace(target, &format!("{fn_name}({target})"))
}

// ── Sprint 2 tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod sprint2_tests {
    use super::*;

    fn js() -> Language { Language::JavaScript }
    fn py() -> Language { Language::Python }
    fn go() -> Language { Language::Go }

    // ── AuthSessionNoHttpOnlyTemplate ─────────────────────────────────────────

    #[test]
    fn test_session_httponly_injected() {
        let t = AuthSessionNoHttpOnlyTemplate;
        let line = "    app.use(session({ cookie: { secure: true } }));";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("httpOnly: true"));
    }

    #[test]
    fn test_session_httponly_already_present() {
        let t = AuthSessionNoHttpOnlyTemplate;
        assert!(t.generate_patch("    cookie: { httpOnly: true, secure: true }", js()).is_none());
    }

    #[test]
    fn test_session_httponly_wrong_lang() {
        let t = AuthSessionNoHttpOnlyTemplate;
        assert!(t.generate_patch("cookie: { secure: true }", py()).is_none());
    }

    // ── AuthSessionNoSecureFlagTemplate ───────────────────────────────────────

    #[test]
    fn test_session_secure_injected() {
        let t = AuthSessionNoSecureFlagTemplate;
        let line = "    app.use(session({ cookie: { httpOnly: true } }));";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("secure:"));
        assert!(result.contains("NODE_ENV"));
    }

    #[test]
    fn test_session_secure_already_present() {
        let t = AuthSessionNoSecureFlagTemplate;
        assert!(t.generate_patch("    cookie: { secure: true }", js()).is_none());
    }

    // ── AuthSessionFixationTemplate ───────────────────────────────────────────

    #[test]
    fn test_session_fixation_wrapped() {
        let t = AuthSessionFixationTemplate;
        let line = "    req.session.userId = user.id;";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("req.session.regenerate"));
        assert!(result.contains("req.session.userId = user.id"));
    }

    #[test]
    fn test_session_fixation_regenerate_not_wrapped() {
        let t = AuthSessionFixationTemplate;
        assert!(t.generate_patch("    req.session.regenerate(() => {", js()).is_none());
    }

    #[test]
    fn test_session_fixation_wrong_lang() {
        let t = AuthSessionFixationTemplate;
        assert!(t.generate_patch("    req.session.userId = id;", py()).is_none());
    }

    // ── AuthPasswordInLogTemplate ─────────────────────────────────────────────

    #[test]
    fn test_password_in_log_js() {
        let t = AuthPasswordInLogTemplate;
        let line = "    console.log('password:', password);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("// SICARIO FIX"));
        assert!(!result.contains("console.log"));
    }

    #[test]
    fn test_password_in_log_python() {
        let t = AuthPasswordInLogTemplate;
        let line = "    print(f'token: {token}')";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("# SICARIO FIX"));
    }

    #[test]
    fn test_password_in_log_no_sensitive() {
        let t = AuthPasswordInLogTemplate;
        assert!(t.generate_patch("    console.log('user logged in');", js()).is_none());
    }

    // ── AuthBasicAuthOverHttpTemplate ─────────────────────────────────────────

    #[test]
    fn test_basic_auth_http_replaced() {
        let t = AuthBasicAuthOverHttpTemplate;
        let line = "    const url = 'http://api.example.com'; // Authorization: 'Basic abc'";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("https://"));
        assert!(!result.contains("http://"));
    }

    #[test]
    fn test_basic_auth_already_https() {
        let t = AuthBasicAuthOverHttpTemplate;
        assert!(t.generate_patch("    fetch('https://api.example.com', { headers: { Authorization: 'Basic abc' } })", js()).is_none());
    }

    // ── AuthJwtNoExpiryTemplate ───────────────────────────────────────────────

    #[test]
    fn test_jwt_no_expiry_js_two_args() {
        let t = AuthJwtNoExpiryTemplate;
        let line = "    const token = jwt.sign(payload, secret);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("expiresIn: '1h'"));
    }

    #[test]
    fn test_jwt_no_expiry_already_has_expiry() {
        let t = AuthJwtNoExpiryTemplate;
        assert!(t.generate_patch("    jwt.sign(payload, secret, { expiresIn: '2h' });", js()).is_none());
    }

    #[test]
    fn test_jwt_no_expiry_python_comment() {
        let t = AuthJwtNoExpiryTemplate;
        let line = "    token = jwt.encode(payload, secret, algorithm='HS256')";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("# SICARIO FIX"));
        assert!(result.contains("timedelta"));
    }

    // ── InjectChildProcessShellTrueTemplate ───────────────────────────────────

    #[test]
    fn test_shell_true_removed_spawn() {
        let t = InjectChildProcessShellTrueTemplate;
        let line = "    const proc = spawn(cmd, args, { shell: true });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(!result.contains("shell: true"));
    }

    #[test]
    fn test_shell_true_removed_execfile() {
        let t = InjectChildProcessShellTrueTemplate;
        let line = "    execFile(cmd, args, { shell: true }, cb);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(!result.contains("shell: true"));
    }

    #[test]
    fn test_shell_true_no_match() {
        let t = InjectChildProcessShellTrueTemplate;
        assert!(t.generate_patch("    const x = { shell: true };", js()).is_none());
    }

    #[test]
    fn test_shell_true_wrong_lang() {
        let t = InjectChildProcessShellTrueTemplate;
        assert!(t.generate_patch("spawn(cmd, { shell: true })", py()).is_none());
    }

    // ── InjectPythonSubprocessShellTemplate ───────────────────────────────────

    #[test]
    fn test_subprocess_shell_true_replaced() {
        let t = InjectPythonSubprocessShellTemplate;
        let line = "    subprocess.run(cmd, shell=True)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("shell=False"));
        assert!(!result.contains("shell=True"));
    }

    #[test]
    fn test_subprocess_shell_false_untouched() {
        let t = InjectPythonSubprocessShellTemplate;
        assert!(t.generate_patch("    subprocess.run(cmd, shell=False)", py()).is_none());
    }

    #[test]
    fn test_subprocess_shell_wrong_lang() {
        let t = InjectPythonSubprocessShellTemplate;
        assert!(t.generate_patch("subprocess.run(cmd, shell=True)", js()).is_none());
    }

    // ── InjectSstiTemplate ────────────────────────────────────────────────────

    #[test]
    fn test_ssti_wrapped() {
        let t = InjectSstiTemplate;
        let line = "    return render_template_string(user_input)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("escape(user_input)"));
        assert!(!result.contains("render_template_string(user_input)"));
    }

    #[test]
    fn test_ssti_already_escaped() {
        let t = InjectSstiTemplate;
        assert!(t.generate_patch("    render_template_string(escape(user_input))", py()).is_none());
    }

    #[test]
    fn test_ssti_wrong_lang() {
        let t = InjectSstiTemplate;
        assert!(t.generate_patch("render_template_string(x)", js()).is_none());
    }

    // ── InjectLdapTemplate ────────────────────────────────────────────────────

    #[test]
    fn test_ldap_js_wrapped() {
        let t = InjectLdapTemplate;
        let line = "    const filter = '(uid=' + req.body.username + ')';  // ldap query";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("ldap.escape(req.body.username)"));
    }

    #[test]
    fn test_ldap_python_wrapped() {
        let t = InjectLdapTemplate;
        let line = "    ldap_filter = f'(uid={user_input})'  # ldap search";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("escape_filter_chars(user_input)"));
    }

    #[test]
    fn test_ldap_no_user_input() {
        let t = InjectLdapTemplate;
        assert!(t.generate_patch("    ldap_filter = '(uid=admin)'", py()).is_none());
    }

    // ── InjectXpathTemplate ───────────────────────────────────────────────────

    #[test]
    fn test_xpath_comment_injected() {
        let t = InjectXpathTemplate;
        let line = "    const expr = '//user[@id=' + req.query.id + ']';  // xpath";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("// SICARIO FIX"));
        assert!(result.contains("parameterized XPath"));
        // Original line preserved
        assert!(result.contains("req.query.id"));
    }

    #[test]
    fn test_xpath_no_user_input() {
        let t = InjectXpathTemplate;
        assert!(t.generate_patch("    const expr = '//user[@id=1]';  // xpath", js()).is_none());
    }

    // ── Registry integration ──────────────────────────────────────────────────

    #[test]
    fn test_registry_session_fixation_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-384")).is_some());
    }

    #[test]
    fn test_registry_jwt_no_expiry_by_rule() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("js-jwt-no-expiry", None).is_some());
    }

    #[test]
    fn test_registry_subprocess_shell_by_rule() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("py-subprocess-shell-true", None).is_some());
    }

    #[test]
    fn test_registry_ldap_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-90")).is_some());
    }

    #[test]
    fn test_registry_xpath_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-643")).is_some());
    }
}

// ── Sprint 3: Web Headers + Input Validation + File Handling (18 templates) ──

// ── Domain 4: Web Security Headers & CORS ────────────────────────────────────

// ── 40. WebHelmetMissingTemplate (CWE-693) ───────────────────────────────────

/// Injects `app.use(require('helmet')());` after `const app = express()`.
/// Only fires when `helmet` is not already present on the same line.
pub struct WebHelmetMissingTemplate;

impl PatchTemplate for WebHelmetMissingTemplate {
    fn name(&self) -> &'static str { "WebHelmetMissing" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        let trimmed = line.trim();
        if !trimmed.contains("express()") { return None; }
        if line.contains("helmet") { return None; }
        // Extract app variable name
        let app_var = trimmed
            .trim_start_matches("const ").trim_start_matches("let ").trim_start_matches("var ")
            .split(|c: char| c == '=' || c.is_whitespace()).next()
            .map(str::trim).filter(|s| !s.is_empty())?;
        let indent = get_indent(line);
        let semi = if line.trim_end().ends_with(';') { ";" } else { "" };
        Some(format!("{line}\n{indent}{app_var}.use(require('helmet')()){semi}"))
    }
}

// ── 41. WebCspMissingTemplate (CWE-693) ──────────────────────────────────────

/// Replaces bare `helmet()` with a version that includes a CSP directive.
pub struct WebCspMissingTemplate;

impl PatchTemplate for WebCspMissingTemplate {
    fn name(&self) -> &'static str { "WebCspMissing" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        if !line.contains("helmet()") { return None; }
        if line.contains("contentSecurityPolicy") { return None; }
        Some(line.replace(
            "helmet()",
            "helmet({ contentSecurityPolicy: { directives: { defaultSrc: [\"'self'\"] } } })",
        ))
    }
}

// ── 42. WebHstsDisabledTemplate (CWE-319) ────────────────────────────────────

/// Replaces `hsts: false` or `hsts: { maxAge: 0 }` with a secure HSTS config.
pub struct WebHstsDisabledTemplate;

impl PatchTemplate for WebHstsDisabledTemplate {
    fn name(&self) -> &'static str { "WebHstsDisabled" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        let lower = line.to_lowercase();
        if !lower.contains("hsts") { return None; }
        if !lower.contains("false") && !lower.contains("maxage: 0") && !lower.contains("maxage:0") {
            return None;
        }
        let fixed = line
            .replace("hsts: false", "hsts: { maxAge: 31536000, includeSubDomains: true }")
            .replace("hsts:false", "hsts: { maxAge: 31536000, includeSubDomains: true }")
            .replace("maxAge: 0", "maxAge: 31536000, includeSubDomains: true")
            .replace("maxAge:0", "maxAge: 31536000, includeSubDomains: true");
        if fixed == line { return None; }
        Some(fixed)
    }
}

// ── 43. WebCorsCredentialsWildcardTemplate (CWE-942) ─────────────────────────

/// Replaces `origin: '*'` when `credentials: true` is also present.
pub struct WebCorsCredentialsWildcardTemplate;

impl PatchTemplate for WebCorsCredentialsWildcardTemplate {
    fn name(&self) -> &'static str { "WebCorsCredentialsWildcard" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        let lower = line.to_lowercase();
        if !lower.contains("credentials") { return None; }
        if !line.contains("origin: '*'") && !line.contains("origin:\"*\"")
            && !line.contains("origin: \"*\"") { return None; }
        let fixed = line
            .replace("origin: '*'", "origin: process.env.ALLOWED_ORIGIN")
            .replace("origin: \"*\"", "origin: process.env.ALLOWED_ORIGIN")
            .replace("origin:\"*\"", "origin: process.env.ALLOWED_ORIGIN");
        if fixed == line { return None; }
        Some(fixed)
    }
}

// ── 44. WebReferrerPolicyMissingTemplate (CWE-200) ───────────────────────────

/// Injects `referrerPolicy` into a `helmet({...})` call that lacks it.
pub struct WebReferrerPolicyMissingTemplate;

impl PatchTemplate for WebReferrerPolicyMissingTemplate {
    fn name(&self) -> &'static str { "WebReferrerPolicyMissing" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        if !line.contains("helmet(") { return None; }
        if line.contains("referrerPolicy") { return None; }
        // helmet() with no args → add options
        if line.contains("helmet()") {
            return Some(line.replace(
                "helmet()",
                "helmet({ referrerPolicy: { policy: 'strict-origin-when-cross-origin' } })",
            ));
        }
        // helmet({ existing }) → inject referrerPolicy
        if let Some(pos) = line.find("helmet({") {
            let after = &line[pos + "helmet({".len()..];
            let before = &line[..pos + "helmet({".len()];
            return Some(format!(
                "{before} referrerPolicy: {{ policy: 'strict-origin-when-cross-origin' }}, {after}"
            ));
        }
        None
    }
}

// ── 45. WebClickjackingTemplate (CWE-1021) ───────────────────────────────────

/// Replaces `frameguard: false` or `X-Frame-Options: ALLOWALL` with deny.
pub struct WebClickjackingTemplate;

impl PatchTemplate for WebClickjackingTemplate {
    fn name(&self) -> &'static str { "WebClickjacking" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        let lower = line.to_lowercase();
        if !lower.contains("frameguard") && !lower.contains("x-frame-options") { return None; }
        let fixed = line
            .replace("frameguard: false", "frameguard: { action: 'deny' }")
            .replace("frameguard:false", "frameguard: { action: 'deny' }")
            .replace("X-Frame-Options: ALLOWALL", "X-Frame-Options: DENY")
            .replace("X-Frame-Options: SAMEORIGIN", "X-Frame-Options: DENY");
        if fixed == line { return None; }
        Some(fixed)
    }
}

// ── 46. WebCacheControlMissingTemplate (CWE-525) ─────────────────────────────

/// Injects `res.setHeader('Cache-Control', 'no-store');` before `res.json(` / `res.send(`.
pub struct WebCacheControlMissingTemplate;

impl PatchTemplate for WebCacheControlMissingTemplate {
    fn name(&self) -> &'static str { "WebCacheControlMissing" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        if !line.contains("res.json(") && !line.contains("res.send(")
            && !line.contains("res.render(") { return None; }
        if line.contains("Cache-Control") { return None; }
        let indent = get_indent(line);
        Some(format!("{indent}res.setHeader('Cache-Control', 'no-store');\n{line}"))
    }
}

// ── Domain 5: Input Validation & Prototype Pollution ─────────────────────────

// ── 47. PrototypePollutionMergeTemplate (CWE-1321) ───────────────────────────

/// Replaces `Object.assign(target, userInput)` with a prototype-safe merge.
pub struct PrototypePollutionMergeTemplate;

impl PatchTemplate for PrototypePollutionMergeTemplate {
    fn name(&self) -> &'static str { "PrototypePollutionMerge" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        if !line.contains("Object.assign(") && !line.contains("_.merge(") { return None; }
        // Must involve req.body or req.query
        if !line.contains("req.body") && !line.contains("req.query") { return None; }
        let fixed = if line.contains("Object.assign(") {
            // Object.assign(target, src) → Object.assign(Object.create(null), target, JSON.parse(JSON.stringify(src)))
            // Simple heuristic: wrap the second argument
            if let Some(pos) = line.find("Object.assign(") {
                let after = &line[pos + "Object.assign(".len()..];
                if let Some(comma) = find_top_level_comma(after) {
                    let first_arg = &after[..comma];
                    let rest_after_comma = after[comma + 1..].trim_start();
                    if let Some(close) = find_matching_paren(rest_after_comma) {
                        let second_arg = &rest_after_comma[..close];
                        let tail = &rest_after_comma[close + 1..];
                        let before = &line[..pos];
                        return Some(format!(
                            "{before}Object.assign(Object.create(null), {first_arg}, JSON.parse(JSON.stringify({second_arg}))){tail}"
                        ));
                    }
                }
            }
            line.to_string()
        } else {
            // _.merge(target, src) → same pattern
            line.replace("_.merge(", "Object.assign(Object.create(null), ")
        };
        if fixed == line { return None; }
        Some(fixed)
    }
}

// ── 48. PrototypePollutionSetTemplate (CWE-1321) ─────────────────────────────

/// Prepends a key validation guard before `obj[req.body.key] = ...`.
pub struct PrototypePollutionSetTemplate;

impl PatchTemplate for PrototypePollutionSetTemplate {
    fn name(&self) -> &'static str { "PrototypePollutionSet" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        // Dynamic property assignment from user input
        if !line.contains("req.body.key") && !line.contains("req.query.key")
            && !line.contains("req.params.key") { return None; }
        if !line.contains("] =") && !line.contains("]=") { return None; }
        let indent = get_indent(line);
        let key_src = if line.contains("req.body.key") { "req.body.key" }
            else if line.contains("req.query.key") { "req.query.key" }
            else { "req.params.key" };
        Some(format!(
            "{indent}if (['__proto__', 'constructor', 'prototype'].includes({key_src})) throw new Error('Invalid key');\n{line}"
        ))
    }
}

// ── 49. InputRegexDosTemplate (CWE-1333) ─────────────────────────────────────

/// Prepends a length guard before `new RegExp(userInput)`.
pub struct InputRegexDosTemplate;

impl PatchTemplate for InputRegexDosTemplate {
    fn name(&self) -> &'static str { "InputRegexDos" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        if !line.contains("new RegExp(") { return None; }
        // Must use user-controlled input
        if !line.contains("req.") && !line.contains("userInput") && !line.contains("input") {
            return None;
        }
        let indent = get_indent(line);
        Some(format!(
            "{indent}if (userInput.length > 100) throw new Error('Input too long');\n{line}"
        ))
    }
}

// ── 50. InputJsonParseNoTryCatchTemplate (CWE-755) ───────────────────────────

/// Wraps `JSON.parse(userInput)` in a try/catch when not already wrapped.
pub struct InputJsonParseNoTryCatchTemplate;

impl PatchTemplate for InputJsonParseNoTryCatchTemplate {
    fn name(&self) -> &'static str { "InputJsonParseNoTryCatch" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        if !line.contains("JSON.parse(") { return None; }
        // Don't fire if already inside a try block (heuristic: line starts with try)
        if line.trim_start().starts_with("try") { return None; }
        // Extract the variable being assigned to, if any
        let indent = get_indent(line);
        let trimmed = line.trim();
        // Check for assignment: `const x = JSON.parse(...)` or `let x = JSON.parse(...)`
        let (decl, var_name) = if trimmed.starts_with("const ") || trimmed.starts_with("let ")
            || trimmed.starts_with("var ") {
            let after_kw = trimmed.trim_start_matches("const ").trim_start_matches("let ")
                .trim_start_matches("var ");
            let var = after_kw.split(|c: char| c == '=' || c.is_whitespace()).next()
                .map(str::trim).unwrap_or("parsed");
            let kw = if trimmed.starts_with("const ") { "const" }
                else if trimmed.starts_with("let ") { "let" } else { "var" };
            (kw, var.to_string())
        } else {
            ("let", "parsed".to_string())
        };
        Some(format!(
            "{indent}{decl} {var_name};\n\
             {indent}try {{\n\
             {indent}    {var_name} = {trimmed}\n\
             {indent}}} catch (e) {{\n\
             {indent}    return res.status(400).json({{ error: 'Invalid JSON' }});\n\
             {indent}}}"
        ))
    }
}

// ── 51. InputPathTraversalTemplate (CWE-22) ──────────────────────────────────

/// Wraps `path.join(baseDir, userInput)` with a startsWith guard.
pub struct InputPathTraversalTemplate;

impl PatchTemplate for InputPathTraversalTemplate {
    fn name(&self) -> &'static str { "InputPathTraversal" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        if !line.contains("path.join(") && !line.contains("path.resolve(") { return None; }
        if !line.contains("req.") && !line.contains("userInput") && !line.contains("filename") {
            return None;
        }
        if line.contains("startsWith") { return None; }
        let indent = get_indent(line);
        Some(format!(
            "{line}\n{indent}if (!resolvedPath.startsWith(path.resolve(baseDir))) throw new Error('Path traversal blocked');"
        ))
    }
}

// ── 52. InputReqBodyNoValidationTemplate (CWE-20) ────────────────────────────

/// Injects a validation comment above the first `req.body.*` access.
pub struct InputReqBodyNoValidationTemplate;

impl PatchTemplate for InputReqBodyNoValidationTemplate {
    fn name(&self) -> &'static str { "InputReqBodyNoValidation" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        if !line.contains("req.body.") { return None; }
        // Don't fire if already has a validation comment nearby
        if line.contains("SICARIO") || line.contains("validate") || line.contains("schema") {
            return None;
        }
        let indent = get_indent(line);
        Some(format!(
            "{indent}// SICARIO: validate req.body with express-validator, joi, or zod before use\n{line}"
        ))
    }
}

// ── Domain 6: File & Resource Handling ───────────────────────────────────────

// ── 53. FileUploadNoMimeCheckTemplate (CWE-434) ───────────────────────────────

/// Injects a `fileFilter` into `multer({ dest: '...' })` calls missing one.
pub struct FileUploadNoMimeCheckTemplate;

impl PatchTemplate for FileUploadNoMimeCheckTemplate {
    fn name(&self) -> &'static str { "FileUploadNoMimeCheck" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        if !line.contains("multer(") { return None; }
        if line.contains("fileFilter") || line.contains("mimetype") { return None; }
        // Inject fileFilter into the multer options object
        let fixed = if line.contains("multer({") {
            if let Some(pos) = line.find("multer({") {
                let after = &line[pos + "multer({".len()..];
                let before = &line[..pos + "multer({".len()];
                format!(
                    "{before} fileFilter: (req, file, cb) => {{ const allowed = ['image/jpeg', 'image/png']; cb(null, allowed.includes(file.mimetype)); }}, {after}"
                )
            } else { line.to_string() }
        } else {
            line.to_string()
        };
        if fixed == line { return None; }
        Some(fixed)
    }
}

// ── 54. FileTempFileInsecureTemplate (CWE-377) ────────────────────────────────

/// Replaces `tempfile.mktemp()` with `tempfile.mkstemp()`.
pub struct FileTempFileInsecureTemplate;

impl PatchTemplate for FileTempFileInsecureTemplate {
    fn name(&self) -> &'static str { "FileTempFileInsecure" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python { return None; }
        if !line.contains("tempfile.mktemp(") { return None; }
        Some(line.replace("tempfile.mktemp(", "tempfile.mkstemp("))
    }
}

// ── 55. FilePermissionsWorldWritableTemplate (CWE-732) ────────────────────────

/// Replaces `os.chmod(path, 0o777)` / `0o666` with `0o600`.
pub struct FilePermissionsWorldWritableTemplate;

impl PatchTemplate for FilePermissionsWorldWritableTemplate {
    fn name(&self) -> &'static str { "FilePermissionsWorldWritable" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python { return None; }
        if !line.contains("os.chmod(") { return None; }
        if !line.contains("0o777") && !line.contains("0o666") && !line.contains("0o775")
            && !line.contains("0o755") { return None; }
        let fixed = line
            .replace("0o777", "0o600")
            .replace("0o666", "0o600")
            .replace("0o775", "0o640")
            .replace("0o755", "0o640");
        if fixed == line { return None; }
        Some(fixed)
    }
}

// ── 56. GoFileCloseErrorIgnoredTemplate (CWE-390) ────────────────────────────

/// Replaces bare `defer f.Close()` with an error-checking wrapper.
pub struct GoFileCloseErrorIgnoredTemplate;

impl PatchTemplate for GoFileCloseErrorIgnoredTemplate {
    fn name(&self) -> &'static str { "GoFileCloseErrorIgnored" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Go { return None; }
        let trimmed = line.trim();
        // Must be a bare `defer X.Close()` — not already wrapped in a func
        if !trimmed.starts_with("defer ") || !trimmed.contains(".Close()") { return None; }
        if trimmed.contains("func()") || trimmed.contains("func (") { return None; }
        // Extract the variable: `defer f.Close()` → `f`
        let after_defer = trimmed.trim_start_matches("defer ").trim();
        let var_name = after_defer.split('.').next()?.trim();
        if var_name.is_empty() { return None; }
        let indent = get_indent(line);
        Some(format!(
            "{indent}defer func() {{ if err := {var_name}.Close(); err != nil {{ log.Printf(\"close error: %v\", err) }} }}()"
        ))
    }
}

// ── 57. FileReadSyncTemplate (CWE-400) ────────────────────────────────────────

/// Replaces `fs.readFileSync(userInput)` with async + validation comment.
pub struct FileReadSyncTemplate;

impl PatchTemplate for FileReadSyncTemplate {
    fn name(&self) -> &'static str { "FileReadSync" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        if !line.contains("fs.readFileSync(") { return None; }
        // Only fire when the argument looks user-controlled
        if !line.contains("req.") && !line.contains("userInput") && !line.contains("filename")
            && !line.contains("filePath") { return None; }
        let fixed = line.replace("fs.readFileSync(", "await fs.promises.readFile(");
        if fixed == line { return None; }
        let indent = get_indent(line);
        Some(format!(
            "{indent}// SICARIO FIX: validate path before reading — see InputPathTraversalTemplate\n{fixed}"
        ))
    }
}

// ── Sprint 3 tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod sprint3_tests {
    use super::*;

    fn js() -> Language { Language::JavaScript }
    fn py() -> Language { Language::Python }
    fn go() -> Language { Language::Go }

    // ── WebHelmetMissingTemplate ──────────────────────────────────────────────

    #[test]
    fn test_helmet_injected() {
        let t = WebHelmetMissingTemplate;
        let line = "const app = express();";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("app.use(require('helmet')())"));
        assert!(result.contains("express()"));
    }

    #[test]
    fn test_helmet_already_present() {
        let t = WebHelmetMissingTemplate;
        assert!(t.generate_patch("const app = express(); app.use(helmet());", js()).is_none());
    }

    #[test]
    fn test_helmet_no_express() {
        let t = WebHelmetMissingTemplate;
        assert!(t.generate_patch("const router = express.Router();", js()).is_none());
    }

    // ── WebCspMissingTemplate ─────────────────────────────────────────────────

    #[test]
    fn test_csp_injected() {
        let t = WebCspMissingTemplate;
        let line = "    app.use(helmet());";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("contentSecurityPolicy"));
        assert!(result.contains("defaultSrc"));
    }

    #[test]
    fn test_csp_already_present() {
        let t = WebCspMissingTemplate;
        assert!(t.generate_patch("    app.use(helmet({ contentSecurityPolicy: {} }));", js()).is_none());
    }

    // ── WebHstsDisabledTemplate ───────────────────────────────────────────────

    #[test]
    fn test_hsts_false_replaced() {
        let t = WebHstsDisabledTemplate;
        let line = "    app.use(helmet({ hsts: false }));";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("maxAge: 31536000"));
        assert!(!result.contains("hsts: false"));
    }

    #[test]
    fn test_hsts_max_age_zero_replaced() {
        let t = WebHstsDisabledTemplate;
        let line = "    hsts: { maxAge: 0 }";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("31536000"));
    }

    // ── WebCorsCredentialsWildcardTemplate ────────────────────────────────────

    #[test]
    fn test_cors_credentials_wildcard_replaced() {
        let t = WebCorsCredentialsWildcardTemplate;
        let line = "    cors({ origin: '*', credentials: true })";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("process.env.ALLOWED_ORIGIN"));
        assert!(!result.contains("'*'"));
    }

    #[test]
    fn test_cors_no_credentials_not_fired() {
        let t = WebCorsCredentialsWildcardTemplate;
        // No credentials: true — don't fire
        assert!(t.generate_patch("    cors({ origin: '*' })", js()).is_none());
    }

    // ── WebReferrerPolicyMissingTemplate ──────────────────────────────────────

    #[test]
    fn test_referrer_policy_injected_bare_helmet() {
        let t = WebReferrerPolicyMissingTemplate;
        let line = "    app.use(helmet());";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("referrerPolicy"));
        assert!(result.contains("strict-origin-when-cross-origin"));
    }

    #[test]
    fn test_referrer_policy_already_present() {
        let t = WebReferrerPolicyMissingTemplate;
        assert!(t.generate_patch("    helmet({ referrerPolicy: { policy: 'no-referrer' } })", js()).is_none());
    }

    // ── WebClickjackingTemplate ───────────────────────────────────────────────

    #[test]
    fn test_frameguard_false_replaced() {
        let t = WebClickjackingTemplate;
        let line = "    helmet({ frameguard: false })";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("action: 'deny'"));
        assert!(!result.contains("frameguard: false"));
    }

    // ── WebCacheControlMissingTemplate ────────────────────────────────────────

    #[test]
    fn test_cache_control_injected() {
        let t = WebCacheControlMissingTemplate;
        let line = "    res.json({ user });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("Cache-Control"));
        assert!(result.contains("no-store"));
        assert!(result.contains("res.json("));
    }

    #[test]
    fn test_cache_control_already_set() {
        let t = WebCacheControlMissingTemplate;
        assert!(t.generate_patch("    res.setHeader('Cache-Control', 'no-store'); res.json(data);", js()).is_none());
    }

    // ── PrototypePollutionMergeTemplate ───────────────────────────────────────

    #[test]
    fn test_prototype_pollution_merge_wrapped() {
        let t = PrototypePollutionMergeTemplate;
        let line = "    Object.assign(config, req.body);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("Object.create(null)"));
        assert!(result.contains("JSON.parse(JSON.stringify("));
    }

    #[test]
    fn test_prototype_pollution_no_user_input() {
        let t = PrototypePollutionMergeTemplate;
        assert!(t.generate_patch("    Object.assign(a, b);", js()).is_none());
    }

    // ── PrototypePollutionSetTemplate ─────────────────────────────────────────

    #[test]
    fn test_prototype_pollution_set_guard() {
        let t = PrototypePollutionSetTemplate;
        let line = "    obj[req.body.key] = req.body.value;";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("__proto__"));
        assert!(result.contains("constructor"));
        assert!(result.contains("prototype"));
    }

    #[test]
    fn test_prototype_pollution_set_no_match() {
        let t = PrototypePollutionSetTemplate;
        assert!(t.generate_patch("    obj['name'] = value;", js()).is_none());
    }

    // ── InputRegexDosTemplate ─────────────────────────────────────────────────

    #[test]
    fn test_regex_dos_guard_injected() {
        let t = InputRegexDosTemplate;
        let line = "    const re = new RegExp(userInput);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("userInput.length > 100"));
        assert!(result.contains("new RegExp(userInput)"));
    }

    #[test]
    fn test_regex_dos_literal_not_fired() {
        let t = InputRegexDosTemplate;
        assert!(t.generate_patch("    const re = new RegExp('^[a-z]+$');", js()).is_none());
    }

    // ── InputJsonParseNoTryCatchTemplate ──────────────────────────────────────

    #[test]
    fn test_json_parse_wrapped() {
        let t = InputJsonParseNoTryCatchTemplate;
        let line = "    const data = JSON.parse(body);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("try {"));
        assert!(result.contains("catch (e)"));
        assert!(result.contains("400"));
    }

    #[test]
    fn test_json_parse_wrong_lang() {
        let t = InputJsonParseNoTryCatchTemplate;
        assert!(t.generate_patch("    data = JSON.parse(body)", py()).is_none());
    }

    // ── InputPathTraversalTemplate ────────────────────────────────────────────

    #[test]
    fn test_path_traversal_guard_injected() {
        let t = InputPathTraversalTemplate;
        let line = "    const filePath = path.join(baseDir, req.params.filename);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("startsWith"));
        assert!(result.contains("Path traversal blocked"));
    }

    #[test]
    fn test_path_traversal_already_guarded() {
        let t = InputPathTraversalTemplate;
        assert!(t.generate_patch("    if (!p.startsWith(base)) throw new Error();", js()).is_none());
    }

    // ── InputReqBodyNoValidationTemplate ─────────────────────────────────────

    #[test]
    fn test_req_body_comment_injected() {
        let t = InputReqBodyNoValidationTemplate;
        let line = "    const name = req.body.name;";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("// SICARIO:"));
        assert!(result.contains("req.body.name"));
    }

    // ── FileUploadNoMimeCheckTemplate ─────────────────────────────────────────

    #[test]
    fn test_multer_filefilter_injected() {
        let t = FileUploadNoMimeCheckTemplate;
        let line = "    const upload = multer({ dest: 'uploads/' });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("fileFilter"));
        assert!(result.contains("mimetype"));
    }

    #[test]
    fn test_multer_already_has_filter() {
        let t = FileUploadNoMimeCheckTemplate;
        assert!(t.generate_patch("    multer({ fileFilter: myFilter })", js()).is_none());
    }

    // ── FileTempFileInsecureTemplate ──────────────────────────────────────────

    #[test]
    fn test_mktemp_replaced() {
        let t = FileTempFileInsecureTemplate;
        let line = "    tmp = tempfile.mktemp()";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("tempfile.mkstemp()"));
        assert!(!result.contains("tempfile.mktemp()"));
    }

    #[test]
    fn test_mktemp_wrong_lang() {
        let t = FileTempFileInsecureTemplate;
        assert!(t.generate_patch("tempfile.mktemp()", js()).is_none());
    }

    // ── FilePermissionsWorldWritableTemplate ──────────────────────────────────

    #[test]
    fn test_chmod_777_replaced() {
        let t = FilePermissionsWorldWritableTemplate;
        let line = "    os.chmod(path, 0o777)";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("0o600"));
        assert!(!result.contains("0o777"));
    }

    #[test]
    fn test_chmod_600_untouched() {
        let t = FilePermissionsWorldWritableTemplate;
        assert!(t.generate_patch("    os.chmod(path, 0o600)", py()).is_none());
    }

    // ── GoFileCloseErrorIgnoredTemplate ───────────────────────────────────────

    #[test]
    fn test_go_close_error_wrapped() {
        let t = GoFileCloseErrorIgnoredTemplate;
        let line = "\tdefer f.Close()";
        let result = t.generate_patch(line, go()).unwrap();
        assert!(result.contains("func()"));
        assert!(result.contains("f.Close()"));
        assert!(result.contains("log.Printf"));
    }

    #[test]
    fn test_go_close_already_wrapped() {
        let t = GoFileCloseErrorIgnoredTemplate;
        assert!(t.generate_patch("\tdefer func() { f.Close() }()", go()).is_none());
    }

    #[test]
    fn test_go_close_wrong_lang() {
        let t = GoFileCloseErrorIgnoredTemplate;
        assert!(t.generate_patch("\tdefer f.Close()", js()).is_none());
    }

    // ── FileReadSyncTemplate ──────────────────────────────────────────────────

    #[test]
    fn test_readfilesync_replaced() {
        let t = FileReadSyncTemplate;
        let line = "    const data = fs.readFileSync(req.params.filename);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("fs.promises.readFile("));
        assert!(result.contains("// SICARIO FIX"));
    }

    #[test]
    fn test_readfilesync_no_user_input() {
        let t = FileReadSyncTemplate;
        assert!(t.generate_patch("    const data = fs.readFileSync('./config.json');", js()).is_none());
    }

    // ── Registry integration ──────────────────────────────────────────────────

    #[test]
    fn test_registry_helmet_by_rule() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("express-helmet-missing", None).is_some());
    }

    #[test]
    fn test_registry_hsts_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-319")).is_some());
    }

    #[test]
    fn test_registry_prototype_pollution_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-1321")).is_some());
    }

    #[test]
    fn test_registry_path_traversal_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-22")).is_some());
    }

    #[test]
    fn test_registry_chmod_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-732")).is_some());
    }

    #[test]
    fn test_registry_go_close_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-390")).is_some());
    }
}

// ── Sprint 4: SQL + TLS/SSRF + Django/Flask + Cloud/IaC + React (23 templates)

// ── Domain 3 (remaining): SQL Injection ──────────────────────────────────────

// ── 58. SqlStringConcatTemplate (CWE-89) ─────────────────────────────────────

/// Replaces string concatenation inside SQL query calls with a parameterized comment.
///
/// Full parameterized rewrite is context-dependent (varies by ORM/driver), so
/// we inject a targeted SICARIO FIX comment on the vulnerable line and preserve
/// the original for the developer to complete.
pub struct SqlStringConcatTemplate;

impl PatchTemplate for SqlStringConcatTemplate {
    fn name(&self) -> &'static str { "SqlStringConcat" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        // Must be inside a query call
        let is_query = lower.contains(".query(") || lower.contains("cursor.execute(")
            || lower.contains("db.exec(") || lower.contains("db.query(")
            || lower.contains(".execute(") || lower.contains("db.raw(");
        if !is_query { return None; }
        // Must have string concatenation or f-string
        if !line.contains(" + ") && !line.contains("f\"") && !line.contains("f'")
            && !line.contains('`') { return None; }
        // Must reference user input
        if !line.contains("req.") && !line.contains("user") && !line.contains("input")
            && !line.contains("param") && !line.contains("body") { return None; }

        let indent = get_indent(line);
        let comment = match lang {
            Language::Python => format!("{indent}# SICARIO FIX (CWE-89): use parameterized query — replace string concat with %s placeholder"),
            Language::Go     => format!("{indent}// SICARIO FIX (CWE-89): use parameterized query — replace string concat with $1 placeholder"),
            _                => format!("{indent}// SICARIO FIX (CWE-89): use parameterized query — replace string concat with $1 placeholder"),
        };
        Some(format!("{comment}\n{line}"))
    }
}

// ── 59. SqlTemplateStringTemplate (CWE-89) ───────────────────────────────────

/// Flags template literals used as SQL query strings in JS/TS.
pub struct SqlTemplateStringTemplate;

impl PatchTemplate for SqlTemplateStringTemplate {
    fn name(&self) -> &'static str { "SqlTemplateString" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        let lower = line.to_lowercase();
        if !lower.contains(".query(") && !lower.contains(".execute(") { return None; }
        // Must use a template literal with interpolation
        if !line.contains('`') || !line.contains("${") { return None; }
        let indent = get_indent(line);
        Some(format!(
            "{indent}// SICARIO FIX (CWE-89): replace template literal with parameterized query — use $1, $2 placeholders and pass values as array\n{line}"
        ))
    }
}

// ── Domain 7: Network & TLS ───────────────────────────────────────────────────

// ── 60. TlsMinVersionTemplate (CWE-326) ──────────────────────────────────────

/// Replaces insecure TLS version strings with TLSv1.2.
pub struct TlsMinVersionTemplate;

impl PatchTemplate for TlsMinVersionTemplate {
    fn name(&self) -> &'static str { "TlsMinVersion" }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        if !lower.contains("tlsv1") && !lower.contains("minversion") { return None; }
        let fixed = line
            .replace("TLSv1_method", "TLSv1_2_method")
            .replace("TLSv1.1_method", "TLSv1_2_method")
            .replace("minVersion: 'TLSv1'", "minVersion: 'TLSv1.2'")
            .replace("minVersion: 'TLSv1.1'", "minVersion: 'TLSv1.2'")
            .replace("minVersion: \"TLSv1\"", "minVersion: \"TLSv1.2\"")
            .replace("minVersion: \"TLSv1.1\"", "minVersion: \"TLSv1.2\"")
            // Go: tls.VersionTLS10 / tls.VersionTLS11
            .replace("tls.VersionTLS10", "tls.VersionTLS12")
            .replace("tls.VersionTLS11", "tls.VersionTLS12");
        if fixed == line { return None; }
        Some(fixed)
    }
}

// ── 61. TlsCertVerifyDisabledNodeTemplate (CWE-295) ──────────────────────────

/// Fixes disabled TLS certificate verification in Node.js.
pub struct TlsCertVerifyDisabledNodeTemplate;

impl PatchTemplate for TlsCertVerifyDisabledNodeTemplate {
    fn name(&self) -> &'static str { "TlsCertVerifyDisabledNode" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        if line.contains("NODE_TLS_REJECT_UNAUTHORIZED") && line.contains("'0'") {
            return Some(line
                .replace("= '0'", "= '1'")
                .replace("= \"0\"", "= \"1\""));
        }
        if line.contains("rejectUnauthorized: false") || line.contains("rejectUnauthorized:false") {
            return Some(line
                .replace("rejectUnauthorized: false", "rejectUnauthorized: true")
                .replace("rejectUnauthorized:false", "rejectUnauthorized: true"));
        }
        None
    }
}

// ── 62. TlsCertVerifyDisabledGoTemplate (CWE-295) ────────────────────────────

/// Replaces `InsecureSkipVerify: true` with `false` in Go TLS configs.
pub struct TlsCertVerifyDisabledGoTemplate;

impl PatchTemplate for TlsCertVerifyDisabledGoTemplate {
    fn name(&self) -> &'static str { "TlsCertVerifyDisabledGo" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Go { return None; }
        if !line.contains("InsecureSkipVerify: true") && !line.contains("InsecureSkipVerify:true") {
            return None;
        }
        Some(line
            .replace("InsecureSkipVerify: true", "InsecureSkipVerify: false")
            .replace("InsecureSkipVerify:true", "InsecureSkipVerify: false"))
    }
}

// ── 63. SsrfHttpGetUserInputTemplate (CWE-918) ───────────────────────────────

/// Prepends an allowlist guard before axios/requests calls with user-controlled URLs.
pub struct SsrfHttpGetUserInputTemplate;

impl PatchTemplate for SsrfHttpGetUserInputTemplate {
    fn name(&self) -> &'static str { "SsrfHttpGetUserInput" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        let is_http_call = lower.contains("axios.get(") || lower.contains("axios.post(")
            || lower.contains("requests.get(") || lower.contains("requests.post(")
            || lower.contains("http.get(") || lower.contains("http.post(");
        if !is_http_call { return None; }
        // Must use user-controlled URL
        if !line.contains("req.body.") && !line.contains("req.query.")
            && !line.contains("user_url") && !line.contains("userUrl")
            && !line.contains("url)") { return None; }
        if line.contains("ALLOWED_HOSTS") || line.contains("allowlist") { return None; }

        let indent = get_indent(line);
        match lang {
            Language::JavaScript | Language::TypeScript => Some(format!(
                "{indent}const _parsed = new URL(req.body.url || req.query.url);\n\
                 {indent}if (!ALLOWED_HOSTS.has(_parsed.hostname)) throw new Error('SSRF blocked');\n\
                 {line}"
            )),
            Language::Python => Some(format!(
                "{indent}from urllib.parse import urlparse as _urlparse\n\
                 {indent}_parsed = _urlparse(user_url)\n\
                 {indent}if _parsed.hostname not in ALLOWED_HOSTS: raise ValueError('SSRF blocked')\n\
                 {line}"
            )),
            _ => None,
        }
    }
}

// ── 64. SsrfFetchUserInputTemplate (CWE-918) ─────────────────────────────────

/// Prepends an allowlist guard before `fetch(userInput)` calls.
pub struct SsrfFetchUserInputTemplate;

impl PatchTemplate for SsrfFetchUserInputTemplate {
    fn name(&self) -> &'static str { "SsrfFetchUserInput" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        if !line.contains("fetch(") { return None; }
        if !line.contains("req.") && !line.contains("userInput") && !line.contains("url") {
            return None;
        }
        if line.contains("ALLOWED_HOSTS") { return None; }
        let indent = get_indent(line);
        Some(format!(
            "{indent}const _fetchUrl = new URL(userInput || req.query.url);\n\
             {indent}if (!ALLOWED_HOSTS.has(_fetchUrl.hostname)) throw new Error('SSRF blocked');\n\
             {line}"
        ))
    }
}

// ── Domain 8: Django / Flask ──────────────────────────────────────────────────

// ── 65. DjangoDebugTrueTemplate (CWE-215) ────────────────────────────────────

/// Replaces `DEBUG = True` with an env-var-driven value.
pub struct DjangoDebugTrueTemplate;

impl PatchTemplate for DjangoDebugTrueTemplate {
    fn name(&self) -> &'static str { "DjangoDebugTrue" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python { return None; }
        let trimmed = line.trim();
        if trimmed != "DEBUG = True" && trimmed != "DEBUG=True" { return None; }
        let indent = get_indent(line);
        Some(format!("{indent}DEBUG = os.environ.get('DJANGO_DEBUG', 'False') == 'True'"))
    }
}

// ── 66. DjangoSecretKeyHardcodedTemplate (CWE-798) ───────────────────────────

/// Replaces hardcoded `SECRET_KEY = '...'` with an env-var lookup.
pub struct DjangoSecretKeyHardcodedTemplate;

impl PatchTemplate for DjangoSecretKeyHardcodedTemplate {
    fn name(&self) -> &'static str { "DjangoSecretKeyHardcoded" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python { return None; }
        let trimmed = line.trim();
        if !trimmed.starts_with("SECRET_KEY") { return None; }
        if !trimmed.contains(" = ") { return None; }
        // Must have a string literal value
        let after_eq = trimmed.splitn(2, " = ").nth(1).unwrap_or("").trim();
        if !after_eq.starts_with('\'') && !after_eq.starts_with('"') { return None; }
        let indent = get_indent(line);
        Some(format!("{indent}SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')"))
    }
}

// ── 67. DjangoAllowedHostsWildcardTemplate (CWE-183) ─────────────────────────

/// Replaces `ALLOWED_HOSTS = ['*']` with an env-var-driven list.
pub struct DjangoAllowedHostsWildcardTemplate;

impl PatchTemplate for DjangoAllowedHostsWildcardTemplate {
    fn name(&self) -> &'static str { "DjangoAllowedHostsWildcard" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python { return None; }
        let trimmed = line.trim();
        if !trimmed.starts_with("ALLOWED_HOSTS") { return None; }
        if !trimmed.contains("'*'") && !trimmed.contains("\"*\"") { return None; }
        let indent = get_indent(line);
        Some(format!("{indent}ALLOWED_HOSTS = os.environ.get('ALLOWED_HOSTS', '').split(',')"))
    }
}

// ── 68. DjangoCsrfExemptTemplate (CWE-352) ───────────────────────────────────

/// Removes `@csrf_exempt` decorator and replaces with a comment.
pub struct DjangoCsrfExemptTemplate;

impl PatchTemplate for DjangoCsrfExemptTemplate {
    fn name(&self) -> &'static str { "DjangoCsrfExempt" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python { return None; }
        if !line.trim().starts_with("@csrf_exempt") { return None; }
        let indent = get_indent(line);
        Some(format!("{indent}# SICARIO FIX: removed @csrf_exempt — ensure CSRF token is sent by client"))
    }
}

// ── 69. FlaskDebugTrueTemplate (CWE-215) ─────────────────────────────────────

/// Replaces `app.run(debug=True)` with an env-var-driven debug flag.
pub struct FlaskDebugTrueTemplate;

impl PatchTemplate for FlaskDebugTrueTemplate {
    fn name(&self) -> &'static str { "FlaskDebugTrue" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python { return None; }
        if !line.contains("debug=True") && !line.contains("debug = True")
            && !line.contains("'DEBUG'] = True") && !line.contains("\"DEBUG\"] = True") {
            return None;
        }
        let fixed = line
            .replace("debug=True", "debug=os.environ.get('FLASK_DEBUG', 'False') == 'True'")
            .replace("debug = True", "debug=os.environ.get('FLASK_DEBUG', 'False') == 'True'")
            .replace("'DEBUG'] = True", "'DEBUG'] = os.environ.get('FLASK_DEBUG', 'False') == 'True'")
            .replace("\"DEBUG\"] = True", "\"DEBUG\"] = os.environ.get('FLASK_DEBUG', 'False') == 'True'");
        if fixed == line { return None; }
        Some(fixed)
    }
}

// ── 70. FlaskSecretKeyHardcodedTemplate (CWE-798) ────────────────────────────

/// Replaces hardcoded Flask secret key with an env-var lookup.
pub struct FlaskSecretKeyHardcodedTemplate;

impl PatchTemplate for FlaskSecretKeyHardcodedTemplate {
    fn name(&self) -> &'static str { "FlaskSecretKeyHardcoded" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python { return None; }
        let lower = line.to_lowercase();
        if !lower.contains("secret_key") { return None; }
        // Must be an assignment with a string literal
        if !line.contains(" = ") { return None; }
        let after_eq = line.splitn(2, " = ").nth(1).unwrap_or("").trim();
        if !after_eq.starts_with('\'') && !after_eq.starts_with('"') { return None; }
        let indent = get_indent(line);
        if line.contains("app.secret_key") {
            return Some(format!("{indent}app.secret_key = os.environ.get('FLASK_SECRET_KEY')"));
        }
        if line.contains("'SECRET_KEY']") || line.contains("\"SECRET_KEY\"]") {
            return Some(format!("{indent}app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET_KEY')"));
        }
        None
    }
}

// ── 71. FlaskSqlAlchemyUriHardcodedTemplate (CWE-798) ────────────────────────

/// Replaces hardcoded SQLAlchemy database URI with an env-var lookup.
pub struct FlaskSqlAlchemyUriHardcodedTemplate;

impl PatchTemplate for FlaskSqlAlchemyUriHardcodedTemplate {
    fn name(&self) -> &'static str { "FlaskSqlAlchemyUriHardcoded" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python { return None; }
        if !line.contains("SQLALCHEMY_DATABASE_URI") { return None; }
        if !line.contains(" = ") { return None; }
        let after_eq = line.splitn(2, " = ").nth(1).unwrap_or("").trim();
        if !after_eq.starts_with('\'') && !after_eq.starts_with('"') { return None; }
        let indent = get_indent(line);
        Some(format!("{indent}SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL')"))
    }
}

// ── Domain 9: Cloud & Infrastructure ─────────────────────────────────────────

// ── 72. AwsHardcodedAccessKeyTemplate (CWE-798) ───────────────────────────────

/// Replaces hardcoded AWS access key IDs (starting with AKIA) with a comment.
pub struct AwsHardcodedAccessKeyTemplate;

impl PatchTemplate for AwsHardcodedAccessKeyTemplate {
    fn name(&self) -> &'static str { "AwsHardcodedAccessKey" }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        // AWS access key IDs always start with AKIA
        if !line.contains("AKIA") { return None; }
        let lower = line.to_lowercase();
        if !lower.contains("accesskeyid") && !lower.contains("access_key_id")
            && !lower.contains("aws_access") { return None; }
        let indent = get_indent(line);
        Some(format!(
            "{indent}// SICARIO FIX (CWE-798): use IAM role or environment credentials — remove hardcoded AWS key\n\
             {indent}// AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY should be set via environment or IAM role"
        ))
    }
}

// ── 73. AwsS3PublicReadAclTemplate (CWE-732) ──────────────────────────────────

/// Removes `ACL: 'public-read'` / `ACL: 'public-read-write'` from S3 calls.
pub struct AwsS3PublicReadAclTemplate;

impl PatchTemplate for AwsS3PublicReadAclTemplate {
    fn name(&self) -> &'static str { "AwsS3PublicReadAcl" }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        if !line.contains("ACL:") && !line.contains("acl=") { return None; }
        let lower = line.to_lowercase();
        if !lower.contains("public-read") { return None; }
        let fixed = line
            .replace(", ACL: 'public-read'", "")
            .replace(", ACL: 'public-read-write'", "")
            .replace(", ACL: \"public-read\"", "")
            .replace(", ACL: \"public-read-write\"", "")
            .replace("ACL: 'public-read', ", "")
            .replace("ACL: 'public-read-write', ", "")
            .replace(", acl='public-read'", "")
            .replace(", acl='public-read-write'", "");
        if fixed == line { return None; }
        Some(fixed)
    }
}

// ── 74. IacDockerLatestTagTemplate (CWE-1104) ────────────────────────────────

/// Replaces `:latest` in Dockerfile FROM instructions with a safer default.
pub struct IacDockerLatestTagTemplate;

impl PatchTemplate for IacDockerLatestTagTemplate {
    fn name(&self) -> &'static str { "IacDockerLatestTag" }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        let trimmed = line.trim();
        if !trimmed.starts_with("FROM ") { return None; }
        if !trimmed.contains(":latest") { return None; }
        let lower = trimmed.to_lowercase();
        let fixed = if lower.contains("node") {
            trimmed.replace(":latest", ":lts-alpine")
        } else if lower.contains("python") {
            trimmed.replace(":latest", ":slim")
        } else if lower.contains("ubuntu") || lower.contains("debian") {
            trimmed.replace(":latest", ":stable-slim")
        } else {
            trimmed.replace(":latest", ":stable")
        };
        let indent = get_indent(line);
        Some(format!(
            "{indent}{fixed}\n{indent}# SICARIO FIX: pin to a specific digest for reproducible builds"
        ))
    }
}

// ── 75. IacDockerAddInsteadOfCopyTemplate (CWE-706) ──────────────────────────

/// Replaces `ADD <local_path>` with `COPY` in Dockerfiles.
pub struct IacDockerAddInsteadOfCopyTemplate;

impl PatchTemplate for IacDockerAddInsteadOfCopyTemplate {
    fn name(&self) -> &'static str { "IacDockerAddInsteadOfCopy" }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        let trimmed = line.trim();
        if !trimmed.starts_with("ADD ") { return None; }
        // Don't replace ADD with a URL argument (ADD http://... is intentional)
        let arg = trimmed.trim_start_matches("ADD ").trim();
        if arg.starts_with("http://") || arg.starts_with("https://") { return None; }
        let indent = get_indent(line);
        Some(format!("{indent}{}", trimmed.replacen("ADD ", "COPY ", 1)))
    }
}

// ── Domain 10: React & Frontend ───────────────────────────────────────────────

// ── 76. ReactHrefJavascriptTemplate (CWE-79) ─────────────────────────────────

/// Wraps `href={userInput}` with a URL scheme validation guard.
pub struct ReactHrefJavascriptTemplate;

impl PatchTemplate for ReactHrefJavascriptTemplate {
    fn name(&self) -> &'static str { "ReactHrefJavascript" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        if !line.contains("href={") { return None; }
        if line.contains("https?://") || line.contains("startsWith") { return None; }
        // Wrap the href value with a scheme check
        let fixed = line
            .replace("href={userInput}", "href={/^https?:\\/\\//.test(userInput) ? userInput : '#'}")
            .replace("href={url}", "href={/^https?:\\/\\//.test(url) ? url : '#'}");
        if fixed == line { return None; }
        Some(fixed)
    }
}

// ── 77. ReactWindowLocationTemplate (CWE-601) ────────────────────────────────

/// Prepends a URL validation guard before `window.location.href = userInput`.
pub struct ReactWindowLocationTemplate;

impl PatchTemplate for ReactWindowLocationTemplate {
    fn name(&self) -> &'static str { "ReactWindowLocation" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        if !line.contains("window.location.href") && !line.contains("window.location.replace") {
            return None;
        }
        if line.contains("startsWith") || line.contains("test(") { return None; }
        let indent = get_indent(line);
        Some(format!(
            "{indent}if (!/^\\//.test(userInput) && !/^https:\\/\\//.test(userInput)) throw new Error('Redirect blocked');\n{line}"
        ))
    }
}

// ── 78. ReactLocalStorageTokenTemplate (CWE-922) ─────────────────────────────

/// Replaces `localStorage.setItem('token', ...)` with a comment.
pub struct ReactLocalStorageTokenTemplate;

impl PatchTemplate for ReactLocalStorageTokenTemplate {
    fn name(&self) -> &'static str { "ReactLocalStorageToken" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        if !line.contains("localStorage.setItem(") { return None; }
        let lower = line.to_lowercase();
        if !lower.contains("token") && !lower.contains("jwt") && !lower.contains("auth") {
            return None;
        }
        let indent = get_indent(line);
        Some(format!(
            "{indent}// SICARIO FIX (CWE-922): store auth tokens in httpOnly cookies, not localStorage\n\
             {indent}// localStorage is accessible to XSS — use Set-Cookie with HttpOnly; Secure; SameSite=Strict"
        ))
    }
}

// ── 79. ReactUseEffectMissingDepTemplate (CWE-362) ───────────────────────────

/// Replaces empty `[]` dependency array in useEffect when the callback uses outer vars.
///
/// Heuristic: if the line contains `useEffect(` with `}, [])` and the callback
/// references a variable that looks like a prop/state (camelCase identifier),
/// replace `[]` with `[<detected_var>]`.
pub struct ReactUseEffectMissingDepTemplate;

impl PatchTemplate for ReactUseEffectMissingDepTemplate {
    fn name(&self) -> &'static str { "ReactUseEffectMissingDep" }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang { Language::JavaScript | Language::TypeScript => {} _ => return None }
        // Must end with }, []) — the empty dep array pattern
        let trimmed = line.trim_end();
        if !trimmed.ends_with("}, [])") && !trimmed.ends_with("}, []);") { return None; }
        if !line.contains("useEffect(") { return None; }
        // Extract the callback body to find referenced variables
        // Simple heuristic: look for fetchData(X) or similar patterns
        let var = extract_useeffect_dep(line)?;
        let dep_array = format!("[{var}]");
        // Build replacement strings without format! to avoid brace escaping issues
        let repl      = ["}," , " ", &dep_array, ")"].concat();   // }, [userId])
        let repl_semi = ["}," , " ", &dep_array, ");"].concat();  // }, [userId]);
        let fixed = if trimmed.ends_with("}, []);") {
            line.replace("}, []);", &repl_semi)
        } else {
            line.replace("}, [])", &repl)
        };
        if fixed == line { return None; }
        Some(fixed)
    }
}

// ── 80. IacEnvFileHardcodedTemplate (CWE-798) ────────────────────────────────

/// Replaces hardcoded secret values in `.env` files with a placeholder.
///
/// Fires on lines matching `KEY=<non-empty-literal-value>` that look like
/// real secrets (not already a reference like `${VAR}` or `$(cmd)`).
pub struct IacEnvFileHardcodedTemplate;

impl PatchTemplate for IacEnvFileHardcodedTemplate {
    fn name(&self) -> &'static str { "IacEnvFileHardcoded" }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        let trimmed = line.trim();
        // Must be KEY=VALUE format (no spaces around =)
        if trimmed.starts_with('#') || trimmed.is_empty() { return None; }
        let eq_pos = trimmed.find('=')?;
        let key = &trimmed[..eq_pos];
        let value = &trimmed[eq_pos + 1..];

        // Key must be UPPER_SNAKE_CASE (env var convention)
        if !key.chars().all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit()) {
            return None;
        }
        // Value must be non-empty and not already a reference
        if value.is_empty() || value.starts_with("${") || value.starts_with("$(") {
            return None;
        }
        // Skip obviously safe values
        if value == "true" || value == "false" || value == "0" || value == "1"
            || value == "localhost" || value == "development" || value == "production" {
            return None;
        }
        // Must look like a secret (contains letters + digits, or is quoted)
        let is_secret = value.len() > 4
            && (value.starts_with('"') || value.starts_with('\'')
                || value.chars().any(|c| c.is_ascii_digit())
                    && value.chars().any(|c| c.is_ascii_alphabetic()));
        if !is_secret { return None; }

        let indent = get_indent(line);
        Some(format!(
            "{indent}# SICARIO: do not commit real secrets — use a secrets manager or CI/CD env vars\n\
             {indent}{key}=<REPLACE_WITH_REAL_VALUE>"
        ))
    }
}

/// Extract the most likely missing dependency from a useEffect callback.
fn extract_useeffect_dep(line: &str) -> Option<&str> {
    // Look for patterns like fetchData(userId), loadUser(id), etc.
    // Extract the argument of the first function call inside the callback
    let patterns = ["fetchData(", "loadData(", "fetchUser(", "loadUser(",
                    "getData(", "getUser(", "fetch(", "load("];
    for pat in &patterns {
        if let Some(pos) = line.find(pat) {
            let after = &line[pos + pat.len()..];
            let end = after.find(|c: char| !c.is_alphanumeric() && c != '_').unwrap_or(after.len());
            let var = &after[..end];
            if !var.is_empty() && var.chars().next().map(|c| c.is_lowercase()).unwrap_or(false) {
                return Some(var);
            }
        }
    }
    None
}



// ── Sprint 4 tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod sprint4_tests {
    use super::*;

    fn js() -> Language { Language::JavaScript }
    fn py() -> Language { Language::Python }
    fn go() -> Language { Language::Go }

    #[test]
    fn test_sql_concat_comment_injected() {
        let t = SqlStringConcatTemplate;
        let line = "    db.query('SELECT * FROM users WHERE id = ' + req.body.id);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("// SICARIO FIX (CWE-89)"));
        assert!(result.contains("db.query("));
    }

    #[test]
    fn test_sql_concat_no_user_input() {
        let t = SqlStringConcatTemplate;
        assert!(t.generate_patch("    db.query('SELECT * FROM users');", js()).is_none());
    }

    #[test]
    fn test_sql_template_string_flagged() {
        let t = SqlTemplateStringTemplate;
        let line = "    db.query(`SELECT * FROM users WHERE id = ${userId}`);";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("// SICARIO FIX (CWE-89)"));
    }

    #[test]
    fn test_sql_template_no_interpolation() {
        let t = SqlTemplateStringTemplate;
        assert!(t.generate_patch("    db.query(`SELECT * FROM users`);", js()).is_none());
    }

    #[test]
    fn test_tls_min_version_node() {
        let t = TlsMinVersionTemplate;
        let result = t.generate_patch("    tls.createServer({ minVersion: 'TLSv1' })", js()).unwrap();
        assert!(result.contains("TLSv1.2"));
        assert!(!result.contains("minVersion: 'TLSv1'"));
    }

    #[test]
    fn test_tls_min_version_go() {
        let t = TlsMinVersionTemplate;
        let result = t.generate_patch("\tMinVersion: tls.VersionTLS10,", go()).unwrap();
        assert!(result.contains("VersionTLS12"));
    }

    #[test]
    fn test_tls_already_v12() {
        let t = TlsMinVersionTemplate;
        assert!(t.generate_patch("    minVersion: 'TLSv1.2'", js()).is_none());
    }

    #[test]
    fn test_tls_reject_unauthorized_fixed() {
        let t = TlsCertVerifyDisabledNodeTemplate;
        let result = t.generate_patch("    const opts = { rejectUnauthorized: false };", js()).unwrap();
        assert!(result.contains("rejectUnauthorized: true"));
    }

    #[test]
    fn test_tls_node_env_fixed() {
        let t = TlsCertVerifyDisabledNodeTemplate;
        let result = t.generate_patch("    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';", js()).unwrap();
        assert!(result.contains("= '1'"));
    }

    #[test]
    fn test_go_insecure_skip_verify_fixed() {
        let t = TlsCertVerifyDisabledGoTemplate;
        let result = t.generate_patch("\t\tInsecureSkipVerify: true,", go()).unwrap();
        assert!(result.contains("InsecureSkipVerify: false"));
    }

    #[test]
    fn test_go_insecure_skip_verify_wrong_lang() {
        let t = TlsCertVerifyDisabledGoTemplate;
        assert!(t.generate_patch("InsecureSkipVerify: true", js()).is_none());
    }

    #[test]
    fn test_ssrf_axios_guard_injected() {
        let t = SsrfHttpGetUserInputTemplate;
        let result = t.generate_patch("    const resp = await axios.get(req.body.url);", js()).unwrap();
        assert!(result.contains("ALLOWED_HOSTS"));
        assert!(result.contains("SSRF blocked"));
        assert!(result.contains("axios.get("));
    }

    #[test]
    fn test_ssrf_already_guarded() {
        let t = SsrfHttpGetUserInputTemplate;
        assert!(t.generate_patch("    if (!ALLOWED_HOSTS.has(h)) throw new Error(); axios.get(url);", js()).is_none());
    }

    #[test]
    fn test_ssrf_fetch_guard_injected() {
        let t = SsrfFetchUserInputTemplate;
        let result = t.generate_patch("    const r = await fetch(req.query.url);", js()).unwrap();
        assert!(result.contains("ALLOWED_HOSTS"));
        assert!(result.contains("fetch("));
    }

    #[test]
    fn test_django_debug_replaced() {
        let t = DjangoDebugTrueTemplate;
        let result = t.generate_patch("DEBUG = True", py()).unwrap();
        assert!(result.contains("os.environ.get('DJANGO_DEBUG'"));
        assert!(!result.contains("DEBUG = True"));
    }

    #[test]
    fn test_django_debug_false_untouched() {
        let t = DjangoDebugTrueTemplate;
        assert!(t.generate_patch("DEBUG = False", py()).is_none());
    }

    #[test]
    fn test_django_secret_key_replaced() {
        let t = DjangoSecretKeyHardcodedTemplate;
        let result = t.generate_patch("SECRET_KEY = 'django-insecure-abc123'", py()).unwrap();
        assert!(result.contains("os.environ.get('DJANGO_SECRET_KEY')"));
    }

    #[test]
    fn test_django_allowed_hosts_replaced() {
        let t = DjangoAllowedHostsWildcardTemplate;
        let result = t.generate_patch("ALLOWED_HOSTS = ['*']", py()).unwrap();
        assert!(result.contains("os.environ.get('ALLOWED_HOSTS'"));
        assert!(result.contains(".split(',')"));
    }

    #[test]
    fn test_csrf_exempt_removed() {
        let t = DjangoCsrfExemptTemplate;
        let result = t.generate_patch("@csrf_exempt", py()).unwrap();
        assert!(result.contains("# SICARIO FIX"));
        assert!(result.starts_with('#'));
    }

    #[test]
    fn test_flask_debug_replaced() {
        let t = FlaskDebugTrueTemplate;
        let result = t.generate_patch("    app.run(debug=True)", py()).unwrap();
        assert!(result.contains("os.environ.get('FLASK_DEBUG'"));
    }

    #[test]
    fn test_flask_secret_key_replaced() {
        let t = FlaskSecretKeyHardcodedTemplate;
        let result = t.generate_patch("    app.secret_key = 'my-secret'", py()).unwrap();
        assert!(result.contains("os.environ.get('FLASK_SECRET_KEY')"));
    }

    #[test]
    fn test_sqlalchemy_uri_replaced() {
        let t = FlaskSqlAlchemyUriHardcodedTemplate;
        let result = t.generate_patch("SQLALCHEMY_DATABASE_URI = 'postgresql://user:pass@localhost/db'", py()).unwrap();
        assert!(result.contains("os.environ.get('DATABASE_URL')"));
    }

    #[test]
    fn test_aws_key_comment_injected() {
        let t = AwsHardcodedAccessKeyTemplate;
        let result = t.generate_patch("    accessKeyId: 'AKIAIOSFODNN7EXAMPLE',", js()).unwrap();
        assert!(result.contains("// SICARIO FIX (CWE-798)"));
        assert!(result.contains("IAM role"));
    }

    #[test]
    fn test_aws_key_no_akia() {
        let t = AwsHardcodedAccessKeyTemplate;
        assert!(t.generate_patch("    accessKeyId: process.env.AWS_ACCESS_KEY_ID,", js()).is_none());
    }

    #[test]
    fn test_s3_public_read_removed() {
        let t = AwsS3PublicReadAclTemplate;
        let line = "    s3.putObject({ Bucket: 'my-bucket', Key: 'file', ACL: 'public-read', Body: data });";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(!result.contains("ACL: 'public-read'"));
        assert!(result.contains("Bucket:"));
    }

    #[test]
    fn test_docker_latest_node_replaced() {
        let t = IacDockerLatestTagTemplate;
        let result = t.generate_patch("FROM node:latest", js()).unwrap();
        assert!(result.contains("lts-alpine"));
        assert!(!result.contains(":latest"));
    }

    #[test]
    fn test_docker_latest_python_replaced() {
        let t = IacDockerLatestTagTemplate;
        let result = t.generate_patch("FROM python:latest", js()).unwrap();
        assert!(result.contains(":slim"));
    }

    #[test]
    fn test_docker_pinned_not_replaced() {
        let t = IacDockerLatestTagTemplate;
        assert!(t.generate_patch("FROM node:18-alpine", js()).is_none());
    }

    #[test]
    fn test_docker_add_replaced_with_copy() {
        let t = IacDockerAddInsteadOfCopyTemplate;
        let result = t.generate_patch("ADD ./app /app", js()).unwrap();
        assert!(result.starts_with("COPY"));
        assert!(!result.contains("ADD "));
    }

    #[test]
    fn test_docker_add_url_not_replaced() {
        let t = IacDockerAddInsteadOfCopyTemplate;
        assert!(t.generate_patch("ADD https://example.com/file.tar.gz /tmp/", js()).is_none());
    }

    #[test]
    fn test_env_file_secret_replaced() {
        let t = IacEnvFileHardcodedTemplate;
        let result = t.generate_patch("DATABASE_PASSWORD=super_secret_123", js()).unwrap();
        assert!(result.contains("# SICARIO:"));
        assert!(result.contains("<REPLACE_WITH_REAL_VALUE>"));
    }

    #[test]
    fn test_env_file_empty_value_skipped() {
        let t = IacEnvFileHardcodedTemplate;
        assert!(t.generate_patch("DATABASE_PASSWORD=", js()).is_none());
    }

    #[test]
    fn test_env_file_reference_skipped() {
        let t = IacEnvFileHardcodedTemplate;
        assert!(t.generate_patch("DATABASE_URL=${DATABASE_URL}", js()).is_none());
    }

    #[test]
    fn test_react_href_wrapped() {
        let t = ReactHrefJavascriptTemplate;
        let result = t.generate_patch("    <a href={userInput}>click</a>", js()).unwrap();
        assert!(result.contains("https?:"));
        assert!(result.contains("'#'"));
    }

    #[test]
    fn test_window_location_guard_injected() {
        let t = ReactWindowLocationTemplate;
        let result = t.generate_patch("    window.location.href = userInput;", js()).unwrap();
        assert!(result.contains("Redirect blocked"));
        assert!(result.contains("window.location.href"));
    }

    #[test]
    fn test_localstorage_token_replaced() {
        let t = ReactLocalStorageTokenTemplate;
        let result = t.generate_patch("    localStorage.setItem('token', accessToken);", js()).unwrap();
        assert!(result.contains("// SICARIO FIX (CWE-922)"));
        assert!(result.contains("httpOnly cookies"));
    }

    #[test]
    fn test_localstorage_non_auth_not_replaced() {
        let t = ReactLocalStorageTokenTemplate;
        assert!(t.generate_patch("    localStorage.setItem('theme', 'dark');", js()).is_none());
    }

    #[test]
    fn test_useeffect_dep_injected() {
        let t = ReactUseEffectMissingDepTemplate;
        let result = t.generate_patch("    useEffect(() => { fetchData(userId); }, [])", js()).unwrap();
        assert!(result.contains("[userId]"));
        assert!(!result.contains(", []"));
    }

    #[test]
    fn test_useeffect_no_dep_found() {
        let t = ReactUseEffectMissingDepTemplate;
        assert!(t.generate_patch("    useEffect(() => { doSomething(); }, [])", js()).is_none());
    }

    // ── Registry integration ──────────────────────────────────────────────────

    #[test]
    fn test_registry_django_debug_by_rule() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("django-debug-true", None).is_some());
    }

    #[test]
    fn test_registry_csrf_exempt_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-352")).is_some());
    }

    #[test]
    fn test_registry_docker_latest_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-1104")).is_some());
    }

    #[test]
    fn test_registry_localstorage_by_cwe() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("unknown", Some("CWE-922")).is_some());
    }

    #[test]
    fn test_registry_tls_go_by_rule() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("go-tls-insecure-skip-verify", None).is_some());
    }

    #[test]
    fn test_registry_env_file_by_rule() {
        let reg = TemplateRegistry::default();
        assert!(reg.lookup("env-file-hardcoded-secret", None).is_some());
    }
}

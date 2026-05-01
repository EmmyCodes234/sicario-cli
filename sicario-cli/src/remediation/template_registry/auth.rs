//! Authentication and session management patch templates.

use super::helpers::*;
use super::PatchTemplate;
use crate::parser::Language;

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

// â”€â”€ 11. DomPostMessageWildcardTemplate (CWE-345) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces `postMessage(data, '*')` wildcard origin with an env-var target.
///
/// A wildcard origin allows any page to receive the message, enabling
/// cross-origin data leakage.
pub struct AuthSessionNoHttpOnlyTemplate;

impl PatchTemplate for AuthSessionNoHttpOnlyTemplate {
    fn name(&self) -> &'static str {
        "AuthSessionNoHttpOnly"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        // Must be a session/cookie config line
        let lower = line.to_lowercase();
        if !lower.contains("session") && !lower.contains("cookie") {
            return None;
        }
        // Already has httpOnly â€” leave it
        if lower.contains("httponly") {
            return None;
        }
        // Must contain a cookie options object opening
        if !line.contains("cookie:") && !line.contains("cookie :") {
            return None;
        }
        // Inject httpOnly: true into the cookie object
        let fixed = inject_into_object(line, "cookie:", "httpOnly: true")?;
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// â”€â”€ 29. AuthSessionNoSecureFlagTemplate (CWE-614) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Injects `secure: process.env.NODE_ENV === 'production'` into session cookie options.
pub struct AuthSessionNoSecureFlagTemplate;

impl PatchTemplate for AuthSessionNoSecureFlagTemplate {
    fn name(&self) -> &'static str {
        "AuthSessionNoSecureFlag"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        let lower = line.to_lowercase();
        if !lower.contains("session") && !lower.contains("cookie") {
            return None;
        }
        if lower.contains("secure:") {
            return None;
        }
        if !line.contains("cookie:") && !line.contains("cookie :") {
            return None;
        }
        let fixed = inject_into_object(
            line,
            "cookie:",
            "secure: process.env.NODE_ENV === 'production'",
        )?;
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// â”€â”€ 30. AuthSessionFixationTemplate (CWE-384) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Prepends `req.session.regenerate(() => {` before a session assignment.
///
/// `req.session.userId = user.id;`
/// â†’ `req.session.regenerate(() => {\n    req.session.userId = user.id;\n});`
pub struct AuthSessionFixationTemplate;

impl PatchTemplate for AuthSessionFixationTemplate {
    fn name(&self) -> &'static str {
        "AuthSessionFixation"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        // Must be a req.session.X = ... assignment (not .regenerate itself)
        if !line.contains("req.session.") {
            return None;
        }
        if line.contains(".regenerate") || line.contains(".destroy") || line.contains(".save") {
            return None;
        }
        // Must be an assignment
        let trimmed = line.trim();
        if !trimmed.contains(" = ") && !trimmed.contains(" =\t") {
            return None;
        }

        let indent = get_indent(line);
        let semicolon = if line.trim_end().ends_with(';') {
            ";"
        } else {
            ""
        };
        Some(format!(
            "{indent}req.session.regenerate(() => {{\n{line}\n{indent}}}){}",
            semicolon
        ))
    }
}

// â”€â”€ 31. AuthPasswordInLogTemplate (CWE-532) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces log calls that expose sensitive values with a comment.
///
/// Fires when the log argument contains `password`, `passwd`, `secret`, or `token`.
pub struct AuthPasswordInLogTemplate;

impl PatchTemplate for AuthPasswordInLogTemplate {
    fn name(&self) -> &'static str {
        "AuthPasswordInLog"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        // Must be a log call
        let is_log = lower.contains("console.log")
            || lower.contains("console.error")
            || lower.contains("console.warn")
            || lower.contains("console.info")
            || lower.contains("logger.info")
            || lower.contains("logger.debug")
            || lower.contains("logger.warn")
            || lower.contains("logger.error")
            || lower.contains("print(")
            || lower.contains("logging.");
        if !is_log {
            return None;
        }
        // Must reference a sensitive name
        let is_sensitive = lower.contains("password")
            || lower.contains("passwd")
            || lower.contains("secret")
            || lower.contains("token")
            || lower.contains("api_key")
            || lower.contains("apikey");
        if !is_sensitive {
            return None;
        }

        let indent = get_indent(line);
        let comment = match lang {
            Language::Python => {
                format!("{indent}# SICARIO FIX: removed logging of sensitive value")
            }
            _ => format!("{indent}// SICARIO FIX: removed logging of sensitive value"),
        };
        Some(comment)
    }
}

// â”€â”€ 32. AuthBasicAuthOverHttpTemplate (CWE-523) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces `http://` with `https://` when used with Basic auth headers.
pub struct AuthBasicAuthOverHttpTemplate;

impl PatchTemplate for AuthBasicAuthOverHttpTemplate {
    fn name(&self) -> &'static str {
        "AuthBasicAuthOverHttp"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        let lower = line.to_lowercase();
        if !lower.contains("basic ") && !lower.contains("authorization") {
            return None;
        }
        if !line.contains("http://") {
            return None;
        }
        Some(line.replace("http://", "https://"))
    }
}

// â”€â”€ 33. AuthJwtNoExpiryTemplate (CWE-613) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Injects `{ expiresIn: '1h' }` into `jwt.sign()` calls missing an expiry.
///
/// JS: `jwt.sign(payload, secret)` â†’ `jwt.sign(payload, secret, { expiresIn: '1h' })`
/// Python: adds `exp` field comment (multi-line fix exceeds trimmer budget, so
/// we inject a comment on the same line instead).
pub struct AuthJwtNoExpiryTemplate;

impl PatchTemplate for AuthJwtNoExpiryTemplate {
    fn name(&self) -> &'static str {
        "AuthJwtNoExpiry"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        if !lower.contains("jwt.sign") && !lower.contains("jwt.encode") {
            return None;
        }
        // Already has expiry
        if lower.contains("expiresin")
            || lower.contains("expires_in")
            || lower.contains("exp:")
            || lower.contains("expiry")
        {
            return None;
        }

        match lang {
            Language::JavaScript | Language::TypeScript => {
                // jwt.sign(payload, secret) â†’ jwt.sign(payload, secret, { expiresIn: '1h' })
                if let Some(pos) = line.find("jwt.sign(") {
                    let after = &line[pos + "jwt.sign(".len()..];
                    if let Some(close) = find_matching_paren(after) {
                        let args = &after[..close];
                        // Count top-level commas â€” if < 2, no options object yet
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
                // Add a comment nudge â€” full payload injection is multi-line
                let indent = get_indent(line);
                Some(format!("{line}\n{indent}# SICARIO FIX: add exp=datetime.utcnow()+timedelta(hours=1) to payload"))
            }
            _ => None,
        }
    }
}

// â”€â”€ Domain 3: Injection (continued) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// â”€â”€ 34. InjectChildProcessShellTrueTemplate (CWE-78) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Removes `shell: true` from Node.js child_process spawn/execFile options.
#[cfg(test)]
mod sprint2_tests {
    use crate::remediation::template_registry::*;

    fn js() -> Language {
        Language::JavaScript
    }
    fn py() -> Language {
        Language::Python
    }
    fn go() -> Language {
        Language::Go
    }

    // â”€â”€ AuthSessionNoHttpOnlyTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch("    cookie: { httpOnly: true, secure: true }", js())
            .is_none());
    }

    #[test]
    fn test_session_httponly_wrong_lang() {
        let t = AuthSessionNoHttpOnlyTemplate;
        assert!(t.generate_patch("cookie: { secure: true }", py()).is_none());
    }

    // â”€â”€ AuthSessionNoSecureFlagTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch("    cookie: { secure: true }", js())
            .is_none());
    }

    // â”€â”€ AuthSessionFixationTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch("    req.session.regenerate(() => {", js())
            .is_none());
    }

    #[test]
    fn test_session_fixation_wrong_lang() {
        let t = AuthSessionFixationTemplate;
        assert!(t
            .generate_patch("    req.session.userId = id;", py())
            .is_none());
    }

    // â”€â”€ AuthPasswordInLogTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch("    console.log('user logged in');", js())
            .is_none());
    }

    // â”€â”€ AuthBasicAuthOverHttpTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch(
                "    fetch('https://api.example.com', { headers: { Authorization: 'Basic abc' } })",
                js()
            )
            .is_none());
    }

    // â”€â”€ AuthJwtNoExpiryTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch("    jwt.sign(payload, secret, { expiresIn: '2h' });", js())
            .is_none());
    }

    #[test]
    fn test_jwt_no_expiry_python_comment() {
        let t = AuthJwtNoExpiryTemplate;
        let line = "    token = jwt.encode(payload, secret, algorithm='HS256')";
        let result = t.generate_patch(line, py()).unwrap();
        assert!(result.contains("# SICARIO FIX"));
        assert!(result.contains("timedelta"));
    }

    // â”€â”€ InjectChildProcessShellTrueTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch("    const x = { shell: true };", js())
            .is_none());
    }

    #[test]
    fn test_shell_true_wrong_lang() {
        let t = InjectChildProcessShellTrueTemplate;
        assert!(t
            .generate_patch("spawn(cmd, { shell: true })", py())
            .is_none());
    }

    // â”€â”€ InjectPythonSubprocessShellTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch("    subprocess.run(cmd, shell=False)", py())
            .is_none());
    }

    #[test]
    fn test_subprocess_shell_wrong_lang() {
        let t = InjectPythonSubprocessShellTemplate;
        assert!(t
            .generate_patch("subprocess.run(cmd, shell=True)", js())
            .is_none());
    }

    // â”€â”€ InjectSstiTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch("    render_template_string(escape(user_input))", py())
            .is_none());
    }

    #[test]
    fn test_ssti_wrong_lang() {
        let t = InjectSstiTemplate;
        assert!(t
            .generate_patch("render_template_string(x)", js())
            .is_none());
    }

    // â”€â”€ InjectLdapTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch("    ldap_filter = '(uid=admin)'", py())
            .is_none());
    }

    // â”€â”€ InjectXpathTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch("    const expr = '//user[@id=1]';  // xpath", js())
            .is_none());
    }

    // â”€â”€ Registry integration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

//! Web security headers and DOM-related patch templates.

use super::helpers::*;
use super::PatchTemplate;
use crate::parser::Language;

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

// â”€â”€ 4. DomDocumentWriteTemplate (CWE-79) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€ 5. WebCorsWildcardTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€ 6. PyUnsafeDeserializeTemplate (CWE-502) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces unsafe Python deserialization calls with safe alternatives.
///
/// - `yaml.load(...)` â†’ `yaml.safe_load(...)`
/// - `pickle.loads(...)` â†’ `json.loads(...)`
/// - `pickle.load(...)` â†’ `json.load(...)`
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

// â”€â”€ 12. WebCookieInsecureTemplate (CWE-614 / CWE-1004) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€ 13. WebExpressXPoweredByTemplate (CWE-200) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€ 14. PyRequestsVerifyFalseTemplate (CWE-295) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Removes `verify=False` from Python `requests` calls, restoring TLS verification.
///
/// `requests.get(url, verify=False)` â†’ `requests.get(url)`
/// `requests.post(url, data=d, verify=False)` â†’ `requests.post(url, data=d)`
///
/// Handles both standalone `verify=False` and `verify=False` mixed with other kwargs.
pub struct WebHelmetMissingTemplate;

impl PatchTemplate for WebHelmetMissingTemplate {
    fn name(&self) -> &'static str {
        "WebHelmetMissing"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        let trimmed = line.trim();
        if !trimmed.contains("express()") {
            return None;
        }
        if line.contains("helmet") {
            return None;
        }
        // Extract app variable name
        let app_var = trimmed
            .trim_start_matches("const ")
            .trim_start_matches("let ")
            .trim_start_matches("var ")
            .split(|c: char| c == '=' || c.is_whitespace())
            .next()
            .map(str::trim)
            .filter(|s| !s.is_empty())?;
        let indent = get_indent(line);
        let semi = if line.trim_end().ends_with(';') {
            ";"
        } else {
            ""
        };
        Some(format!(
            "{line}\n{indent}{app_var}.use(require('helmet')()){semi}"
        ))
    }
}

// â”€â”€ 41. WebCspMissingTemplate (CWE-693) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces bare `helmet()` with a version that includes a CSP directive.
pub struct WebCspMissingTemplate;

impl PatchTemplate for WebCspMissingTemplate {
    fn name(&self) -> &'static str {
        "WebCspMissing"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("helmet()") {
            return None;
        }
        if line.contains("contentSecurityPolicy") {
            return None;
        }
        Some(line.replace(
            "helmet()",
            "helmet({ contentSecurityPolicy: { directives: { defaultSrc: [\"'self'\"] } } })",
        ))
    }
}

// â”€â”€ 42. WebHstsDisabledTemplate (CWE-319) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces `hsts: false` or `hsts: { maxAge: 0 }` with a secure HSTS config.
pub struct WebHstsDisabledTemplate;

impl PatchTemplate for WebHstsDisabledTemplate {
    fn name(&self) -> &'static str {
        "WebHstsDisabled"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        let lower = line.to_lowercase();
        if !lower.contains("hsts") {
            return None;
        }
        if !lower.contains("false") && !lower.contains("maxage: 0") && !lower.contains("maxage:0") {
            return None;
        }
        let fixed = line
            .replace(
                "hsts: false",
                "hsts: { maxAge: 31536000, includeSubDomains: true }",
            )
            .replace(
                "hsts:false",
                "hsts: { maxAge: 31536000, includeSubDomains: true }",
            )
            .replace("maxAge: 0", "maxAge: 31536000, includeSubDomains: true")
            .replace("maxAge:0", "maxAge: 31536000, includeSubDomains: true");
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// â”€â”€ 43. WebCorsCredentialsWildcardTemplate (CWE-942) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces `origin: '*'` when `credentials: true` is also present.
pub struct WebCorsCredentialsWildcardTemplate;

impl PatchTemplate for WebCorsCredentialsWildcardTemplate {
    fn name(&self) -> &'static str {
        "WebCorsCredentialsWildcard"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        let lower = line.to_lowercase();
        if !lower.contains("credentials") {
            return None;
        }
        if !line.contains("origin: '*'")
            && !line.contains("origin:\"*\"")
            && !line.contains("origin: \"*\"")
        {
            return None;
        }
        let fixed = line
            .replace("origin: '*'", "origin: process.env.ALLOWED_ORIGIN")
            .replace("origin: \"*\"", "origin: process.env.ALLOWED_ORIGIN")
            .replace("origin:\"*\"", "origin: process.env.ALLOWED_ORIGIN");
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// â”€â”€ 44. WebReferrerPolicyMissingTemplate (CWE-200) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Injects `referrerPolicy` into a `helmet({...})` call that lacks it.
pub struct WebReferrerPolicyMissingTemplate;

impl PatchTemplate for WebReferrerPolicyMissingTemplate {
    fn name(&self) -> &'static str {
        "WebReferrerPolicyMissing"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("helmet(") {
            return None;
        }
        if line.contains("referrerPolicy") {
            return None;
        }
        // helmet() with no args â†’ add options
        if line.contains("helmet()") {
            return Some(line.replace(
                "helmet()",
                "helmet({ referrerPolicy: { policy: 'strict-origin-when-cross-origin' } })",
            ));
        }
        // helmet({ existing }) â†’ inject referrerPolicy
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

// â”€â”€ 45. WebClickjackingTemplate (CWE-1021) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces `frameguard: false` or `X-Frame-Options: ALLOWALL` with deny.
pub struct WebClickjackingTemplate;

impl PatchTemplate for WebClickjackingTemplate {
    fn name(&self) -> &'static str {
        "WebClickjacking"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        let lower = line.to_lowercase();
        if !lower.contains("frameguard") && !lower.contains("x-frame-options") {
            return None;
        }
        let fixed = line
            .replace("frameguard: false", "frameguard: { action: 'deny' }")
            .replace("frameguard:false", "frameguard: { action: 'deny' }")
            .replace("X-Frame-Options: ALLOWALL", "X-Frame-Options: DENY")
            .replace("X-Frame-Options: SAMEORIGIN", "X-Frame-Options: DENY");
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// â”€â”€ 46. WebCacheControlMissingTemplate (CWE-525) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Injects `res.setHeader('Cache-Control', 'no-store');` before `res.json(` / `res.send(`.
pub struct WebCacheControlMissingTemplate;

impl PatchTemplate for WebCacheControlMissingTemplate {
    fn name(&self) -> &'static str {
        "WebCacheControlMissing"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("res.json(")
            && !line.contains("res.send(")
            && !line.contains("res.render(")
        {
            return None;
        }
        if line.contains("Cache-Control") {
            return None;
        }
        let indent = get_indent(line);
        Some(format!(
            "{indent}res.setHeader('Cache-Control', 'no-store');\n{line}"
        ))
    }
}

// â”€â”€ Domain 5: Input Validation & Prototype Pollution â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// â”€â”€ 47. PrototypePollutionMergeTemplate (CWE-1321) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces `Object.assign(target, userInput)` with a prototype-safe merge.
#[cfg(test)]
mod sprint3_tests {
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

    // â”€â”€ WebHelmetMissingTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch("const app = express(); app.use(helmet());", js())
            .is_none());
    }

    #[test]
    fn test_helmet_no_express() {
        let t = WebHelmetMissingTemplate;
        assert!(t
            .generate_patch("const router = express.Router();", js())
            .is_none());
    }

    // â”€â”€ WebCspMissingTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch("    app.use(helmet({ contentSecurityPolicy: {} }));", js())
            .is_none());
    }

    // â”€â”€ WebHstsDisabledTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

    // â”€â”€ WebCorsCredentialsWildcardTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        // No credentials: true â€” don't fire
        assert!(t
            .generate_patch("    cors({ origin: '*' })", js())
            .is_none());
    }

    // â”€â”€ WebReferrerPolicyMissingTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch(
                "    helmet({ referrerPolicy: { policy: 'no-referrer' } })",
                js()
            )
            .is_none());
    }

    // â”€â”€ WebClickjackingTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_frameguard_false_replaced() {
        let t = WebClickjackingTemplate;
        let line = "    helmet({ frameguard: false })";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("action: 'deny'"));
        assert!(!result.contains("frameguard: false"));
    }

    // â”€â”€ WebCacheControlMissingTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch(
                "    res.setHeader('Cache-Control', 'no-store'); res.json(data);",
                js()
            )
            .is_none());
    }

    // â”€â”€ PrototypePollutionMergeTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

    // â”€â”€ PrototypePollutionSetTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

    // â”€â”€ InputRegexDosTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch("    const re = new RegExp('^[a-z]+$');", js())
            .is_none());
    }

    // â”€â”€ InputJsonParseNoTryCatchTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch("    data = JSON.parse(body)", py())
            .is_none());
    }

    // â”€â”€ InputPathTraversalTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch("    if (!p.startsWith(base)) throw new Error();", js())
            .is_none());
    }

    // â”€â”€ InputReqBodyNoValidationTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

    #[test]
    fn test_req_body_comment_injected() {
        let t = InputReqBodyNoValidationTemplate;
        let line = "    const name = req.body.name;";
        let result = t.generate_patch(line, js()).unwrap();
        assert!(result.contains("// SICARIO:"));
        assert!(result.contains("req.body.name"));
    }

    // â”€â”€ FileUploadNoMimeCheckTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch("    multer({ fileFilter: myFilter })", js())
            .is_none());
    }

    // â”€â”€ FileTempFileInsecureTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

    // â”€â”€ FilePermissionsWorldWritableTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch("    os.chmod(path, 0o600)", py())
            .is_none());
    }

    // â”€â”€ GoFileCloseErrorIgnoredTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch("\tdefer func() { f.Close() }()", go())
            .is_none());
    }

    #[test]
    fn test_go_close_wrong_lang() {
        let t = GoFileCloseErrorIgnoredTemplate;
        assert!(t.generate_patch("\tdefer f.Close()", js()).is_none());
    }

    // â”€â”€ FileReadSyncTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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
        assert!(t
            .generate_patch("    const data = fs.readFileSync('./config.json');", js())
            .is_none());
    }

    // â”€â”€ Registry integration â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

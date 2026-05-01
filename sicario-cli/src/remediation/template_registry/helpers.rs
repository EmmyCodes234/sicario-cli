//! Shared helper functions used by multiple template implementations.

use crate::parser::Language;

pub fn get_indent(line: &str) -> &str {
    let trimmed = line.trim_start();
    &line[..line.len() - trimmed.len()]
}

/// Extract the argument string from a simple single-argument function call.
///
/// Given `"  document.write(userInput);"` and `"document.write"`,
/// returns `Some("userInput")`.
///
/// Returns `None` if the call pattern is not found or the argument is empty.
pub fn extract_call_arg<'a>(line: &'a str, fn_name: &str) -> Option<&'a str> {
    let call = format!("{fn_name}(");
    let start = line.find(&call)? + call.len();
    // Find the matching closing paren â€” handle one level of nesting
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

pub fn replace_jwt_secret_js(line: &str, replacement: &str) -> Option<String> {
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
pub fn replace_jwt_secret_py(line: &str, replacement: &str) -> Option<String> {
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

// â”€â”€ 10. AuthMissingSaltTemplate (CWE-759) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Injects a secure salt-rounds parameter into bcrypt hash calls missing one.
///
/// `bcrypt.hash(password)` â†’ `bcrypt.hash(password, 12)`
/// `bcrypt.hashSync(password)` â†’ `bcrypt.hashSync(password, 12)`
/// `bcrypt.hashpw(password, ...)` is Python â€” already requires a salt, so
/// this template targets the JS/TS pattern where the rounds arg is omitted.
pub fn remove_verify_false(line: &str) -> Option<String> {
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
    // Sole kwarg: (url, verify=False) â†’ already handled above
    // Edge case: verify=False is the only argument after url
    if line.contains("(verify=False)") {
        return Some(line.replace("(verify=False)", "()"));
    }
    None
}

// â”€â”€ 15. InjectEvalTemplate (CWE-94) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces `eval(` with `JSON.parse(` (JS/TS) or `ast.literal_eval(` (Python).
///
/// `eval` executes arbitrary code; `JSON.parse` / `ast.literal_eval` safely
/// parse data without code execution.
pub fn contains_standalone_exec(line: &str) -> bool {
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
pub fn replace_standalone_exec(line: &str) -> String {
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

// â”€â”€ 17. InjectNoSqlTypeCastTemplate (CWE-943) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Wraps untyped user-input variables in `String()` casts inside MongoDB queries.
///
/// `User.find({ _id: req.query.id })` â†’ `User.find({ _id: String(req.query.id) })`
///
/// Prevents NoSQL object injection where `req.query.id` could be `{ $gt: "" }`
/// instead of a plain string.
pub fn wrap_nosql_input(line: &str, prefix: &str) -> String {
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

// â”€â”€ 18. ReactDangerouslySetInnerHtmlTemplate (CWE-79) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Wraps the `__html` value in `DOMPurify.sanitize(...)` in React JSX.
///
/// `dangerouslySetInnerHTML={{ __html: userInput }}`
/// â†’ `dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }}`
pub fn wrap_html_value(line: &str) -> Option<String> {
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
pub fn find_value_end(s: &str) -> Option<usize> {
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

// â”€â”€ 19. IacDockerRootUserTemplate (CWE-269) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Injects `USER nonroot` before the final `CMD` or `ENTRYPOINT` in a Dockerfile.
///
/// Running containers as root is a privilege escalation risk. This template
/// detects CMD/ENTRYPOINT lines and prepends a USER instruction.
///
/// Accepts any language â€” Dockerfiles have no entry in the `Language` enum,
/// so the registry matches by rule ID only.
pub fn find_top_level_comma(s: &str) -> Option<usize> {
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
pub fn find_string_literal_end(s: &str) -> Option<(usize, char)> {
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
pub fn find_matching_paren(s: &str) -> Option<usize> {
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

// â”€â”€ Sprint 1: Cryptography & Secrets (7 templates) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// â”€â”€ 20. CryptoPbkdf2LowIterationsTemplate (CWE-916) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces dangerously low PBKDF2 iteration counts with the OWASP 2023 minimum.
///
/// OWASP recommends â‰¥ 310,000 iterations for PBKDF2-HMAC-SHA256.
/// Handles Node.js `crypto.pbkdf2Sync(pwd, salt, <N>, ...)` and
/// Python `hashlib.pbkdf2_hmac('sha256', pwd, salt, <N>)`.
///
/// Only fires when the iteration count is a numeric literal < 100,000.
pub fn replace_low_iteration_count(line: &str, replacement: u64) -> Option<String> {
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

// â”€â”€ 21. CryptoRsaKeyTooShortTemplate (CWE-326) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces RSA key sizes < 2048 bits with 4096.
///
/// Handles:
/// - Node.js: `generateKeyPair('rsa', { modulusLength: 1024 })`
/// - Python cryptography: `rsa.generate_private_key(key_size=1024, ...)`
/// - Python Crypto: `RSA.generate(1024)`
pub fn replace_rsa_key_size(line: &str, replacement: u32) -> Option<String> {
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

// â”€â”€ 22. CryptoHardcodedAesKeyTemplate (CWE-321) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces a hardcoded string literal used as an AES key with an env-var lookup.
///
/// Handles:
/// - Node.js: `createCipheriv('aes-256-gcm', 'hardcodedkey', iv)`
///   â†’ `createCipheriv('aes-256-gcm', process.env.AES_KEY, iv)`
/// - Python: `AES.new(b'hardcodedkey', AES.MODE_GCM)`
///   â†’ `AES.new(os.environ.get("AES_KEY").encode(), AES.MODE_GCM)`
pub fn inject_into_object(line: &str, marker: &str, kv: &str) -> Option<String> {
    let pos = line.find(marker)?;
    let after_marker = &line[pos + marker.len()..];
    // Find the opening brace
    let brace_offset = after_marker.find('{')?;
    let after_brace = &after_marker[brace_offset + 1..];
    let insert_pos = pos + marker.len() + brace_offset + 1;
    // Insert after the opening brace, before any existing content
    let trimmed_after = after_brace.trim_start();
    let space = if trimmed_after.starts_with('}') {
        ""
    } else {
        " "
    };
    let sep = if trimmed_after.starts_with('}') {
        ""
    } else {
        ", "
    };
    Some(format!(
        "{}{{ {kv}{sep}{}",
        &line[..insert_pos - 1], // everything up to and including the brace position
        &line[insert_pos..]      // everything after the opening brace
    ))
}

/// Count the number of top-level commas in a string (not inside nested parens/brackets/braces).
pub fn count_top_level_commas(s: &str) -> usize {
    let mut depth = 0usize;
    let mut count = 0usize;
    let mut in_str: Option<char> = None;
    for ch in s.chars() {
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
                depth = depth.saturating_sub(1);
            }
            ',' if depth == 0 => count += 1,
            _ => {}
        }
    }
    count
}

/// Wrap occurrences of `target` (that are not already wrapped) with `fn_name(target)`.
pub fn wrap_with_fn(line: &str, target: &str, fn_name: &str) -> String {
    let already_wrapped = format!("{fn_name}({target}");
    if line.contains(&already_wrapped) {
        return line.to_string();
    }
    line.replace(target, &format!("{fn_name}({target})"))
}

// â”€â”€ Sprint 2 tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Extract the most likely missing dependency from a useEffect callback.
pub fn extract_useeffect_dep(line: &str) -> Option<&str> {
    // Look for patterns like fetchData(userId), loadUser(id), etc.
    // Extract the argument of the first function call inside the callback
    let patterns = [
        "fetchData(",
        "loadData(",
        "fetchUser(",
        "loadUser(",
        "getData(",
        "getUser(",
        "fetch(",
        "load(",
    ];
    for pat in &patterns {
        if let Some(pos) = line.find(pat) {
            let after = &line[pos + pat.len()..];
            let end = after
                .find(|c: char| !c.is_alphanumeric() && c != '_')
                .unwrap_or(after.len());
            let var = &after[..end];
            if !var.is_empty()
                && var
                    .chars()
                    .next()
                    .map(|c| c.is_lowercase())
                    .unwrap_or(false)
            {
                return Some(var);
            }
        }
    }
    None
}

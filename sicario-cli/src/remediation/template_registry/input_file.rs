//! Input validation, file/resource, and deserialization patch templates.

use super::helpers::*;
use super::PatchTemplate;
use crate::parser::Language;

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
            // yaml.load( â†’ yaml.safe_load(  (must come before generic .load( check)
            .replace("yaml.load(", "yaml.safe_load(")
            // pickle.loads( â†’ json.loads(
            .replace("pickle.loads(", "json.loads(")
            // pickle.load( â†’ json.load(
            .replace("pickle.load(", "json.load(");

        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// â”€â”€ 7. GoDeferCloseTemplate â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

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

// â”€â”€ Shared helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Get the leading whitespace of a line.
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
pub struct PrototypePollutionMergeTemplate;

impl PatchTemplate for PrototypePollutionMergeTemplate {
    fn name(&self) -> &'static str {
        "PrototypePollutionMerge"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("Object.assign(") && !line.contains("_.merge(") {
            return None;
        }
        // Must involve req.body or req.query
        if !line.contains("req.body") && !line.contains("req.query") {
            return None;
        }
        let fixed = if line.contains("Object.assign(") {
            // Object.assign(target, src) â†’ Object.assign(Object.create(null), target, JSON.parse(JSON.stringify(src)))
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
            // _.merge(target, src) â†’ same pattern
            line.replace("_.merge(", "Object.assign(Object.create(null), ")
        };
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// â”€â”€ 48. PrototypePollutionSetTemplate (CWE-1321) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Prepends a key validation guard before `obj[req.body.key] = ...`.
pub struct PrototypePollutionSetTemplate;

impl PatchTemplate for PrototypePollutionSetTemplate {
    fn name(&self) -> &'static str {
        "PrototypePollutionSet"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        // Dynamic property assignment from user input
        if !line.contains("req.body.key")
            && !line.contains("req.query.key")
            && !line.contains("req.params.key")
        {
            return None;
        }
        if !line.contains("] =") && !line.contains("]=") {
            return None;
        }
        let indent = get_indent(line);
        let key_src = if line.contains("req.body.key") {
            "req.body.key"
        } else if line.contains("req.query.key") {
            "req.query.key"
        } else {
            "req.params.key"
        };
        Some(format!(
            "{indent}if (['__proto__', 'constructor', 'prototype'].includes({key_src})) throw new Error('Invalid key');\n{line}"
        ))
    }
}

// â”€â”€ 49. InputRegexDosTemplate (CWE-1333) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Prepends a length guard before `new RegExp(userInput)`.
pub struct InputRegexDosTemplate;

impl PatchTemplate for InputRegexDosTemplate {
    fn name(&self) -> &'static str {
        "InputRegexDos"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("new RegExp(") {
            return None;
        }
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

// â”€â”€ 50. InputJsonParseNoTryCatchTemplate (CWE-755) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Wraps `JSON.parse(userInput)` in a try/catch when not already wrapped.
pub struct InputJsonParseNoTryCatchTemplate;

impl PatchTemplate for InputJsonParseNoTryCatchTemplate {
    fn name(&self) -> &'static str {
        "InputJsonParseNoTryCatch"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("JSON.parse(") {
            return None;
        }
        // Don't fire if already inside a try block (heuristic: line starts with try)
        if line.trim_start().starts_with("try") {
            return None;
        }
        // Extract the variable being assigned to, if any
        let indent = get_indent(line);
        let trimmed = line.trim();
        // Check for assignment: `const x = JSON.parse(...)` or `let x = JSON.parse(...)`
        let (decl, var_name) = if trimmed.starts_with("const ")
            || trimmed.starts_with("let ")
            || trimmed.starts_with("var ")
        {
            let after_kw = trimmed
                .trim_start_matches("const ")
                .trim_start_matches("let ")
                .trim_start_matches("var ");
            let var = after_kw
                .split(|c: char| c == '=' || c.is_whitespace())
                .next()
                .map(str::trim)
                .unwrap_or("parsed");
            let kw = if trimmed.starts_with("const ") {
                "const"
            } else if trimmed.starts_with("let ") {
                "let"
            } else {
                "var"
            };
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

// â”€â”€ 51. InputPathTraversalTemplate (CWE-22) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Wraps `path.join(baseDir, userInput)` with a startsWith guard.
pub struct InputPathTraversalTemplate;

impl PatchTemplate for InputPathTraversalTemplate {
    fn name(&self) -> &'static str {
        "InputPathTraversal"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("path.join(") && !line.contains("path.resolve(") {
            return None;
        }
        if !line.contains("req.") && !line.contains("userInput") && !line.contains("filename") {
            return None;
        }
        if line.contains("startsWith") {
            return None;
        }
        let indent = get_indent(line);
        Some(format!(
            "{line}\n{indent}if (!resolvedPath.startsWith(path.resolve(baseDir))) throw new Error('Path traversal blocked');"
        ))
    }
}

// â”€â”€ 52. InputReqBodyNoValidationTemplate (CWE-20) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Injects a validation comment above the first `req.body.*` access.
pub struct InputReqBodyNoValidationTemplate;

impl PatchTemplate for InputReqBodyNoValidationTemplate {
    fn name(&self) -> &'static str {
        "InputReqBodyNoValidation"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("req.body.") {
            return None;
        }
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

// â”€â”€ Domain 6: File & Resource Handling â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// â”€â”€ 53. FileUploadNoMimeCheckTemplate (CWE-434) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Injects a `fileFilter` into `multer({ dest: '...' })` calls missing one.
pub struct FileUploadNoMimeCheckTemplate;

impl PatchTemplate for FileUploadNoMimeCheckTemplate {
    fn name(&self) -> &'static str {
        "FileUploadNoMimeCheck"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("multer(") {
            return None;
        }
        if line.contains("fileFilter") || line.contains("mimetype") {
            return None;
        }
        // Inject fileFilter into the multer options object
        let fixed = if line.contains("multer({") {
            if let Some(pos) = line.find("multer({") {
                let after = &line[pos + "multer({".len()..];
                let before = &line[..pos + "multer({".len()];
                format!(
                    "{before} fileFilter: (req, file, cb) => {{ const allowed = ['image/jpeg', 'image/png']; cb(null, allowed.includes(file.mimetype)); }}, {after}"
                )
            } else {
                line.to_string()
            }
        } else {
            line.to_string()
        };
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// â”€â”€ 54. FileTempFileInsecureTemplate (CWE-377) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces `tempfile.mktemp()` with `tempfile.mkstemp()`.
pub struct FileTempFileInsecureTemplate;

impl PatchTemplate for FileTempFileInsecureTemplate {
    fn name(&self) -> &'static str {
        "FileTempFileInsecure"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }
        if !line.contains("tempfile.mktemp(") {
            return None;
        }
        Some(line.replace("tempfile.mktemp(", "tempfile.mkstemp("))
    }
}

// â”€â”€ 55. FilePermissionsWorldWritableTemplate (CWE-732) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces `os.chmod(path, 0o777)` / `0o666` with `0o600`.
pub struct FilePermissionsWorldWritableTemplate;

impl PatchTemplate for FilePermissionsWorldWritableTemplate {
    fn name(&self) -> &'static str {
        "FilePermissionsWorldWritable"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Python {
            return None;
        }
        if !line.contains("os.chmod(") {
            return None;
        }
        if !line.contains("0o777")
            && !line.contains("0o666")
            && !line.contains("0o775")
            && !line.contains("0o755")
        {
            return None;
        }
        let fixed = line
            .replace("0o777", "0o600")
            .replace("0o666", "0o600")
            .replace("0o775", "0o640")
            .replace("0o755", "0o640");
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// â”€â”€ 56. GoFileCloseErrorIgnoredTemplate (CWE-390) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces bare `defer f.Close()` with an error-checking wrapper.
pub struct GoFileCloseErrorIgnoredTemplate;

impl PatchTemplate for GoFileCloseErrorIgnoredTemplate {
    fn name(&self) -> &'static str {
        "GoFileCloseErrorIgnored"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        if lang != Language::Go {
            return None;
        }
        let trimmed = line.trim();
        // Must be a bare `defer X.Close()` â€” not already wrapped in a func
        if !trimmed.starts_with("defer ") || !trimmed.contains(".Close()") {
            return None;
        }
        if trimmed.contains("func()") || trimmed.contains("func (") {
            return None;
        }
        // Extract the variable: `defer f.Close()` â†’ `f`
        let after_defer = trimmed.trim_start_matches("defer ").trim();
        let var_name = after_defer.split('.').next()?.trim();
        if var_name.is_empty() {
            return None;
        }
        let indent = get_indent(line);
        Some(format!(
            "{indent}defer func() {{ if err := {var_name}.Close(); err != nil {{ log.Printf(\"close error: %v\", err) }} }}()"
        ))
    }
}

// â”€â”€ 57. FileReadSyncTemplate (CWE-400) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces `fs.readFileSync(userInput)` with async + validation comment.
pub struct FileReadSyncTemplate;

impl PatchTemplate for FileReadSyncTemplate {
    fn name(&self) -> &'static str {
        "FileReadSync"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        if !line.contains("fs.readFileSync(") {
            return None;
        }
        // Only fire when the argument looks user-controlled
        if !line.contains("req.")
            && !line.contains("userInput")
            && !line.contains("filename")
            && !line.contains("filePath")
        {
            return None;
        }
        let fixed = line.replace("fs.readFileSync(", "await fs.promises.readFile(");
        if fixed == line {
            return None;
        }
        let indent = get_indent(line);
        Some(format!(
            "{indent}// SICARIO FIX: validate path before reading â€” see InputPathTraversalTemplate\n{fixed}"
        ))
    }
}

// â”€â”€ Sprint 3 tests â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

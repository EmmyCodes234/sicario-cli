//! SQL injection patch templates.

use super::helpers::*;
use super::PatchTemplate;
use crate::parser::Language;

pub struct SqlStringConcatTemplate;

impl PatchTemplate for SqlStringConcatTemplate {
    fn name(&self) -> &'static str {
        "SqlStringConcat"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        let lower = line.to_lowercase();
        // Must be inside a query call
        let is_query = lower.contains(".query(")
            || lower.contains("cursor.execute(")
            || lower.contains("db.exec(")
            || lower.contains("db.query(")
            || lower.contains(".execute(")
            || lower.contains("db.raw(");
        if !is_query {
            return None;
        }
        // Must have string concatenation or f-string
        if !line.contains(" + ")
            && !line.contains("f\"")
            && !line.contains("f'")
            && !line.contains('`')
        {
            return None;
        }
        // Must reference user input
        if !line.contains("req.")
            && !line.contains("user")
            && !line.contains("input")
            && !line.contains("param")
            && !line.contains("body")
        {
            return None;
        }

        let indent = get_indent(line);
        let comment = match lang {
            Language::Python => format!("{indent}# SICARIO FIX (CWE-89): use parameterized query â€” replace string concat with %s placeholder"),
            Language::Go     => format!("{indent}// SICARIO FIX (CWE-89): use parameterized query â€” replace string concat with $1 placeholder"),
            _                => format!("{indent}// SICARIO FIX (CWE-89): use parameterized query â€” replace string concat with $1 placeholder"),
        };
        Some(format!("{comment}\n{line}"))
    }
}

// â”€â”€ 59. SqlTemplateStringTemplate (CWE-89) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Flags template literals used as SQL query strings in JS/TS.
pub struct SqlTemplateStringTemplate;

impl PatchTemplate for SqlTemplateStringTemplate {
    fn name(&self) -> &'static str {
        "SqlTemplateString"
    }

    fn generate_patch(&self, line: &str, lang: Language) -> Option<String> {
        match lang {
            Language::JavaScript | Language::TypeScript => {}
            _ => return None,
        }
        let lower = line.to_lowercase();
        if !lower.contains(".query(") && !lower.contains(".execute(") {
            return None;
        }
        // Must use a template literal with interpolation
        if !line.contains('`') || !line.contains("${") {
            return None;
        }
        let indent = get_indent(line);
        Some(format!(
            "{indent}// SICARIO FIX (CWE-89): replace template literal with parameterized query â€” use $1, $2 placeholders and pass values as array\n{line}"
        ))
    }
}

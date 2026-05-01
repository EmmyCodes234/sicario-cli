//! IaC, Docker, AWS, and cloud security patch templates.

use super::helpers::*;
use super::PatchTemplate;
use crate::parser::Language;

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

// â”€â”€ Shared parsing helpers â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

pub struct AwsHardcodedAccessKeyTemplate;

impl PatchTemplate for AwsHardcodedAccessKeyTemplate {
    fn name(&self) -> &'static str {
        "AwsHardcodedAccessKey"
    }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        // AWS access key IDs always start with AKIA
        if !line.contains("AKIA") {
            return None;
        }
        let lower = line.to_lowercase();
        if !lower.contains("accesskeyid")
            && !lower.contains("access_key_id")
            && !lower.contains("aws_access")
        {
            return None;
        }
        let indent = get_indent(line);
        Some(format!(
            "{indent}// SICARIO FIX (CWE-798): use IAM role or environment credentials â€” remove hardcoded AWS key\n\
             {indent}// AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY should be set via environment or IAM role"
        ))
    }
}

// â”€â”€ 73. AwsS3PublicReadAclTemplate (CWE-732) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Removes `ACL: 'public-read'` / `ACL: 'public-read-write'` from S3 calls.
pub struct AwsS3PublicReadAclTemplate;

impl PatchTemplate for AwsS3PublicReadAclTemplate {
    fn name(&self) -> &'static str {
        "AwsS3PublicReadAcl"
    }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        if !line.contains("ACL:") && !line.contains("acl=") {
            return None;
        }
        let lower = line.to_lowercase();
        if !lower.contains("public-read") {
            return None;
        }
        let fixed = line
            .replace(", ACL: 'public-read'", "")
            .replace(", ACL: 'public-read-write'", "")
            .replace(", ACL: \"public-read\"", "")
            .replace(", ACL: \"public-read-write\"", "")
            .replace("ACL: 'public-read', ", "")
            .replace("ACL: 'public-read-write', ", "")
            .replace(", acl='public-read'", "")
            .replace(", acl='public-read-write'", "");
        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// â”€â”€ 74. IacDockerLatestTagTemplate (CWE-1104) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces `:latest` in Dockerfile FROM instructions with a safer default.
pub struct IacDockerLatestTagTemplate;

impl PatchTemplate for IacDockerLatestTagTemplate {
    fn name(&self) -> &'static str {
        "IacDockerLatestTag"
    }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        let trimmed = line.trim();
        if !trimmed.starts_with("FROM ") {
            return None;
        }
        if !trimmed.contains(":latest") {
            return None;
        }
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

// â”€â”€ 75. IacDockerAddInsteadOfCopyTemplate (CWE-706) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Replaces `ADD <local_path>` with `COPY` in Dockerfiles.
pub struct IacDockerAddInsteadOfCopyTemplate;

impl PatchTemplate for IacDockerAddInsteadOfCopyTemplate {
    fn name(&self) -> &'static str {
        "IacDockerAddInsteadOfCopy"
    }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        let trimmed = line.trim();
        if !trimmed.starts_with("ADD ") {
            return None;
        }
        // Don't replace ADD with a URL argument (ADD http://... is intentional)
        let arg = trimmed.trim_start_matches("ADD ").trim();
        if arg.starts_with("http://") || arg.starts_with("https://") {
            return None;
        }
        let indent = get_indent(line);
        Some(format!("{indent}{}", trimmed.replacen("ADD ", "COPY ", 1)))
    }
}

// â”€â”€ Domain 10: React & Frontend â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

// â”€â”€ 76. ReactHrefJavascriptTemplate (CWE-79) â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

/// Wraps `href={userInput}` with a URL scheme validation guard.
pub struct IacEnvFileHardcodedTemplate;

impl PatchTemplate for IacEnvFileHardcodedTemplate {
    fn name(&self) -> &'static str {
        "IacEnvFileHardcoded"
    }

    fn generate_patch(&self, line: &str, _lang: Language) -> Option<String> {
        let trimmed = line.trim();
        // Must be KEY=VALUE format (no spaces around =)
        if trimmed.starts_with('#') || trimmed.is_empty() {
            return None;
        }
        let eq_pos = trimmed.find('=')?;
        let key = &trimmed[..eq_pos];
        let value = &trimmed[eq_pos + 1..];

        // Key must be UPPER_SNAKE_CASE (env var convention)
        if !key
            .chars()
            .all(|c| c.is_ascii_uppercase() || c == '_' || c.is_ascii_digit())
        {
            return None;
        }
        // Value must be non-empty and not already a reference
        if value.is_empty() || value.starts_with("${") || value.starts_with("$(") {
            return None;
        }
        // Skip obviously safe values
        if value == "true"
            || value == "false"
            || value == "0"
            || value == "1"
            || value == "localhost"
            || value == "development"
            || value == "production"
        {
            return None;
        }
        // Must look like a secret (contains letters + digits, or is quoted)
        let is_secret = value.len() > 4
            && (value.starts_with('"')
                || value.starts_with('\'')
                || value.chars().any(|c| c.is_ascii_digit())
                    && value.chars().any(|c| c.is_ascii_alphabetic()));
        if !is_secret {
            return None;
        }

        let indent = get_indent(line);
        Some(format!(
            "{indent}# SICARIO: do not commit real secrets â€” use a secrets manager or CI/CD env vars\n\
             {indent}{key}=<REPLACE_WITH_REAL_VALUE>"
        ))
    }
}

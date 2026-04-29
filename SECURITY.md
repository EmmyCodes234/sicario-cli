# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a vulnerability

If you discover a security vulnerability in Sicario, please report it responsibly.

**Do not open a public GitHub issue.**

Email **security@usesicario.xyz** with:

- A clear description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge your report within 48 hours and aim to release a fix within 7 days for critical issues.

## Scope

**In scope:**
- Vulnerabilities in the Sicario CLI binary
- Security rule bypasses (false negatives in detection)
- Authentication and token handling issues
- Path traversal or arbitrary file access via CLI inputs
- Dependency vulnerabilities in `Cargo.lock`

**Out of scope:**
- Vulnerabilities in third-party dependencies with no available fix
- Issues requiring physical access to the machine

## Recognition

We appreciate responsible disclosure and will credit reporters in the release notes unless you prefer to remain anonymous.

//! Cryptography-related patch templates.

use super::helpers::*;
use super::PatchTemplate;
use crate::parser::Language;

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

// Ã¢â€â‚¬Ã¢â€â‚¬ 2. CryptoMathRandomTemplate (CWE-338) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

// Ã¢â€â‚¬Ã¢â€â‚¬ 3. DomInnerHtmlTemplate (CWE-79) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

// Ã¢â€â‚¬Ã¢â€â‚¬ 8. CryptoEcbModeTemplate (CWE-327) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// Replaces ECB cipher mode with GCM in cipher algorithm strings.
///
/// ECB (Electronic Codebook) is deterministic and leaks patterns across blocks.
/// GCM (Galois/Counter Mode) provides authenticated encryption.
///
/// Handles:
/// - `"aes-128-ecb"` Ã¢â€ â€™ `"aes-256-gcm"`
/// - `"AES/ECB/PKCS5Padding"` Ã¢â€ â€™ `"AES/GCM/NoPadding"` (Java)
/// - `Cipher.getInstance("AES/ECB/...")` Ã¢â€ â€™ `Cipher.getInstance("AES/GCM/NoPadding")`
/// - `createCipheriv("aes-...-ecb", ...)` Ã¢â€ â€™ `createCipheriv("aes-256-gcm", ...)`
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
            // Java JCE: "AES/ECB/PKCS5Padding" Ã¢â€ â€™ "AES/GCM/NoPadding"
            .replace("AES/ECB/PKCS5Padding", "AES/GCM/NoPadding")
            .replace("AES/ECB/PKCS7Padding", "AES/GCM/NoPadding")
            .replace("AES/ECB/NoPadding", "AES/GCM/NoPadding")
            // Node.js crypto: any "aes-NNN-ecb" Ã¢â€ â€™ "aes-256-gcm"
            .replace("aes-128-ecb", "aes-256-gcm")
            .replace("aes-192-ecb", "aes-256-gcm")
            .replace("aes-256-ecb", "aes-256-gcm")
            // Python PyCryptodome / cryptography: AES.MODE_ECB Ã¢â€ â€™ AES.MODE_GCM
            .replace("AES.MODE_ECB", "AES.MODE_GCM")
            // Generic uppercase ECB Ã¢â€ â€™ GCM (catches remaining patterns)
            .replace("ECB", "GCM");

        if fixed == line {
            return None;
        }
        Some(fixed)
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ 9. CryptoHardcodedJwtTemplate (CWE-798) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// Replaces hardcoded JWT signing secrets with environment variable lookups.
///
/// Handles JS/TS `jwt.sign(payload, "literal")` and Python
/// `jwt.encode(payload, "literal", ...)`.
///
/// The replacement preserves the rest of the call Ã¢â‚¬â€ only the secret argument
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
                    // The first arg is the key Ã¢â‚¬â€ check for string/bytes literal
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

// Ã¢â€â‚¬Ã¢â€â‚¬ 23. CryptoInsecureRandomSeedTemplate (CWE-335) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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
        Some(format!("{indent}# SICARIO FIX: removed deterministic random.seed({arg}) Ã¢â‚¬â€ PRNG is now seeded from OS entropy"))
    }
}

// Ã¢â€â‚¬Ã¢â€â‚¬ 24. CryptoMd5PasswordHashTemplate (CWE-916) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// Replaces MD5-based password hashing with bcrypt.
///
/// MD5 is not a password hashing function Ã¢â‚¬â€ it's a fast hash with no work
/// factor, making it trivially brute-forceable.
///
/// Handles:
/// - JS: `md5(password)` Ã¢â€ â€™ `await bcrypt.hash(password, 12)`
/// - Python: `hashlib.md5(password.encode())` Ã¢â€ â€™ `bcrypt.hashpw(password.encode(), bcrypt.gensalt(12))`
/// - Go: `md5.Sum([]byte(password))` Ã¢â€ â€™ `bcrypt.GenerateFromPassword([]byte(password), 12)`
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

// Ã¢â€â‚¬Ã¢â€â‚¬ 25. CryptoJwtNoneAlgorithmTemplate (CWE-347) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// Replaces `'none'` / `"none"` in JWT algorithm specifications with `'HS256'`.
///
/// The `none` algorithm disables signature verification entirely, allowing
/// any token to be accepted as valid.
///
/// Handles:
/// - JS: `{ algorithms: ['none'] }` Ã¢â€ â€™ `{ algorithms: ['HS256'] }`
/// - JS: `jwt.verify(token, secret, { algorithms: ['none'] })`
/// - Python: `algorithm='none'` Ã¢â€ â€™ `algorithm='HS256'`
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

// Ã¢â€â‚¬Ã¢â€â‚¬ 26. CryptoJwtWeakAlgorithmTemplate (CWE-327) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

// Ã¢â€â‚¬Ã¢â€â‚¬ 27. CryptoHardcodedSaltTemplate (CWE-760) Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

/// Replaces hardcoded bcrypt salt literals with `bcrypt.gensalt(12)`.
///
/// A hardcoded salt defeats the purpose of salting Ã¢â‚¬â€ every password gets the
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

        // Find the second argument (the salt) Ã¢â‚¬â€ look for a bytes literal b"..." or b'...'
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

// Ã¢â€â‚¬Ã¢â€â‚¬ Tests Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

#[cfg(test)]
mod tests {
    use crate::remediation::template_registry::helpers::extract_call_arg;
    use crate::remediation::template_registry::*;

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ Registry Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ CryptoWeakHashTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ CryptoMathRandomTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ DomInnerHtmlTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ DomDocumentWriteTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ WebCorsWildcardTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ PyUnsafeDeserializeTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ GoDeferCloseTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ extract_call_arg Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ CryptoEcbModeTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ CryptoHardcodedJwtTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ AuthMissingSaltTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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
        // Already has salt rounds Ã¢â‚¬â€ should not modify
        assert!(t
            .generate_patch("    bcrypt.hash(password, 10);", js())
            .is_none());
    }

    #[test]
    fn test_bcrypt_wrong_lang() {
        let t = AuthMissingSaltTemplate;
        assert!(t.generate_patch("bcrypt.hash(password)", py()).is_none());
    }

    // Ã¢â€â‚¬Ã¢â€â‚¬ DomPostMessageWildcardTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ WebCookieInsecureTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ WebExpressXPoweredByTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ PyRequestsVerifyFalseTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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
        // verify=True is the default Ã¢â‚¬â€ no match
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
mod sprint1_tests {
    use crate::remediation::template_registry::*;

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ CryptoPbkdf2LowIterationsTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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
        // 310000 is already safe Ã¢â‚¬â€ should not modify
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

    // Ã¢â€â‚¬Ã¢â€â‚¬ CryptoRsaKeyTooShortTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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
        // 2048 is the minimum Ã¢â‚¬â€ should not be replaced
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

    // Ã¢â€â‚¬Ã¢â€â‚¬ CryptoHardcodedAesKeyTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ CryptoInsecureRandomSeedTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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
        // Variable seed Ã¢â‚¬â€ not deterministic, don't touch
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

    // Ã¢â€â‚¬Ã¢â€â‚¬ CryptoMd5PasswordHashTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ CryptoJwtNoneAlgorithmTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ CryptoJwtWeakAlgorithmTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

    // Ã¢â€â‚¬Ã¢â€â‚¬ CryptoHardcodedSaltTemplate Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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
        // Already using gensalt Ã¢â‚¬â€ no match
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

    // Ã¢â€â‚¬Ã¢â€â‚¬ Registry integration Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬Ã¢â€â‚¬

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

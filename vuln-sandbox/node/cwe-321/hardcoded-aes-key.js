// VULNERABLE: hardcoded-aes-key — AES cipher initialized with a hardcoded string key
// Rule: CryptoHardcodedAesKey | CWE-321 | Severity: CRITICAL

const crypto = require('crypto');

const iv = crypto.randomBytes(16);

// VULNERABLE: hardcoded string literal used as AES key — exposed in source control
const cipher = crypto.createCipheriv('aes-256-gcm', 'hardcodedkey123456789012345678', iv);

let encrypted = cipher.update('sensitive data', 'utf8', 'hex');
encrypted += cipher.final('hex');

console.log('Encrypted:', encrypted);

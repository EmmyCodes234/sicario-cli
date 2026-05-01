// VULNERABLE: rsa-key-too-short — RSA key generated with insufficient modulus length
// Rule: CryptoRsaKeyTooShort | CWE-326 | Severity: HIGH

const crypto = require('crypto');

// VULNERABLE: 1024-bit RSA key is considered broken — minimum should be 2048 (prefer 4096)
crypto.generateKeyPair('rsa', {
  modulusLength: 1024,
  publicKeyEncoding: { type: 'spki', format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
}, (err, publicKey, privateKey) => {
  if (err) throw err;
  console.log('Public key:', publicKey);
  console.log('Private key:', privateKey);
});

// VULNERABLE: pbkdf2-low-iterations — PBKDF2 with dangerously low iteration count
// Rule: CryptoPbkdf2LowIterations | CWE-916 | Severity: HIGH

const crypto = require('crypto');
const express = require('express');

const app = express();
app.use(express.json());

app.post('/register', (req, res) => {
  const { password } = req.body;
  const salt = crypto.randomBytes(16).toString('hex');

  // VULNERABLE: 1000 iterations is far below OWASP minimum of 310,000 for PBKDF2-HMAC-SHA256
  const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha256').toString('hex');

  res.json({ hash, salt });
});

app.listen(3000);

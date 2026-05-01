// VULNERABLE: jwt-weak-algorithm — JWT signed with weak HS1 algorithm
// Rule: CryptoJwtWeakAlgorithm | CWE-327 | Severity: HIGH

const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const SECRET = process.env.JWT_SECRET || 'supersecret';

app.post('/login', (req, res) => {
  const { username } = req.body;

  // VULNERABLE: HS1 (HMAC-SHA1) is cryptographically weak — use HS256 or stronger
  const token = jwt.sign({ username, role: 'user' }, SECRET, { algorithm: 'HS1' });

  res.json({ token });
});

app.listen(3000);

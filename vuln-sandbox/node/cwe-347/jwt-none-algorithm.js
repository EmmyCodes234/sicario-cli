// VULNERABLE: jwt-none-algorithm — JWT verification allows 'none' algorithm
// Rule: CryptoJwtNoneAlgorithm | CWE-347 | Severity: CRITICAL

const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const SECRET = process.env.JWT_SECRET || 'supersecret';

app.get('/protected', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];

  // VULNERABLE: allowing 'none' algorithm lets attackers forge tokens without a signature
  const decoded = jwt.verify(token, SECRET, { algorithms: ['none'] });

  res.json({ user: decoded });
});

app.listen(3000);

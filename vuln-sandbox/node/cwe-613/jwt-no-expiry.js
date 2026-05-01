// VULNERABLE: jwt-no-expiry — JWT signed without expiration claim
// Rule: AuthJwtNoExpiry | CWE-613 | Severity: MEDIUM

const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();
app.use(express.json());

const SECRET = process.env.JWT_SECRET || 'supersecret';

app.post('/login', (req, res) => {
  const { username } = req.body;

  // VULNERABLE: no expiresIn option — token is valid forever
  const token = jwt.sign({ username, role: 'user' }, SECRET);

  res.json({ token });
});

app.listen(3000);

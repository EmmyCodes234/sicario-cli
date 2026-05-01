// VULNERABLE: password-in-log — password logged to console
// Rule: AuthPasswordInLog | CWE-532 | Severity: HIGH

const express = require('express');

const app = express();
app.use(express.json());

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  // VULNERABLE: password written to logs — visible in log aggregators and audit trails
  console.log('Login attempt:', username, 'password:', password);

  if (username === 'admin' && password === 'secret') {
    res.json({ token: 'abc123' });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.listen(3000);

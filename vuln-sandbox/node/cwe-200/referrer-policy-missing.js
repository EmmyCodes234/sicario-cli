// VULNERABLE: referrer-policy-missing — helmet() without referrerPolicy option
// Rule: WebReferrerPolicyMissing | CWE-200 | Severity: LOW

const express = require('express');
const helmet = require('helmet');

const app = express();

// VULNERABLE: helmet() called without referrerPolicy — Referer header leaks origin info
app.use(helmet({ referrerPolicy: false }));
app.use(express.json());

app.get('/api/data', (req, res) => {
  res.json({ message: 'Hello, world!' });
});

app.listen(3000);

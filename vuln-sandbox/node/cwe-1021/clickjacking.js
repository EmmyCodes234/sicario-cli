// VULNERABLE: clickjacking — helmet with frameguard disabled
// Rule: WebClickjacking | CWE-1021 | Severity: MEDIUM

const express = require('express');
const helmet = require('helmet');

const app = express();

// VULNERABLE: frameguard:false disables X-Frame-Options, allowing clickjacking
app.use(helmet({ frameguard: false }));
app.use(express.json());

app.get('/api/data', (req, res) => {
  res.json({ message: 'Hello, world!' });
});

app.listen(3000);

// VULNERABLE: hsts-disabled — helmet configured with HSTS explicitly disabled
// Rule: WebHstsDisabled | CWE-319 | Severity: MEDIUM

const express = require('express');
const helmet = require('helmet');

const app = express();

// VULNERABLE: hsts: false disables HTTP Strict Transport Security header
app.use(helmet({ hsts: false }));
app.use(express.json());

app.get('/api/data', (req, res) => {
  res.json({ message: 'Hello, world!' });
});

app.listen(3000);

// VULNERABLE: csp-missing — helmet() used without contentSecurityPolicy
// Rule: WebCspMissing | CWE-693 | Severity: MEDIUM

const express = require('express');
const helmet = require('helmet');

const app = express();

// VULNERABLE: helmet() called without contentSecurityPolicy configuration
app.use(helmet());
app.use(express.json());

app.get('/api/data', (req, res) => {
  res.json({ message: 'Hello, world!' });
});

app.listen(3000);

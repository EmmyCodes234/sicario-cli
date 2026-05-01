// VULNERABLE: helmet-missing — Express app without helmet() security headers
// Rule: WebHelmetMissing | CWE-693 | Severity: MEDIUM

const express = require('express');

// VULNERABLE: helmet is never imported or applied — security headers are absent
const app = express();
app.use(express.json());

app.get('/api/data', (req, res) => {
  res.json({ message: 'Hello, world!' });
});

app.listen(3000);

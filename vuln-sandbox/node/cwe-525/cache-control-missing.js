// VULNERABLE: cache-control-missing — sensitive route without Cache-Control header
// Rule: WebCacheControlMissing | CWE-525 | Severity: LOW

const express = require('express');

const app = express();
app.use(express.json());

app.get('/api/user/profile', (req, res) => {
  // VULNERABLE: no Cache-Control: no-store header — sensitive data may be cached
  res.json({
    userId: 42,
    email: 'user@example.com',
    creditCard: '4111-1111-1111-1111',
  });
});

app.listen(3000);

// VULNERABLE: cors-credentials-wildcard — CORS wildcard origin with credentials:true
// Rule: WebCorsCredentialsWildcard | CWE-942 | Severity: HIGH

const express = require('express');
const cors = require('cors');

const app = express();

// VULNERABLE: origin:'*' combined with credentials:true is a CORS misconfiguration
app.use(cors({ origin: '*', credentials: true }));
app.use(express.json());

app.get('/api/profile', (req, res) => {
  res.json({ user: 'admin', email: 'admin@example.com' });
});

app.listen(3000);

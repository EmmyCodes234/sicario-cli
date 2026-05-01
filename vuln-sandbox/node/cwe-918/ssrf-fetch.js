// VULNERABLE: ssrf-fetch — fetch() with user-controlled URL (SSRF)
// Rule: SsrfFetchUserInput | CWE-918 | Severity: HIGH

const express = require('express');

const app = express();

app.get('/proxy', async (req, res) => {
  // VULNERABLE: user-controlled URL passed directly to fetch — enables SSRF
  const response = await fetch(req.query.url);
  const data = await response.text();
  res.send(data);
});

app.listen(3000);

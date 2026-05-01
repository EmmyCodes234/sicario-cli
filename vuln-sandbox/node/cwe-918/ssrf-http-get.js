// VULNERABLE: ssrf-http-get — axios.get with user-controlled URL (SSRF)
// Rule: SsrfHttpGetUserInput | CWE-918 | Severity: HIGH

const express = require('express');
const axios = require('axios');

const app = express();
app.use(express.json());

app.post('/fetch', async (req, res) => {
  // VULNERABLE: user-controlled URL passed directly to axios.get — enables SSRF
  const response = await axios.get(req.body.url);
  res.json({ data: response.data });
});

app.listen(3000);

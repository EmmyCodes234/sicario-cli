// VULNERABLE: json-parse-no-try-catch — JSON.parse without error handling
// Rule: InputJsonParseNoTryCatch | CWE-755 | Severity: LOW

const express = require('express');

const app = express();

app.post('/parse', (req, res) => {
  const userInput = req.body.data;

  // VULNERABLE: JSON.parse without try/catch — malformed input throws unhandled exception
  const parsed = JSON.parse(userInput);

  res.json({ result: parsed });
});

app.listen(3000);

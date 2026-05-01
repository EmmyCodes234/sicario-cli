// VULNERABLE: regex-dos — new RegExp() with user-controlled pattern (ReDoS)
// Rule: InputRegexDos | CWE-1333 | Severity: MEDIUM

const express = require('express');

const app = express();

app.get('/search', (req, res) => {
  const userInput = req.query.pattern;

  // VULNERABLE: user-controlled regex pattern can cause catastrophic backtracking
  const regex = new RegExp(userInput);
  const matches = ['hello', 'world', 'foo', 'bar'].filter(s => regex.test(s));

  res.json({ matches });
});

app.listen(3000);

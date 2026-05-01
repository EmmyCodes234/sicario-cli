// VULNERABLE: file-read-sync — fs.readFileSync with user-controlled path
// Rule: FileReadSync | CWE-400 | Severity: MEDIUM

const express = require('express');
const fs = require('fs');

const app = express();

app.get('/read', (req, res) => {
  const userInput = req.query.path;

  // VULNERABLE: synchronous file read with user-controlled path blocks event loop
  const content = fs.readFileSync(userInput, 'utf8');

  res.send(content);
});

app.listen(3000);

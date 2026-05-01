// VULNERABLE: eval-injection — eval() called with user-controlled input
// Rule: InjectEval | CWE-95 | Severity: CRITICAL

const express = require('express');

const app = express();
app.use(express.json());

app.post('/calculate', (req, res) => {
  const userInput = req.body.expression;

  // VULNERABLE: eval executes arbitrary user-supplied JavaScript
  const result = eval(userInput);
  res.json({ result });
});

app.listen(3000);

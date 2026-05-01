// VULNERABLE: req-body-no-validation — req.body accessed without any validation
// Rule: InputReqBodyNoValidation | CWE-20 | Severity: MEDIUM

const express = require('express');

const app = express();
app.use(express.json());

app.post('/register', (req, res) => {
  // VULNERABLE: req.body fields used directly without express-validator, joi, or zod
  const username = req.body.username;
  const email = req.body.email;
  const age = req.body.age;

  // No type checks, length limits, or format validation
  res.json({ registered: true, username, email, age });
});

app.listen(3000);

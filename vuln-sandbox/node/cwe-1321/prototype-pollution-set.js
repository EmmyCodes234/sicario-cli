// VULNERABLE: prototype-pollution-set — dynamic property assignment from user input
// Rule: PrototypePollutionSet | CWE-1321 | Severity: HIGH

const express = require('express');

const app = express();
app.use(express.json());

const config = {};

app.post('/config', (req, res) => {
  // VULNERABLE: user-controlled key allows setting __proto__, constructor, etc.
  config[req.body.key] = req.body.value;
  res.json({ saved: true });
});

app.listen(3000);

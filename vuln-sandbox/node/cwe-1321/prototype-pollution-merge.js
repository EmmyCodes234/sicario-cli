// VULNERABLE: prototype-pollution-merge — Object.assign with unsanitized req.body
// Rule: PrototypePollutionMerge | CWE-1321 | Severity: HIGH

const express = require('express');

const app = express();
app.use(express.json());

app.post('/settings', (req, res) => {
  const userSettings = {};

  // VULNERABLE: Object.assign with req.body allows __proto__ pollution
  Object.assign(userSettings, req.body);

  res.json({ saved: true, settings: userSettings });
});

app.listen(3000);

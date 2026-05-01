// VULNERABLE: xpath-injection — XPath query built with string concatenation of user input
// Rule: InjectXpath | CWE-643 | Severity: HIGH

const express = require('express');
const xpath = require('xpath');
const { DOMParser } = require('xmldom');

const app = express();
app.use(express.json());

const xmlDoc = new DOMParser().parseFromString(
  '<users><user><name>admin</name><role>admin</role></user></users>'
);

app.get('/user', (req, res) => {
  const username = req.query.name;

  // VULNERABLE: user input concatenated into XPath expression — allows XPath injection
  const expression = "//user[name='" + username + "']";
  const nodes = xpath.select(expression, xmlDoc);

  res.json({ found: nodes.length > 0 });
});

app.listen(3000);

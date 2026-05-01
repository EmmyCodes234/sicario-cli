// VULNERABLE: ldap-injection — LDAP filter built with string concatenation of user input
// Rule: InjectLdap | CWE-90 | Severity: HIGH

const express = require('express');
const ldap = require('ldapjs');

const app = express();
app.use(express.json());

const client = ldap.createClient({ url: 'ldap://localhost:389' });

app.post('/login', (req, res) => {
  const username = req.body.username;

  // VULNERABLE: user input concatenated directly into LDAP filter — allows filter injection
  const filter = '(&(objectClass=user)(uid=' + username + '))';

  client.search('dc=example,dc=com', { filter }, (err, searchRes) => {
    if (err) return res.status(500).json({ error: err.message });
    const entries = [];
    searchRes.on('searchEntry', (entry) => entries.push(entry.object));
    searchRes.on('end', () => res.json({ entries }));
  });
});

app.listen(3000);

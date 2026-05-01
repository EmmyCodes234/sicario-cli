// VULNERABLE: sql-template-string — Template literal SQL with user input
// Rule: SqlTemplateString | CWE-89 | Severity: CRITICAL

const express = require('express');
const mysql = require('mysql2');

const app = express();
const db = mysql.createConnection({ host: 'localhost', user: 'root', database: 'app' });

app.get('/user/:id', (req, res) => {
  // VULNERABLE: template literal interpolates user input directly into SQL query
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  db.query(query, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(results);
  });
});

app.listen(3000);

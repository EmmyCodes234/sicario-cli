// VULNERABLE: path-traversal — path.join without startsWith validation
// Rule: InputPathTraversal | CWE-22 | Severity: HIGH

const express = require('express');
const path = require('path');
const fs = require('fs');

const app = express();
const baseDir = path.join(__dirname, 'public');

app.get('/file/:filename', (req, res) => {
  // VULNERABLE: no check that resolved path stays within baseDir
  const filePath = path.join(baseDir, req.params.filename);
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) return res.status(404).json({ error: 'File not found' });
    res.send(data);
  });
});

app.listen(3000);

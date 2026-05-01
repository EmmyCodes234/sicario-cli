// VULNERABLE: session-fixation — session ID not regenerated after login
// Rule: AuthSessionFixation | CWE-384 | Severity: HIGH

const express = require('express');
const session = require('express-session');

const app = express();
app.use(express.json());
app.use(session({ secret: 'keyboard cat', resave: false, saveUninitialized: true }));

app.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (username === 'admin' && password === 'secret') {
    // VULNERABLE: session ID not regenerated — attacker can fixate session before login
    req.session.userId = username;
    req.session.authenticated = true;
    res.json({ success: true });
  } else {
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

app.listen(3000);

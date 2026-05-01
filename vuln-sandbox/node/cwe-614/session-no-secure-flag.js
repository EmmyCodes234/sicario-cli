// VULNERABLE: session-no-secure-flag — express-session without secure cookie flag
// Rule: AuthSessionNoSecureFlag | CWE-614 | Severity: MEDIUM

const express = require('express');
const session = require('express-session');

const app = express();

// VULNERABLE: secure flag missing — session cookie transmitted over plain HTTP
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true,
  cookie: {
    httpOnly: true,
    maxAge: 3600000,
  },
}));

app.get('/', (req, res) => {
  res.send('Hello!');
});

app.listen(3000);

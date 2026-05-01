// VULNERABLE: session-no-httponly — express-session without httpOnly cookie flag
// Rule: AuthSessionNoHttpOnly | CWE-1004 | Severity: MEDIUM

const express = require('express');
const session = require('express-session');

const app = express();

// VULNERABLE: httpOnly not set to true — session cookie accessible via JavaScript (XSS risk)
app.use(session({
  secret: 'keyboard cat',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: true,
    maxAge: 3600000,
  },
}));

app.get('/', (req, res) => {
  res.send('Hello!');
});

app.listen(3000);

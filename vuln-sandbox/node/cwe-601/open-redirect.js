// VULNERABLE: open-redirect — window.location.href set to user-controlled input
// Rule: ReactWindowLocation | CWE-601 | Severity: MEDIUM

const express = require('express');

const app = express();

app.get('/redirect', (req, res) => {
  const userInput = req.query.url;

  // VULNERABLE: user-controlled URL used in open redirect — enables phishing attacks
  const html = `
    <html><body>
      <script>
        window.location.href = ${JSON.stringify(userInput)};
      </script>
    </body></html>
  `;
  res.send(html);
});

app.listen(3000);

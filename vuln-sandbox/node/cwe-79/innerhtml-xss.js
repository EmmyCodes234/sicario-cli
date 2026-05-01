// VULNERABLE: innerhtml-xss — innerHTML assigned from user-controlled input
// Rule: DomInnerHTML | CWE-79 | Severity: HIGH

const express = require('express');

const app = express();
app.use(express.json());

app.get('/render', (req, res) => {
  const userInput = req.query.message;

  // VULNERABLE: innerHTML assignment with unsanitized user input enables XSS
  const html = `
    <html><body>
      <div id="x"></div>
      <script>
        document.getElementById('x').innerHTML = ${JSON.stringify(userInput)};
      </script>
    </body></html>
  `;
  res.send(html);
});

app.listen(3000);

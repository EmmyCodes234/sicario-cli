// VULNERABLE: command-injection — spawn with shell:true and user-controlled command
// Rule: InjectChildProcessShellTrue | CWE-78 | Severity: CRITICAL

const express = require('express');
const { spawn } = require('child_process');

const app = express();
app.use(express.json());

app.post('/run', (req, res) => {
  const cmd = req.body.command;
  const args = req.body.args || [];

  // VULNERABLE: shell:true allows shell metacharacter injection
  const proc = spawn(cmd, args, { shell: true });

  let output = '';
  proc.stdout.on('data', (data) => { output += data.toString(); });
  proc.stderr.on('data', (data) => { output += data.toString(); });
  proc.on('close', (code) => {
    res.json({ output, exitCode: code });
  });
});

app.listen(3000);

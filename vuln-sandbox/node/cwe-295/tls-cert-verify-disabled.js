// VULNERABLE: tls-cert-verify-disabled — rejectUnauthorized:false disables cert validation
// Rule: TlsCertVerifyDisabledNode | CWE-295 | Severity: HIGH

const https = require('https');

// VULNERABLE: rejectUnauthorized:false allows MITM attacks by accepting any certificate
const options = {
  hostname: 'api.example.com',
  port: 443,
  path: '/data',
  method: 'GET',
  rejectUnauthorized: false,
};

const req = https.request(options, (res) => {
  let data = '';
  res.on('data', (chunk) => { data += chunk; });
  res.on('end', () => { console.log(data); });
});

req.end();

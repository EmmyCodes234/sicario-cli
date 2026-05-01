// VULNERABLE: tls-min-version — TLS server configured with deprecated TLSv1
// Rule: TlsMinVersion | CWE-326 | Severity: HIGH

const tls = require('tls');
const fs = require('fs');

// VULNERABLE: TLSv1_method is deprecated and insecure (POODLE, BEAST attacks)
const server = tls.createServer({
  secureProtocol: 'TLSv1_method',
  key: fs.readFileSync('server-key.pem'),
  cert: fs.readFileSync('server-cert.pem'),
}, (socket) => {
  socket.write('Hello, TLS!\n');
  socket.pipe(socket);
});

server.listen(8443);

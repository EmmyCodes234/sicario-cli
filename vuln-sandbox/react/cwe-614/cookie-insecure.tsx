// VULNERABLE: WebCookieInsecure — session cookie set via document.cookie without Secure flag
// Rule: WebCookieInsecure | CWE-614 (Sensitive Cookie in HTTPS Session Without 'Secure' Attribute)
// Pattern: document.cookie = 'session=' + token omits Secure and HttpOnly flags, exposing the cookie over HTTP and to JS

import React, { useState } from 'react';

const SessionManager: React.FC = () => {
  const [token, setToken] = useState<string>('');
  const [status, setStatus] = useState<string>('');

  const saveSession = () => {
    if (token.trim()) {
      // VULNERABLE: cookie set without Secure flag (transmittable over plain HTTP)
      // and without HttpOnly flag (readable by JavaScript — XSS risk)
      document.cookie = 'session=' + token;
      setStatus('Session saved');
    }
  };

  const clearSession = () => {
    document.cookie = 'session=; expires=Thu, 01 Jan 1970 00:00:00 UTC';
    setToken('');
    setStatus('Session cleared');
  };

  return (
    <div className="session-manager">
      <h2>Session Manager</h2>
      <input
        type="text"
        value={token}
        onChange={(e) => setToken(e.target.value)}
        placeholder="Enter session token"
      />
      <button onClick={saveSession}>Save Session</button>
      <button onClick={clearSession}>Clear Session</button>
      {status && <p>{status}</p>}
    </div>
  );
};

export default SessionManager;

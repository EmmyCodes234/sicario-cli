// VULNERABLE: DomPostMessageWildcard — postMessage sent with wildcard target origin '*'
// Rule: DomPostMessageWildcard | CWE-346 (Origin Validation Error)
// Pattern: window.postMessage(data, '*') allows any origin to receive sensitive message data

import React, { useState } from 'react';

const IframeMessenger: React.FC = () => {
  const [message, setMessage] = useState<string>('');
  const [authToken] = useState<string>('eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.example');

  const sendMessage = () => {
    const payload = {
      type: 'AUTH_TOKEN',
      token: authToken,
      data: message,
    };

    // VULNERABLE: '*' wildcard origin means any page (including attacker-controlled iframes)
    // can receive this message, potentially leaking the auth token
    window.postMessage(payload, '*');
  };

  return (
    <div className="messenger">
      <h2>Send Message to Embedded Frame</h2>
      <input
        type="text"
        value={message}
        onChange={(e) => setMessage(e.target.value)}
        placeholder="Enter message content"
      />
      <button onClick={sendMessage}>Send</button>
      <iframe
        src="/embedded-widget"
        title="Embedded Widget"
        style={{ width: '100%', height: '300px' }}
      />
    </div>
  );
};

export default IframeMessenger;

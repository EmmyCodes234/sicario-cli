// VULNERABLE: ReactWindowLocation — user-controlled input used in window.location.href (open redirect)
// Rule: ReactWindowLocation | CWE-601 (URL Redirection to Untrusted Site)
// Pattern: window.location.href = userInput redirects to any attacker-supplied URL

import React, { useState } from 'react';

const RedirectHandler: React.FC = () => {
  const [userInput, setUserInput] = useState<string>('');

  const handleRedirect = () => {
    if (userInput.trim()) {
      // VULNERABLE: no validation — attacker can redirect to any URL (phishing, credential harvesting)
      window.location.href = userInput;
    }
  };

  return (
    <div className="redirect-form">
      <h2>Continue to Resource</h2>
      <p>Enter the URL you were trying to reach:</p>
      <input
        type="text"
        value={userInput}
        onChange={(e) => setUserInput(e.target.value)}
        placeholder="https://example.com/resource"
      />
      <button onClick={handleRedirect}>Continue</button>
    </div>
  );
};

export default RedirectHandler;

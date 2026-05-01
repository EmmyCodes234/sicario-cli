// VULNERABLE: ReactHrefJavascript — user-controlled href without URL scheme validation
// Rule: ReactHrefJavascript | CWE-79 (Cross-Site Scripting)
// Pattern: href={userInput} allows javascript: URIs that execute XSS payloads on click

import React, { useState } from 'react';

interface LinkItem {
  label: string;
  url: string;
}

const UserLinkList: React.FC = () => {
  const [userInput, setUserInput] = useState<string>('');
  const [links, setLinks] = useState<LinkItem[]>([]);

  const addLink = () => {
    if (userInput.trim()) {
      setLinks((prev) => [...prev, { label: userInput, url: userInput }]);
      setUserInput('');
    }
  };

  return (
    <div className="link-list">
      <h2>User Links</h2>
      <input
        type="text"
        value={userInput}
        onChange={(e) => setUserInput(e.target.value)}
        placeholder="Enter a URL"
      />
      <button onClick={addLink}>Add Link</button>
      <ul>
        {links.map((link, idx) => (
          <li key={idx}>
            {/* VULNERABLE: href={link.url} with no scheme validation allows javascript: URIs */}
            <a href={link.url}>{link.label}</a>
          </li>
        ))}
      </ul>
    </div>
  );
};

export default UserLinkList;

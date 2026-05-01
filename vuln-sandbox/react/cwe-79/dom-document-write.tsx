// VULNERABLE: DomDocumentWrite — user-controlled input passed to document.write()
// Rule: DomDocumentWrite | CWE-79 (Cross-Site Scripting)
// Pattern: document.write(userInput) injects raw HTML/script into the document without sanitization

import React, { useState } from 'react';

const DocumentWriter: React.FC = () => {
  const [userInput, setUserInput] = useState<string>('');

  const handleWrite = () => {
    // VULNERABLE: document.write() with unsanitized user input enables XSS
    document.write(userInput);
  };

  return (
    <div className="doc-writer">
      <h2>Page Content Injector</h2>
      <textarea
        value={userInput}
        onChange={(e) => setUserInput(e.target.value)}
        placeholder="Enter HTML content to write to the page"
        rows={5}
      />
      <button onClick={handleWrite}>Write to Document</button>
    </div>
  );
};

export default DocumentWriter;

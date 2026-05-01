// VULNERABLE: ReactDangerouslySetInnerHTML — unsanitized user input rendered via dangerouslySetInnerHTML
// Rule: ReactDangerouslySetInnerHTML | CWE-79 (Cross-Site Scripting)
// Pattern: dangerouslySetInnerHTML={{ __html: userInput }} passes attacker-controlled HTML directly to the DOM

import React, { useState } from 'react';

interface CommentProps {
  initialContent?: string;
}

const CommentRenderer: React.FC<CommentProps> = ({ initialContent = '' }) => {
  const [userInput, setUserInput] = useState<string>(initialContent);

  return (
    <div className="comment-container">
      <textarea
        value={userInput}
        onChange={(e) => setUserInput(e.target.value)}
        placeholder="Enter comment (HTML allowed)"
        rows={4}
      />
      {/* VULNERABLE: userInput is rendered as raw HTML without sanitization */}
      <div
        className="comment-body"
        dangerouslySetInnerHTML={{ __html: userInput }}
      />
    </div>
  );
};

export default CommentRenderer;

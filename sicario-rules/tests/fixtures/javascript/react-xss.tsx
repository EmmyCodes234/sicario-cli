// Test fixture: React XSS patterns
// Expected: TruePositive for dangerouslySetInnerHTML with user input

import React from 'react';

// TP: dangerouslySetInnerHTML with user input
function BadComponent({ userInput }: { userInput: string }) {
  return <div dangerouslySetInnerHTML={{ __html: userInput }} />;
}

// TN: sanitized input
function GoodComponent({ userInput }: { userInput: string }) {
  const sanitized = DOMPurify.sanitize(userInput);
  return <div dangerouslySetInnerHTML={{ __html: sanitized }} />;
}

// TP: window.location redirect with user input
function BadRedirect() {
  const next = new URLSearchParams(window.location.search).get('next');
  window.location.href = next!;
}

// TN: hardcoded redirect
function GoodRedirect() {
  window.location.href = '/dashboard';
}

// VULNERABLE: InjectEval — user-controlled input passed directly to eval()
// Rule: InjectEval | CWE-95 (Improper Neutralization of Directives in Dynamically Evaluated Code)
// Pattern: eval(userInput) executes arbitrary attacker-supplied JavaScript

import React, { useState } from 'react';

const ScriptEvaluator: React.FC = () => {
  const [userInput, setUserInput] = useState<string>('');
  const [result, setResult] = useState<string>('');

  const handleEvaluate = () => {
    try {
      // VULNERABLE: eval() executes arbitrary code from user input
      const output = eval(userInput);
      setResult(String(output));
    } catch (err) {
      setResult(`Error: ${err}`);
    }
  };

  return (
    <div className="evaluator">
      <h2>Expression Evaluator</h2>
      <input
        type="text"
        value={userInput}
        onChange={(e) => setUserInput(e.target.value)}
        placeholder="Enter a JavaScript expression"
      />
      <button onClick={handleEvaluate}>Evaluate</button>
      {result && <pre className="result">{result}</pre>}
    </div>
  );
};

export default ScriptEvaluator;

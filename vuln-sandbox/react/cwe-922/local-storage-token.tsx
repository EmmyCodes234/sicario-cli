// VULNERABLE: ReactLocalStorageToken — auth token stored in localStorage (XSS-accessible)
// Rule: ReactLocalStorageToken | CWE-922 (Insecure Storage of Sensitive Information)
// Pattern: localStorage.setItem('token', authToken) exposes the token to any XSS payload on the page

import React, { useState } from 'react';

interface LoginResponse {
  token: string;
  userId: string;
}

const LoginForm: React.FC = () => {
  const [username, setUsername] = useState<string>('');
  const [password, setPassword] = useState<string>('');
  const [status, setStatus] = useState<string>('');

  const handleLogin = async () => {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });

    if (response.ok) {
      const data: LoginResponse = await response.json();
      // VULNERABLE: auth token stored in localStorage — readable by any JS on the page (XSS risk)
      localStorage.setItem('token', data.token);
      setStatus('Logged in successfully');
    } else {
      setStatus('Login failed');
    }
  };

  return (
    <div className="login-form">
      <h2>Sign In</h2>
      <input
        type="text"
        value={username}
        onChange={(e) => setUsername(e.target.value)}
        placeholder="Username"
      />
      <input
        type="password"
        value={password}
        onChange={(e) => setPassword(e.target.value)}
        placeholder="Password"
      />
      <button onClick={handleLogin}>Login</button>
      {status && <p>{status}</p>}
    </div>
  );
};

export default LoginForm;

// VULNERABLE: WebCorsWildcard — CORS configured with wildcard origin in a Next.js API route
// Rule: WebCorsWildcard | CWE-942 (Permissive Cross-domain Policy with Untrusted Domains)
// Pattern: origin: '*' in CORS config allows any domain to make credentialed cross-origin requests

import type { NextApiRequest, NextApiResponse } from 'next';

interface ApiData {
  userId: string;
  email: string;
  role: string;
}

// VULNERABLE: CORS wildcard allows any origin to read the response, including sensitive user data
function setCorsHeaders(res: NextApiResponse): void {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
}

export default function handler(
  req: NextApiRequest,
  res: NextApiResponse<ApiData | { error: string }>
) {
  setCorsHeaders(res);

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method === 'GET') {
    res.status(200).json({
      userId: 'usr_12345',
      email: 'user@example.com',
      role: 'admin',
    });
  } else {
    res.status(405).json({ error: 'Method not allowed' });
  }
}

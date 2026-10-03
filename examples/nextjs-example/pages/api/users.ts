/**
 * Example: Next.js Pages Router API Handler
 * File: pages/api/users/[id].ts
 */

import { withNextGuardPages } from 'nextguard';
import type { NextApiRequest, NextApiResponse } from 'next';

async function handler(req: NextApiRequest, res: NextApiResponse) {
  const { id } = req.query;

  if (req.method === 'GET') {
    res.status(200).json({ user: { id, name: 'John Doe' } });
  } else if (req.method === 'PUT') {
    const { name } = req.body;
    res.status(200).json({ user: { id, name } });
  } else {
    res.status(405).json({ error: 'Method not allowed' });
  }
}

export default withNextGuardPages(handler, {
  rateLimit: {
    windowMs: 60 * 1000,
    max: 50,
  },
  sqlInjection: { enabled: true },
  xss: { enabled: true },
  pathTraversal: { enabled: true },
  commandInjection: { enabled: true },
  securityHeaders: {
    enabled: true,
    xFrameOptions: 'DENY',
    contentSecurityPolicy: "default-src 'self'; script-src 'self'",
  },
});

/**
 * NextGuard — Usage Examples
 * Run: node examples/basic.js
 */
'use strict';

const http = require('http');
const nextguard = require('../nextguard');

// ─── Example 1: Next.js App Router (Conceptual example of middleware.ts) ────
function nextJsExample() {
  console.log(`
// ==========================================
// Next.js: middleware.ts (in your project root)
// ==========================================
import { nextguard } from '@nixxeltzy/nextguard';

// 1. Zero-config protection for any paths:
export const middleware = nextguard({
  telegram: {
    enabled: true, // auto-detects process.env.TELEGRAM_BOT_TOKEN & TELEGRAM_CHAT_ID
  }
});

// 2. You have 100% control over which paths to protect:
export const config = {
  matcher: ['/:path*'], // protect everything!
  // or specific paths:
  // matcher: ['/api/:path*', '/dashboard/:path*', '/admin/:path*'],
};
  `);
}

// ─── Example 2: Express with Path-Agnostic Routes ───────────────────────────
function expressExample() {
  try {
    const express = require('express');
    const app = express();

    // Attach NextGuard as top-level middleware
    app.use(nextguard({
      logLevel: 'info',
      layer2: { maxRequests: 80, windowMs: 60_000 },
      telegram: {
        enabled: Boolean(process.env.TELEGRAM_BOT_TOKEN),
        botToken: process.env.TELEGRAM_BOT_TOKEN,
        chatId: process.env.TELEGRAM_CHAT_ID,
      },
    }));

    // Developer freely defines any routes — NextGuard does NOT intercept them!
    app.get('/', (req, res) => res.json({ status: 'ok', route: '/' }));
    app.get('/login', (req, res) => res.json({ route: '/login' }));
    app.get('/dashboard', (req, res) => res.json({ route: '/dashboard' }));
    app.get('/admin', (req, res) => res.json({ route: '/admin' }));
    app.get('/api/users', (req, res) => res.json({ users: ['Alice', 'Bob'] }));
    app.get('/custom-path/:id', (req, res) => res.json({ id: req.params.id }));

    app.listen(3000, () => {
      console.log('Express running on http://localhost:3000 with NextGuard protection');
    });
  } catch {
    // Express is optional for this demo script
  }
}

// ─── Example 3: Raw Node.js HTTP Server ────────────────────────────────────
function rawHttpExample() {
  const guard = nextguard.createNextGuard({
    logLevel: 'info',
    layer2: { maxRequests: 100 },
    layer5: { inspectQuery: true, inspectBody: true },
    telegram: {
      enabled: Boolean(process.env.TELEGRAM_BOT_TOKEN),
      botToken: process.env.TELEGRAM_BOT_TOKEN,
      chatId: process.env.TELEGRAM_CHAT_ID,
    },
  });

  guard.events.on('threat', ({ ip, layer, reason, path }) => {
    console.error(`\x1b[31m[THREAT]\x1b[0m Layer ${layer} blocked ${ip} on path ${path}: ${reason}`);
  });

  const server = http.createServer(
    guard.handler((req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({
        message: 'Protected by NextGuard!',
        path: req.url,
        stats: guard.getStats(),
      }, null, 2));
    })
  );

  server.listen(3001, () => {
    console.log('Raw HTTP server running on http://localhost:3001');
    console.log('Try visiting: http://localhost:3001/dashboard');
    console.log('Try visiting: http://localhost:3001/admin');
    console.log('Try SQLi attack: curl "http://localhost:3001/api?q=\' UNION SELECT * FROM users--"');
  });
}

// Run demonstrations
nextJsExample();
rawHttpExample();
expressExample();

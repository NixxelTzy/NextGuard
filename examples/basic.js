/**
 * NextGuard — Basic Usage Examples
 * Run: node examples/basic.js
 */
'use strict';

const http = require('http');
const { createNextGuard } = require('../nextguard');

// ─── Example 1: Express App ─────────────────────────────────────────────────
function expressExample() {
  // Requires: npm install express
  try {
    const express = require('express');
    const app = express();

    const guard = createNextGuard({
      logLevel: 'info',
      layer2: { maxRequests: 60, windowMs: 60_000 },
      layer7: {
        tarpitEnabled: true,
        tarpitDelayMs: 5_000,
        honeypotPaths: ['/.env', '/wp-admin', '/phpmyadmin'],
      },
    });

    // Listen to threats
    guard.events.on('threat', ({ ip, layer, reason }) => {
      console.log(`\x1b[31m[THREAT]\x1b[0m Layer ${layer} | ${ip} | ${reason}`);
    });

    app.use(express.json());
    app.use(guard.middleware);

    app.get('/', (req, res) => res.json({ message: 'Protected by NextGuard 🛡️' }));
    app.get('/stats', (req, res) => res.json(guard.getStats()));

    app.listen(3000, () => {
      console.log('Express server protected by NextGuard on http://localhost:3000');
    });
  } catch {
    console.log('Express not installed, skipping expressExample.');
  }
}

// ─── Example 2: Raw Node.js HTTP Server ────────────────────────────────────
function rawHttpExample() {
  const guard = createNextGuard({
    logLevel: 'debug',
    layer2: { maxRequests: 100 },
    layer4: { blockMaliciousUA: true },
    layer5: { inspectQuery: true, inspectBody: true },
    layer7: {
      tarpitEnabled: true,
      honeypotPaths: ['/.env', '/.git/HEAD', '/admin', '/wp-admin'],
    },
  });

  guard.events.on('threat', ({ ip, layer, reason }) => {
    console.error(`[THREAT] Layer ${layer} | IP: ${ip} | ${reason}`);
  });

  const server = http.createServer(
    guard.handler((req, res) => {
      if (req.url === '/stats') {
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify(guard.getStats(), null, 2));
        return;
      }
      res.setHeader('Content-Type', 'text/plain');
      res.end('Hello from NextGuard-protected server!');
    })
  );

  server.listen(3001, () => {
    console.log('Raw HTTP server protected by NextGuard on http://localhost:3001');
    console.log('Stats: http://localhost:3001/stats');
    console.log('Try: curl http://localhost:3001/.env  ← honeypot!');
    console.log('Try: curl "http://localhost:3001/?q=\' OR 1=1--"  ← SQLi!');
  });
}

// ─── Example 3: Admin API Usage ────────────────────────────────────────────
function adminApiExample() {
  const guard = createNextGuard({ logLevel: 'info' });

  // Manually ban an IP for 1 hour
  guard.ban('192.168.1.100', { durationMs: 3_600_000, reason: 'manual-test' });
  console.log('Banned 192.168.1.100');

  // Get stats
  const stats = guard.getStats();
  console.log('Stats:', JSON.stringify(stats, null, 2));

  // Unban
  guard.unban('192.168.1.100');
  console.log('Unbanned 192.168.1.100');

  // Switch to lockdown mode
  guard.setMode('lockdown');
  console.log('Mode → lockdown');

  // Back to normal
  guard.setMode('protect');
  console.log('Mode → protect');

  // Add CIDR to blacklist
  guard.addToBlacklist('10.0.0.0/8');
  console.log('Blacklisted 10.0.0.0/8');
}

// Run examples
rawHttpExample();
adminApiExample();
// expressExample(); // Uncomment if you have express installed

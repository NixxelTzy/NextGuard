'use strict';

const http = require('http');
const nextguard = require('../nextguard');

function rawHttpExample() {
  const guard = nextguard.createNextGuard({
    logLevel: 'info',
    layer2: { maxRequests: 240 },
    layer5: { inspectQuery: true, inspectBody: true },
    telegram: {
      enabled: Boolean(process.env.TELEGRAM_BOT_TOKEN),
      botToken: process.env.TELEGRAM_BOT_TOKEN,
      chatId: process.env.TELEGRAM_CHAT_ID,
    },
  });

  guard.events.on('threat', ({ ip, layer, reason, path }) => {
    console.error(`Layer ${layer} blocked ${ip} on path ${path}: ${reason}`);
  });

  const server = http.createServer(
    guard.handler((req, res) => {
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({
        status: 'ok',
        path: req.url,
        stats: guard.getStats(),
      }));
    })
  );

  server.listen(3001);
}

rawHttpExample();

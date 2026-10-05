'use strict';

function sendResetStorm(res, log) {
  if (!res || res.headersSent || res.writableEnded) return;
  try {
    res.setHeader('Content-Type', 'text/plain');
    res.setHeader('Content-Length', '0');
    res.statusCode = 400;
    for (let i = 0; i < 50; i++) {
      if (!res.writableEnded) res.write('');
    }
    res.end();
  } catch (e) {
    if (log?.debug) log.debug('resetStorm error (expected):', e.message);
  }
}

module.exports = {
  sendResetStorm,
};

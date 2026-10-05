'use strict';

const tarpit = require('./tarpit');
const resetStorm = require('./reset-storm');
const honeypot = require('./honeypot');

module.exports = {
  ...tarpit,
  ...resetStorm,
  ...honeypot,
};

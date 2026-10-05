'use strict';

const ipGate = require('./ip-gate');
const botDetector = require('./bot-detector');

module.exports = {
  ...ipGate,
  ...botDetector,
};

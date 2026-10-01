'use strict';

const path = require('path');

const PROJECT_ROOT = path.resolve(__dirname, '../..');

module.exports = {
  PORT: Number(process.env.PORT || 3000),
  AI_SERVICE_URL: process.env.AI_SERVICE_URL || 'http://127.0.0.1:8000',
  PROJECT_ROOT,
  POLL_INTERVAL_MS: Number(process.env.POLL_INTERVAL_MS || 2000),
  // Analysis of multi-GB NIST image can take a long time
  ANALYSIS_TIMEOUT_MS: Number(process.env.ANALYSIS_TIMEOUT_MS || 60 * 60 * 1000),
};

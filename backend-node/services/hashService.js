'use strict';

/**
 * Local SHA-256 / path helpers used by the orchestrator.
 * Full disk re-hashing is done in Python (streaming); this module stays light.
 */

const crypto = require('crypto');
const path = require('path');

function sha256Hex(text) {
  return crypto.createHash('sha256').update(String(text), 'utf8').digest('hex');
}

function evidenceIdForCase(caseId) {
  return `EV_${caseId}`;
}

function imageNameFromPath(imagePath) {
  return path.basename(imagePath || 'unknown');
}

function utcNow() {
  return new Date().toISOString();
}

module.exports = {
  sha256Hex,
  evidenceIdForCase,
  imageNameFromPath,
  utcNow,
};

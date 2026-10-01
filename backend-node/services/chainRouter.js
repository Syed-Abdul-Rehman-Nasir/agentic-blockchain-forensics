'use strict';

// Selects Hyperledger Fabric or the SQLite mock chain based on USE_REAL_FABRIC.

const USE_REAL_FABRIC = process.env.USE_REAL_FABRIC === 'true';

let chain;
if (USE_REAL_FABRIC) {
  chain = require('./fabricService');
  console.log('[chain] Using real Hyperledger Fabric gateway');
} else {
  chain = require('./mockChain');
  console.log('[chain] Using mock hash chain (SQLite)');
}

module.exports = chain;

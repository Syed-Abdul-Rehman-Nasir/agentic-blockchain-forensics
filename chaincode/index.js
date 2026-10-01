'use strict';

// Chaincode entrypoint: exports ForensicContract for the Fabric peer runtime.

const ForensicContract = require('./lib/forensicContract');

module.exports.ForensicContract = ForensicContract;
module.exports.contracts = [ForensicContract];

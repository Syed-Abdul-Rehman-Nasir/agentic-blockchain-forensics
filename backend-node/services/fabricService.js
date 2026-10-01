'use strict';

// Real Hyperledger Fabric Gateway client for forensiccc.
// Loaded when USE_REAL_FABRIC=true via chainRouter; otherwise mockChain is used.
// Blockchain calls must never block the AI pipeline — callers wrap in try/catch.

/**
 * Hyperledger Fabric gateway wrappers for forensiccc.
 */

const grpc = require('@grpc/grpc-js');
const { connect, hash, signers } = require('@hyperledger/fabric-gateway');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { TextDecoder } = require('util');

const utf8Decoder = new TextDecoder();

const CHANNEL_NAME = process.env.CHANNEL_NAME || 'forensicchannel';
const CHAINCODE_NAME = process.env.CHAINCODE_NAME || 'forensiccc';
const MSP_ID = process.env.MSP_ID || 'Org1MSP';
const PEER_ENDPOINT = process.env.PEER_ENDPOINT || 'localhost:7051';
const PEER_HOST_ALIAS = process.env.PEER_HOST_ALIAS || 'peer0.org1.example.com';

const CRYPTO_PATH = process.env.CRYPTO_PATH || path.join(
  process.env.HOME,
  'fabric-samples/test-network/organizations/peerOrganizations/org1.example.com'
);

const KEY_DIRECTORY_PATH = process.env.KEY_DIRECTORY_PATH || path.join(
  CRYPTO_PATH, 'users', 'User1@org1.example.com', 'msp', 'keystore'
);
const CERT_DIRECTORY_PATH = process.env.CERT_DIRECTORY_PATH || path.join(
  CRYPTO_PATH, 'users', 'User1@org1.example.com', 'msp', 'signcerts'
);
const TLS_CERT_PATH = process.env.TLS_CERT_PATH || path.join(
  CRYPTO_PATH, 'peers', 'peer0.org1.example.com', 'tls', 'ca.crt'
);

const FABRIC_SETUP_HINT =
  'Run: bash scripts/start-fabric.sh  — or set USE_REAL_FABRIC=false in backend-node/.env for the mock chain.';

let gateway;
let client;
let contract;

function firstFileInDir(dirPath) {
  if (!fs.existsSync(dirPath)) {
    throw new Error(`Fabric identity path missing: ${dirPath}. ${FABRIC_SETUP_HINT}`);
  }
  const files = fs.readdirSync(dirPath);
  if (!files.length) {
    throw new Error(`No files in directory: ${dirPath}. ${FABRIC_SETUP_HINT}`);
  }
  return path.join(dirPath, files[0]);
}

function parseResult(bytes) {
  if (!bytes || bytes.length === 0) {
    return null;
  }
  return JSON.parse(utf8Decoder.decode(bytes));
}

function close() {
  if (gateway) {
    try {
      gateway.close();
    } catch {
      /* ignore */
    }
    gateway = null;
  }
  if (client) {
    try {
      client.close();
    } catch {
      /* ignore */
    }
    client = null;
  }
  contract = null;
}

/** Fail fast when crypto or peer endpoint is missing (avoids opaque 10s deadlines). */
function assertFabricPrereqs() {
  if (!fs.existsSync(TLS_CERT_PATH)) {
    throw new Error(
      `Fabric peer TLS cert not found at ${TLS_CERT_PATH}. Crypto may be incomplete after a partial network down. ${FABRIC_SETUP_HINT}`
    );
  }
  if (!fs.existsSync(KEY_DIRECTORY_PATH) || !fs.existsSync(CERT_DIRECTORY_PATH)) {
    throw new Error(
      `Fabric user MSP material missing under ${CRYPTO_PATH}. ${FABRIC_SETUP_HINT}`
    );
  }
}

function mapFabricError(err) {
  const msg = String(err && err.message ? err.message : err);
  close(); // drop stale gateway so the next call reconnects after fabric restart
  if (err && err.status === 503 && /start-fabric/.test(msg)) {
    return err;
  }
  if (/DEADLINE_EXCEEDED|UNAVAILABLE|ECONNREFUSED|ECONNRESET|14 UNAVAILABLE|connect ECONNREFUSED/i.test(msg)) {
    const e = new Error(
      `Fabric peer unreachable at ${PEER_ENDPOINT} (network down, peer not ready, or only CCAAS leftovers running). ${FABRIC_SETUP_HINT}`
    );
    e.status = 503;
    e.cause = err;
    return e;
  }
  if (/no such file|ENOENT|identity path missing|TLS cert not found|MSP material missing/i.test(msg)) {
    const e = new Error(msg.includes('scripts/start-fabric') ? msg : `${msg} ${FABRIC_SETUP_HINT}`);
    e.status = 503;
    e.cause = err;
    return e;
  }
  return err;
}

/**
 * Establish (or reuse) a gateway connection and return the forensiccc contract.
 */
async function getContract() {
  if (contract) {
    return contract;
  }

  try {
    assertFabricPrereqs();

    const tlsRootCert = fs.readFileSync(TLS_CERT_PATH);
    const tlsCredentials = grpc.credentials.createSsl(tlsRootCert);
    client = new grpc.Client(PEER_ENDPOINT, tlsCredentials, {
      'grpc.ssl_target_name_override': PEER_HOST_ALIAS,
    });

    const credentials = fs.readFileSync(firstFileInDir(CERT_DIRECTORY_PATH));
    const privateKeyPem = fs.readFileSync(firstFileInDir(KEY_DIRECTORY_PATH));
    const privateKey = crypto.createPrivateKey(privateKeyPem);

    gateway = connect({
      client,
      identity: { mspId: MSP_ID, credentials },
      signer: signers.newPrivateKeySigner(privateKey),
      hash: hash.sha256,
      evaluateOptions: () => ({ deadline: Date.now() + 10000 }),
      endorseOptions: () => ({ deadline: Date.now() + 15000 }),
      submitOptions: () => ({ deadline: Date.now() + 10000 }),
      commitStatusOptions: () => ({ deadline: Date.now() + 60000 }),
    });

    contract = gateway.getNetwork(CHANNEL_NAME).getContract(CHAINCODE_NAME);
    return contract;
  } catch (err) {
    close();
    throw mapFabricError(err);
  }
}

async function storeEvidence(evidenceId, acqHash, sysHash, imageName, caseId, timestamp) {
  try {
    const c = await getContract();
    const result = await c.submitTransaction(
      'StoreEvidence',
      evidenceId,
      acqHash,
      sysHash,
      imageName,
      caseId,
      timestamp
    );
    return parseResult(result);
  } catch (err) {
    console.error('[fabricService.storeEvidence]', err.message || err);
    throw mapFabricError(err);
  }
}

async function validateEvidence(evidenceId, currentHash) {
  try {
    const c = await getContract();
    const result = await c.evaluateTransaction('ValidateEvidence', evidenceId, currentHash);
    return parseResult(result);
  } catch (err) {
    console.error('[fabricService.validateEvidence]', err.message || err);
    throw mapFabricError(err);
  }
}

async function getEvidence(evidenceId) {
  try {
    const c = await getContract();
    const result = await c.evaluateTransaction('GetEvidence', evidenceId);
    const parsed = parseResult(result);
    return parsed; // null if not found
  } catch (err) {
    console.error('[fabricService.getEvidence]', err.message || err);
    mapFabricError(err); // reset connection; still return null for callers
    return null;
  }
}

async function logAnalystAction(evidenceId, analystId, action, details, timestamp) {
  try {
    const c = await getContract();
    const result = await c.submitTransaction(
      'LogAnalystAction',
      evidenceId,
      analystId,
      action,
      details,
      timestamp
    );
    return parseResult(result);
  } catch (err) {
    console.error('[fabricService.logAnalystAction]', err.message || err);
    throw mapFabricError(err);
  }
}

async function getAuditTrail(evidenceId) {
  try {
    const c = await getContract();
    const result = await c.evaluateTransaction('GetAuditTrail', evidenceId);
    return parseResult(result);
  } catch (err) {
    console.error('[fabricService.getAuditTrail]', err.message || err);
    throw mapFabricError(err);
  }
}

module.exports = {
  storeEvidence,
  validateEvidence,
  getEvidence,
  logAnalystAction,
  getAuditTrail,
  close,
  getContract,
};

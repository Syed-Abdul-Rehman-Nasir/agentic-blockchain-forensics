'use strict';

/**
 * Tamper-evident mock blockchain (Phase 6 Contingency 1).
 * SQLite hash-linked chain at data/chain.db — same API surface as fabricService.
 * Committee note: real Fabric remains preferred; this fallback proves integrity
 * when the Docker network cannot run.
 */

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');

const DB_PATH = process.env.MOCK_CHAIN_DB || path.join(
  __dirname,
  '..',
  '..',
  'data',
  'chain.db'
);

const GENESIS_PREV = '0000000000000000';

let db = null;

function sha256(text) {
  return crypto.createHash('sha256').update(String(text), 'utf8').digest('hex');
}

function ensureDb() {
  if (db) return db;
  fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
  db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.exec(`
    CREATE TABLE IF NOT EXISTS chain (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      evidenceId TEXT,
      dataHash TEXT,
      prevHash TEXT,
      timestamp TEXT,
      actionType TEXT,
      details TEXT
    );
  `);

  const count = db.prepare('SELECT COUNT(*) AS c FROM chain').get().c;
  if (count === 0) {
    const ts = new Date().toISOString();
    db.prepare(
      `INSERT INTO chain (evidenceId, dataHash, prevHash, timestamp, actionType, details)
       VALUES (?, ?, ?, ?, ?, ?)`
    ).run('GENESIS', sha256('genesis'), GENESIS_PREV, ts, 'GENESIS', 'genesis');
  }
  return db;
}

function lastDataHash(database) {
  const row = database
    .prepare('SELECT dataHash FROM chain ORDER BY id DESC LIMIT 1')
    .get();
  return row ? row.dataHash : GENESIS_PREV;
}

/**
 * Recompute the canonical dataHash for a stored row from its columns.
 */
function recomputeDataHash(row) {
  if (row.actionType === 'GENESIS') {
    return sha256('genesis');
  }
  if (row.actionType === 'STORE') {
    let payload;
    try {
      payload = JSON.parse(row.details || '{}');
    } catch {
      return null;
    }
    return sha256(
      JSON.stringify({
        evidenceId: row.evidenceId,
        acqHash: payload.acqHash,
        sysHash: payload.sysHash,
        imageName: payload.imageName,
        caseId: payload.caseId,
        timestamp: row.timestamp,
      })
    );
  }
  if (row.actionType === 'LOG') {
    let payload;
    try {
      payload = JSON.parse(row.details || '{}');
    } catch {
      return null;
    }
    return sha256(
      JSON.stringify({
        evidenceId: row.evidenceId,
        analystId: payload.analystId,
        action: payload.action,
        details: payload.details,
        timestamp: row.timestamp,
      })
    );
  }
  return null;
}

/**
 * Walk all rows; verify dataHash recomputation and prevHash linkage.
 */
function verifyChainSync() {
  const database = ensureDb();
  const rows = database.prepare('SELECT * FROM chain ORDER BY id ASC').all();
  if (!rows.length) {
    return { intact: false, brokenAt: null };
  }

  let prevHash = GENESIS_PREV;
  for (const row of rows) {
    if (row.prevHash !== prevHash) {
      return { intact: false, brokenAt: row.id };
    }
    const expected = recomputeDataHash(row);
    if (!expected || expected !== row.dataHash) {
      return { intact: false, brokenAt: row.id };
    }
    prevHash = row.dataHash;
  }
  return { intact: true, brokenAt: null };
}

async function storeEvidence(evidenceId, acqHash, sysHash, imageName, caseId, timestamp) {
  const database = ensureDb();
  const existing = database
    .prepare(`SELECT id FROM chain WHERE evidenceId = ? AND actionType = 'STORE'`)
    .get(evidenceId);
  if (existing) {
    throw new Error(`Evidence ${evidenceId} already exists`);
  }

  const ts = timestamp || new Date().toISOString();
  const dataHash = sha256(
    JSON.stringify({
      evidenceId,
      acqHash,
      sysHash,
      imageName,
      caseId,
      timestamp: ts,
    })
  );
  const prevHash = lastDataHash(database);
  const details = JSON.stringify({ acqHash, sysHash, imageName, caseId });

  const info = database
    .prepare(
      `INSERT INTO chain (evidenceId, dataHash, prevHash, timestamp, actionType, details)
       VALUES (?, ?, ?, ?, 'STORE', ?)`
    )
    .run(evidenceId, dataHash, prevHash, ts, details);

  return {
    evidenceId,
    acqHash,
    sysHash,
    stored: true,
    blockIndex: Number(info.lastInsertRowid),
  };
}

async function validateEvidence(evidenceId, currentHash) {
  const database = ensureDb();
  const row = database
    .prepare(
      `SELECT * FROM chain WHERE evidenceId = ? AND actionType = 'STORE' ORDER BY id ASC LIMIT 1`
    )
    .get(evidenceId);

  if (!row) {
    throw new Error(`Evidence ${evidenceId} does not exist`);
  }

  let payload;
  try {
    payload = JSON.parse(row.details || '{}');
  } catch {
    payload = {};
  }
  const storedHash = payload.sysHash;
  const chain = verifyChainSync();
  const hashMatch = storedHash === currentHash;
  const isValid = chain.intact && hashMatch;

  return {
    evidenceId,
    isValid,
    tampered: !isValid,
    storedHash,
    providedHash: currentHash,
    validatedAt: new Date().toISOString(),
    chainIntact: chain.intact,
    brokenAt: chain.brokenAt,
  };
}

function getEvidence(evidenceId) {
  const db = ensureDb();
  const row = db
    .prepare(
      "SELECT * FROM chain WHERE evidenceId = ? AND actionType = 'STORE' LIMIT 1"
    )
    .get(evidenceId);
  if (!row) return null;
  let payload = {};
  try {
    payload = JSON.parse(row.details || '{}');
  } catch {
    return null;
  }
  return {
    evidenceId,
    acquisitionHash: payload.acqHash || '',
    systemHash: payload.sysHash || '',
    imageName: payload.imageName || '',
    caseId: payload.caseId || '',
    timestamp: row.timestamp,
    submittedBy: 'system',
    docType: 'evidence',
  };
}

async function logAnalystAction(evidenceId, analystId, action, details, timestamp) {
  const database = ensureDb();
  const ts = timestamp || new Date().toISOString();
  const dataHash = sha256(
    JSON.stringify({
      evidenceId,
      analystId,
      action,
      details,
      timestamp: ts,
    })
  );
  const prevHash = lastDataHash(database);
  const detailsJson = JSON.stringify({ analystId, action, details });

  const info = database
    .prepare(
      `INSERT INTO chain (evidenceId, dataHash, prevHash, timestamp, actionType, details)
       VALUES (?, ?, ?, ?, 'LOG', ?)`
    )
    .run(evidenceId, dataHash, prevHash, ts, detailsJson);

  return {
    evidenceId,
    analystId,
    action,
    details,
    timestamp: ts,
    docType: 'auditlog',
    blockIndex: Number(info.lastInsertRowid),
  };
}

async function getAuditTrail(evidenceId) {
  const database = ensureDb();
  const rows = database
    .prepare(
      `SELECT * FROM chain
       WHERE evidenceId = ? AND actionType != 'GENESIS'
       ORDER BY id ASC`
    )
    .all(evidenceId);

  return rows.map((row) => {
    if (row.actionType === 'LOG') {
      let payload = {};
      try {
        payload = JSON.parse(row.details || '{}');
      } catch { /* ignore */ }
      return {
        evidenceId: row.evidenceId,
        analystId: payload.analystId,
        action: payload.action,
        details: payload.details,
        timestamp: row.timestamp,
        docType: 'auditlog',
        blockIndex: row.id,
        dataHash: row.dataHash,
      };
    }
    // STORE (and any other) rows for this evidenceId
    let payload = {};
    try {
      payload = JSON.parse(row.details || '{}');
    } catch { /* ignore */ }
    return {
      evidenceId: row.evidenceId,
      analystId: 'system',
      action: 'STORE_EVIDENCE',
      details: JSON.stringify(payload),
      timestamp: row.timestamp,
      docType: 'evidence',
      blockIndex: row.id,
      dataHash: row.dataHash,
    };
  });
}

async function verifyChain() {
  return verifyChainSync();
}

function close() {
  if (db) {
    db.close();
    db = null;
  }
}

module.exports = {
  storeEvidence,
  validateEvidence,
  getEvidence,
  logAnalystAction,
  getAuditTrail,
  verifyChain,
  close,
  // exposed for tests
  _sha256: sha256,
  _dbPath: DB_PATH,
};

'use strict';

/**
 * Offline unit coverage for backend-node/services/mockChain.js.
 * Uses an isolated temp SQLite DB — no Fabric / Docker required.
 */

const { describe, it, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const Database = require('../../backend-node/node_modules/better-sqlite3');

const tmpDb = path.join(
  os.tmpdir(),
  `mock-chain-test-${process.pid}-${Date.now()}.db`
);
process.env.MOCK_CHAIN_DB = tmpDb;

// Load after MOCK_CHAIN_DB is set so DB_PATH binds to the temp file.
const mockChain = require('../../backend-node/services/mockChain');

const EVIDENCE_ID = 'EV_MOCK_UNIT';
const ACQ = 'acq_hash_unit';
const SYS = 'sys_hash_unit';
const TS = '2026-10-13T12:00:00.000Z';

function unlinkDb() {
  for (const suffix of ['', '-wal', '-shm']) {
    try {
      fs.unlinkSync(tmpDb + suffix);
    } catch {
      /* ignore */
    }
  }
}

describe('mockChain offline', () => {
  before(() => {
    unlinkDb();
    mockChain.close();
  });

  after(() => {
    mockChain.close();
    unlinkDb();
  });

  it('storeEvidence persists and getEvidence round-trips', async () => {
    const stored = await mockChain.storeEvidence(
      EVIDENCE_ID,
      ACQ,
      SYS,
      'SCHARDT.001',
      'CASE_UNIT',
      TS
    );
    assert.equal(stored.evidenceId, EVIDENCE_ID);
    assert.equal(stored.stored, true);
    assert.ok(stored.blockIndex >= 2);

    const got = mockChain.getEvidence(EVIDENCE_ID);
    assert.ok(got);
    assert.equal(got.systemHash, SYS);
    assert.equal(got.acquisitionHash, ACQ);
    assert.equal(got.caseId, 'CASE_UNIT');
    assert.equal(got.timestamp, TS);
  });

  it('rejects duplicate evidenceId', async () => {
    await assert.rejects(
      () =>
        mockChain.storeEvidence(
          EVIDENCE_ID,
          ACQ,
          SYS,
          'SCHARDT.001',
          'CASE_UNIT',
          TS
        ),
      /already exists/
    );
  });

  it('validateEvidence accepts matching hash and flags tamper', async () => {
    const ok = await mockChain.validateEvidence(EVIDENCE_ID, SYS);
    assert.equal(ok.isValid, true);
    assert.equal(ok.tampered, false);
    assert.equal(ok.chainIntact, true);

    const bad = await mockChain.validateEvidence(EVIDENCE_ID, 'wrong_hash');
    assert.equal(bad.isValid, false);
    assert.equal(bad.tampered, true);
  });

  it('validateEvidence throws for missing evidence', async () => {
    await assert.rejects(
      () => mockChain.validateEvidence('EV_MISSING', SYS),
      /does not exist/
    );
  });

  it('getEvidence returns null for unknown id', () => {
    assert.equal(mockChain.getEvidence('EV_UNKNOWN'), null);
  });

  it('getAuditTrail is chronological after logAnalystAction', async () => {
    const stamps = [
      '2026-10-13T12:01:00.000Z',
      '2026-10-13T12:02:00.000Z',
      '2026-10-13T12:03:00.000Z',
    ];
    const actions = ['PARSE', 'ANALYSE', 'QUERY'];
    for (let i = 0; i < 3; i++) {
      await mockChain.logAnalystAction(
        EVIDENCE_ID,
        'analyst-unit',
        actions[i],
        `detail-${i}`,
        stamps[i]
      );
    }

    const trail = await mockChain.getAuditTrail(EVIDENCE_ID);
    assert.ok(trail.length >= 4); // STORE + 3 LOGs
    const logs = trail.filter((e) => e.docType === 'auditlog');
    assert.equal(logs.length, 3);
    for (let i = 0; i < 3; i++) {
      assert.equal(logs[i].action, actions[i]);
      assert.equal(logs[i].timestamp, stamps[i]);
    }
    for (let i = 1; i < trail.length; i++) {
      assert.ok(trail[i].blockIndex >= trail[i - 1].blockIndex);
    }
  });

  it('verifyChain reports intact after normal ops', async () => {
    const result = await mockChain.verifyChain();
    assert.deepEqual(result, { intact: true, brokenAt: null });
  });

  it('verifyChain detects tampered dataHash', async () => {
    mockChain.close();
    const db = new Database(tmpDb);
    db.prepare(
      `UPDATE chain SET dataHash = ? WHERE actionType = 'STORE' LIMIT 1`
    ).run('deadbeef'.repeat(8));
    db.close();

    // Re-open via mockChain
    const broken = await mockChain.verifyChain();
    assert.equal(broken.intact, false);
    assert.ok(broken.brokenAt != null);
  });
});

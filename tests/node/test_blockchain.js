'use strict';

/**
 * Phase 6 blockchain integration tests against live forensiccc on forensicchannel.
 * Requires: test-network up, forensiccc committed, CCAAS containers running.
 */

const assert = require('assert');
const path = require('path');

const fabricService = require(path.join(
  __dirname,
  '../../backend-node/services/fabricService'
));

const EVIDENCE_ID = `EV_SDK_${Date.now()}`;
const SYS_HASH = 'sha256_system_hash_for_sdk_test';
const ACQ_HASH = 'md5_acquisition_hash_for_sdk_test';

async function run() {
  console.log(`Using evidenceId=${EVIDENCE_ID}`);

  // 1. storeEvidence
  const stored = await fabricService.storeEvidence(
    EVIDENCE_ID,
    ACQ_HASH,
    SYS_HASH,
    'SCHARDT.001',
    'TEST_NIST',
    '2026-07-31T19:00:00.000Z'
  );
  assert.ok(stored, 'storeEvidence returned null');
  assert.strictEqual(stored.evidenceId, EVIDENCE_ID);
  assert.strictEqual(stored.systemHash, SYS_HASH);
  assert.strictEqual(stored.docType, 'evidence');
  console.log('PASS storeEvidence');

  // 2. validateEvidence — correct hash
  const valid = await fabricService.validateEvidence(EVIDENCE_ID, SYS_HASH);
  assert.strictEqual(valid.isValid, true);
  assert.strictEqual(valid.tampered, false);
  console.log('PASS validateEvidence (valid)');

  // 3. validateEvidence — wrong hash
  const invalid = await fabricService.validateEvidence(EVIDENCE_ID, 'tampered_wrong_hash');
  assert.strictEqual(invalid.isValid, false);
  assert.strictEqual(invalid.tampered, true);
  console.log('PASS validateEvidence (tampered)');

  // 4. three logAnalystAction + chronological getAuditTrail
  const timestamps = [
    '2026-07-31T19:01:00.000Z',
    '2026-07-31T19:02:00.000Z',
    '2026-07-31T19:03:00.000Z',
  ];
  const actions = ['PARSE', 'ANALYSE', 'QUERY'];

  for (let i = 0; i < 3; i++) {
    const entry = await fabricService.logAnalystAction(
      EVIDENCE_ID,
      'analyst-sdk',
      actions[i],
      `details-${i}`,
      timestamps[i]
    );
    assert.strictEqual(entry.action, actions[i]);
    assert.strictEqual(entry.timestamp, timestamps[i]);
  }
  console.log('PASS logAnalystAction x3');

  const trail = await fabricService.getAuditTrail(EVIDENCE_ID);
  assert.ok(Array.isArray(trail), 'audit trail is not an array');
  assert.strictEqual(trail.length, 3, `expected 3 audit entries, got ${trail.length}`);
  for (let i = 0; i < 3; i++) {
    assert.strictEqual(trail[i].timestamp, timestamps[i]);
    assert.strictEqual(trail[i].action, actions[i]);
  }
  console.log('PASS getAuditTrail chronological');

  console.log('\nAll blockchain tests passed.');
}

run()
  .catch((err) => {
    console.error('FAILED:', err);
    process.exitCode = 1;
  })
  .finally(() => {
    fabricService.close();
  });

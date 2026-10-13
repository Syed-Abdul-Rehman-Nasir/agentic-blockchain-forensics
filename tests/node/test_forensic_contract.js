'use strict';

/**
 * In-memory stub tests for chaincode/lib/forensicContract.js.
 * No Fabric runtime or new dependencies required.
 */

const { describe, it, beforeEach } = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');

const ForensicContract = require(
  path.join(__dirname, '../../chaincode/lib/forensicContract')
);

/** Minimal stub of the Fabric transaction context / chaincode stub. */
function createCtx() {
  const state = new Map();
  const stub = {
    async getState(key) {
      const v = state.get(String(key));
      return v ? Buffer.from(v) : Buffer.alloc(0);
    },
    async putState(key, value) {
      state.set(String(key), Buffer.from(value).toString('utf8'));
    },
    createCompositeKey(objectType, attributes) {
      return [objectType, ...attributes].join('\u0000');
    },
    async getStateByPartialCompositeKey(objectType, attributes) {
      const prefix = [objectType, ...attributes].join('\u0000');
      const entries = [...state.entries()]
        .filter(([k]) => k === prefix || k.startsWith(prefix + '\u0000'))
        .sort(([a], [b]) => a.localeCompare(b));
      let i = 0;
      return {
        async next() {
          if (i >= entries.length) return { done: true };
          const [key, value] = entries[i++];
          return {
            done: false,
            value: { key, value: Buffer.from(value) },
          };
        },
        async close() {},
      };
    },
  };
  return {
    stub,
    clientIdentity: { getMSPID: () => 'Org1MSP' },
    _state: state,
  };
}

describe('ForensicContract (in-memory stub)', () => {
  let contract;
  let ctx;

  beforeEach(() => {
    contract = new ForensicContract();
    ctx = createCtx();
  });

  it('StoreEvidence persists and GetEvidence round-trips', async () => {
    const raw = await contract.StoreEvidence(
      ctx,
      'EV1',
      'acq1',
      'sys1',
      'img.E01',
      'CASE1',
      '2026-10-13T10:00:00.000Z'
    );
    const stored = JSON.parse(raw);
    assert.equal(stored.evidenceId, 'EV1');
    assert.equal(stored.systemHash, 'sys1');
    assert.equal(stored.submittedBy, 'Org1MSP');
    assert.equal(stored.docType, 'evidence');

    const got = JSON.parse(await contract.GetEvidence(ctx, 'EV1'));
    assert.equal(got.systemHash, 'sys1');
    assert.equal(got.caseId, 'CASE1');
  });

  it('StoreEvidence rejects duplicate evidenceId', async () => {
    await contract.StoreEvidence(
      ctx,
      'EV1',
      'acq',
      'sys',
      'img.E01',
      'C1',
      '2026-10-13T10:00:00.000Z'
    );
    await assert.rejects(
      () =>
        contract.StoreEvidence(
          ctx,
          'EV1',
          'acq2',
          'sys2',
          'img.E01',
          'C1',
          '2026-10-13T11:00:00.000Z'
        ),
      /already exists/
    );
  });

  it('ValidateEvidence throws when evidence is missing', async () => {
    await assert.rejects(
      () => contract.ValidateEvidence(ctx, 'EV_MISSING', 'sys'),
      /does not exist/
    );
  });

  it('ValidateEvidence reports valid and tampered hashes', async () => {
    await contract.StoreEvidence(
      ctx,
      'EV2',
      'acq',
      'sys_ok',
      'img.E01',
      'C1',
      '2026-10-13T10:00:00.000Z'
    );
    const good = JSON.parse(await contract.ValidateEvidence(ctx, 'EV2', 'sys_ok'));
    assert.equal(good.isValid, true);
    assert.equal(good.tampered, false);

    const bad = JSON.parse(await contract.ValidateEvidence(ctx, 'EV2', 'sys_bad'));
    assert.equal(bad.isValid, false);
    assert.equal(bad.tampered, true);
    assert.equal(bad.storedHash, 'sys_ok');
  });

  it('GetEvidence returns JSON null for unknown id', async () => {
    const raw = await contract.GetEvidence(ctx, 'EV_UNKNOWN');
    assert.equal(raw, JSON.stringify(null));
  });

  it('GetAuditTrail returns entries sorted by timestamp', async () => {
    await contract.LogAnalystAction(
      ctx,
      'EV3',
      'a1',
      'QUERY',
      'later',
      '2026-10-13T12:02:00.000Z'
    );
    await contract.LogAnalystAction(
      ctx,
      'EV3',
      'a1',
      'PARSE',
      'earlier',
      '2026-10-13T12:01:00.000Z'
    );
    await contract.LogAnalystAction(
      ctx,
      'EV3',
      'a1',
      'ANALYSE',
      'mid',
      '2026-10-13T12:01:30.000Z'
    );

    const trail = JSON.parse(await contract.GetAuditTrail(ctx, 'EV3'));
    assert.equal(trail.length, 3);
    assert.deepEqual(
      trail.map((e) => e.action),
      ['PARSE', 'ANALYSE', 'QUERY']
    );
    assert.deepEqual(
      trail.map((e) => e.timestamp),
      [
        '2026-10-13T12:01:00.000Z',
        '2026-10-13T12:01:30.000Z',
        '2026-10-13T12:02:00.000Z',
      ]
    );
  });
});

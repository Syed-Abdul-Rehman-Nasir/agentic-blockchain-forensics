'use strict';

const { describe, it, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const orch = require('../../backend-node/services/orchestratorService');

describe('isInvestigationActive', () => {
  afterEach(() => {
    orch._investigations.clear();
  });

  it('is false when no investigation is tracked', () => {
    assert.equal(orch.isInvestigationActive('CASE_NONE'), false);
  });

  it('is true during analysing and blockchain phases', () => {
    orch._investigations.set('CASE_A', { phase: 'analysing' });
    assert.equal(orch.isInvestigationActive('CASE_A'), true);
    orch._investigations.set('CASE_A', { phase: 'blockchain' });
    assert.equal(orch.isInvestigationActive('CASE_A'), true);
  });

  it('is false for terminal phases', () => {
    orch._investigations.set('CASE_A', { phase: 'done' });
    assert.equal(orch.isInvestigationActive('CASE_A'), false);
    orch._investigations.set('CASE_A', { phase: 'error' });
    assert.equal(orch.isInvestigationActive('CASE_A'), false);
  });
});

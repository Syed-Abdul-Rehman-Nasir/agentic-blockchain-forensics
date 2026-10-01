'use strict';

// Blockchain routes: audit trail and integrity verification for a case.

const express = require('express');
const fabricService = require('../services/chainRouter');
const orchestratorService = require('../services/orchestratorService');
const { evidenceIdForCase } = require('../services/hashService');

const router = express.Router({ mergeParams: true });

/** GET /api/cases/:id/audit — on-chain audit trail (+ sealed genesis event) */
router.get('/audit', async (req, res) => {
  try {
    const evidenceId = evidenceIdForCase(req.params.id);
    const [trail, evidence] = await Promise.all([
      fabricService.getAuditTrail(evidenceId).catch(() => []),
      Promise.resolve(fabricService.getEvidence(evidenceId)).catch(() => null),
    ]);

    const fullTrail = [];

    // Prepend the sealing event if evidence exists on chain
    if (evidence) {
      fullTrail.push({
        evidenceId: evidence.evidenceId,
        analystId: evidence.submittedBy || 'system',
        action: 'EVIDENCE_SEALED',
        details: `Image sealed on blockchain. AcqHash: ${(evidence.acquisitionHash || '').slice(0, 16)}… SysHash: ${(evidence.systemHash || '').slice(0, 16)}…`,
        timestamp: evidence.timestamp,
        docType: 'evidence',
        isGenesisEvent: true,
      });
    }

    // Drop mock STORE_EVIDENCE / evidence docType rows so genesis is not duplicated
    fullTrail.push(
      ...(trail || []).filter(
        (e) => e.action !== 'STORE_EVIDENCE' && e.docType !== 'evidence'
      )
    );

    return res.json({ case_id: req.params.id, evidenceId, trail: fullTrail });
  } catch (err) {
    return res.status(500).json({ error: err.message || String(err) });
  }
});

/** POST /api/cases/:id/verify — recompute hash + ValidateEvidence */
router.post('/verify', async (req, res) => {
  try {
    const result = await orchestratorService.verifyEvidence(req.params.id);
    return res.json(result);
  } catch (err) {
    const status = Number(err.status) || 500;
    return res.status(status).json({ error: err.message || String(err) });
  }
});

module.exports = router;

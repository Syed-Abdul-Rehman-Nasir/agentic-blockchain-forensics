'use strict';

/**
 * Master pipeline: AI analysis first, blockchain commit last (async, non-blocking).
 * Committee note: a Fabric failure must never prevent analysis results from reaching the UI.
 */

const aiService = require('./aiService');
const fabricService = require('./chainRouter');
const fs = require('fs');
const {
  evidenceIdForCase,
  imageNameFromPath,
  utcNow,
} = require('./hashService');
const { POLL_INTERVAL_MS, ANALYSIS_TIMEOUT_MS } = require('../config/config');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Track in-flight investigations so status can expose blockchain phase.
 * Map: caseId -> { phase, error?, startedAt }
 */
const investigations = new Map();

function getInvestigation(caseId) {
  return investigations.get(caseId) || null;
}

async function pollUntilDone(caseId) {
  const deadline = Date.now() + ANALYSIS_TIMEOUT_MS;
  while (Date.now() < deadline) {
    const status = await aiService.getStatus(caseId);
    if (status.status === 'complete' || status.status === 'error') {
      return status;
    }
    await sleep(POLL_INTERVAL_MS);
  }
  throw new Error(`Analysis timed out after ${ANALYSIS_TIMEOUT_MS}ms for ${caseId}`);
}

/**
 * Commit evidence + ANALYSIS_COMPLETE log AFTER analysis has persisted to SQLite.
 * Errors are logged only — never thrown to the caller.
 */
async function commitBlockchain(caseId, status, artifacts) {
  const evidenceId = evidenceIdForCase(caseId);
  const now = utcNow();
  const acqHash = status.acquisition_hash || '';
  const sysHash = status.system_hash || '';
  const imageName = imageNameFromPath(status.image_path);
  const counts = (artifacts && artifacts.counts) || {};
  const totalArtifacts =
    (counts.registry || 0) +
    (counts.events || 0) +
    (counts.browser || 0) +
    (counts.prefetch || 0);

  try {
    await fabricService.storeEvidence(
      evidenceId,
      acqHash,
      sysHash,
      imageName,
      caseId,
      now
    );
  } catch (err) {
    // Duplicate evidence on re-run is acceptable; log and continue to audit action
    console.error('[orchestrator] storeEvidence failed (non-fatal):', err.message || err);
  }

  try {
    await fabricService.logAnalystAction(
      evidenceId,
      'ai-system',
      'ANALYSIS_COMPLETE',
      `${totalArtifacts} artifacts extracted`,
      now
    );
  } catch (err) {
    console.error('[orchestrator] logAnalystAction failed (non-fatal):', err.message || err);
  }
}

/**
 * Full investigation: start AI → poll → then blockchain (never blocks result availability).
 */
async function runInvestigation(caseId, imagePath) {
  investigations.set(caseId, { phase: 'analysing', startedAt: utcNow() });
  try {
    await aiService.startAnalysis(caseId, imagePath);
    const status = await pollUntilDone(caseId);

    if (status.status === 'error') {
      investigations.set(caseId, {
        phase: 'error',
        error: 'AI analysis reported error',
        startedAt: investigations.get(caseId)?.startedAt,
      });
      return { caseId, status, blockchain: 'skipped' };
    }

    let artifacts = null;
    let threats = null;
    try {
      artifacts = await aiService.getArtifacts(caseId);
      threats = await aiService.getThreats(caseId);
    } catch (err) {
      console.error('[orchestrator] fetch artifacts/threats failed:', err.message || err);
    }

    // Blockchain is the LAST step and must not fail the investigation
    investigations.set(caseId, { phase: 'blockchain', startedAt: investigations.get(caseId)?.startedAt });
    await commitBlockchain(caseId, status, artifacts);
    investigations.set(caseId, {
      phase: 'done',
      startedAt: investigations.get(caseId)?.startedAt,
      finishedAt: utcNow(),
    });

    return {
      caseId,
      status,
      artifacts,
      threats,
      blockchain: 'attempted',
    };
  } catch (err) {
    console.error('[orchestrator] runInvestigation failed:', err.message || err);
    investigations.set(caseId, {
      phase: 'error',
      error: String(err.message || err),
      startedAt: investigations.get(caseId)?.startedAt,
    });
    // Do not rethrow — fire-and-forget callers must not crash the process
    return { caseId, error: String(err.message || err) };
  }
}

/**
 * Log every investigator chat question to the on-chain audit trail (non-fatal).
 */
async function logChatAction(caseId, question) {
  const evidenceId = evidenceIdForCase(caseId);
  const now = utcNow();
  try {
    await fabricService.logAnalystAction(
      evidenceId,
      'investigator',
      'QUERY',
      String(question || '').slice(0, 500),
      now
    );
    return { logged: true };
  } catch (err) {
    console.error('[orchestrator] logChatAction failed (non-fatal):', err.message || err);
    return { logged: false, error: String(err.message || err) };
  }
}

/**
 * Recompute system hash via Python, then ValidateEvidence on-chain.
 * Throws errors with .status (404/400/500) and actionable messages for the UI.
 */
async function verifyEvidence(caseId) {
  let status;
  try {
    status = await aiService.getStatus(caseId);
  } catch (err) {
    if (err.status === 404) {
      const e = new Error(
        `Case "${caseId}" was not found. It may have been removed from the database.`
      );
      e.status = 404;
      throw e;
    }
    throw err;
  }

  const imagePath = status.image_path;
  if (!imagePath) {
    const e = new Error(
      `Case "${caseId}" has no disk image path. Create a new case and select the image with Browse.`
    );
    e.status = 400;
    throw e;
  }

  if (!fs.existsSync(imagePath)) {
    const e = new Error(
      `Disk image not found at "${imagePath}". Keep the forensic image at this path after creating the case, or create a new case and select the image again.`
    );
    e.status = 404;
    throw e;
  }

  let hashResult;
  try {
    hashResult = await aiService.verifyHash(imagePath);
  } catch (err) {
    if (err.status === 404) {
      const e = new Error(
        `Could not re-hash the disk image at "${imagePath}". ${err.message}`
      );
      e.status = 404;
      throw e;
    }
    throw err;
  }

  const evidenceId = evidenceIdForCase(caseId);
  let validation;
  try {
    validation = await fabricService.validateEvidence(
      evidenceId,
      hashResult.system_hash
    );
  } catch (err) {
    const msg = String(err.message || err);
    if (/does not exist/i.test(msg)) {
      const e = new Error(
        `No sealed evidence on the ledger for ${evidenceId}. Wait until analysis finishes (blockchain commit), then verify again.`
      );
      e.status = 404;
      throw e;
    }
    if (err.status === 503 || /peer unreachable|start-fabric|TLS cert not found|MSP material missing/i.test(msg)) {
      const e = new Error(msg);
      e.status = err.status || 503;
      throw e;
    }
    const e = new Error(`Ledger validation failed: ${msg}`);
    e.status = err.status || 500;
    throw e;
  }

  let evidenceRecord = null;
  try {
    evidenceRecord = await fabricService.getEvidence(evidenceId);
  } catch {
    // Non-fatal — verify result must still return
  }

  const recomputedHash = hashResult.system_hash;
  const storedHash = validation.storedHash;
  const isValid = validation.isValid;
  const tampered = validation.tampered;

  const result = {
    caseId,
    evidenceId,
    recomputedHash,
    storedHash,
    acquisitionHash: evidenceRecord ? evidenceRecord.acquisitionHash || '' : '',
    imageName: evidenceRecord ? evidenceRecord.imageName || '' : '',
    sealedAt: evidenceRecord ? evidenceRecord.timestamp || '' : '',
    submittedBy: evidenceRecord ? evidenceRecord.submittedBy || '' : '',
    isValid,
    tampered,
  };

  // Log verify outcome to audit chain — non-fatal
  try {
    const action = isValid && !tampered ? 'VERIFY_PASS' : 'VERIFY_FAIL';
    const details = isValid
      ? `Integrity confirmed. SystemHash match verified.`
      : `Hash mismatch detected. Stored: ${(storedHash || '').slice(0, 16)}… Recomputed: ${(recomputedHash || '').slice(0, 16)}…`;
    await fabricService.logAnalystAction(
      evidenceId,
      'investigator',
      action,
      details,
      utcNow()
    );
  } catch (logErr) {
    console.warn('[verifyEvidence] Could not log verify action:', logErr.message);
  }

  return result;
}

module.exports = {
  runInvestigation,
  logChatAction,
  verifyEvidence,
  getInvestigation,
  commitBlockchain,
};

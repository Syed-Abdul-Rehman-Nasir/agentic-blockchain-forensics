'use strict';

// Case lifecycle HTTP routes: create, list, status, and start analysis.

const express = require('express');
const aiService = require('../services/aiService');
const orchestratorService = require('../services/orchestratorService');
const { sendRouteError } = require('../utils/httpError');

const router = express.Router();

/** POST /api/cases — create case in Python SQLite */
router.post('/', async (req, res) => {
  try {
    const { name, image_path, case_id } = req.body || {};
    if (!name || !image_path) {
      return res.status(400).json({ error: 'name and image_path are required' });
    }
    const result = await aiService.createCase(name, image_path, case_id);
    return res.status(201).json(result);
  } catch (err) {
    return sendRouteError(res, err);
  }
});

/** GET /api/cases — list all cases */
router.get('/', async (_req, res) => {
  try {
    const result = await aiService.listCases();
    return res.json(result);
  } catch (err) {
    return sendRouteError(res, err);
  }
});

/** POST /api/cases/:id/analyse — fire-and-forget investigation */
router.post('/:id/analyse', async (req, res) => {
  const caseId = req.params.id;
  try {
    let imagePath = req.body?.image_path;
    if (!imagePath) {
      const status = await aiService.getStatus(caseId).catch(() => null);
      imagePath = status?.image_path;
    }
    if (!imagePath) {
      const c = await aiService.getCase(caseId);
      imagePath = c.image_path;
    }
    if (!imagePath) {
      return res.status(400).json({ error: 'image_path required' });
    }

    // Do not await — blockchain and analysis must not block this response
    setImmediate(() => {
      orchestratorService.runInvestigation(caseId, imagePath).catch((err) => {
        console.error('[cases.analyse] background error:', err.message || err);
      });
    });

    return res.status(202).json({
      status: 'accepted',
      case_id: caseId,
      message: 'Investigation started; poll GET /api/cases/:id/status',
    });
  } catch (err) {
    return sendRouteError(res, err);
  }
});

/** GET /api/cases/:id/status */
router.get('/:id/status', async (req, res) => {
  try {
    const status = await aiService.getStatus(req.params.id);
    const inv = orchestratorService.getInvestigation(req.params.id);
    return res.json({ ...status, investigation: inv });
  } catch (err) {
    return sendRouteError(res, err);
  }
});

/** GET /api/cases/:id/artifacts */
router.get('/:id/artifacts', async (req, res) => {
  try {
    const data = await aiService.getArtifacts(req.params.id);
    return res.json(data);
  } catch (err) {
    return sendRouteError(res, err);
  }
});

/** GET /api/cases/:id/threats */
router.get('/:id/threats', async (req, res) => {
  try {
    const data = await aiService.getThreats(req.params.id);
    return res.json(data);
  } catch (err) {
    return sendRouteError(res, err);
  }
});

module.exports = router;

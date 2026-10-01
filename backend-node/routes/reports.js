'use strict';

// Report route: returns the generated HTML forensic report for a case.

const express = require('express');
const aiService = require('../services/aiService');

const router = express.Router({ mergeParams: true });

/** GET /api/cases/:id/report — HTML forensic report */
router.get('/', async (req, res) => {
  try {
    const data = await aiService.getReport(req.params.id);
    const format = (req.query.format || 'json').toLowerCase();
    if (format === 'html' && data.html) {
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      return res.send(data.html);
    }
    return res.json(data);
  } catch (err) {
    const status = err.response?.status || 500;
    return res.status(status).json({
      error: err.response?.data?.detail || err.message,
    });
  }
});

module.exports = router;

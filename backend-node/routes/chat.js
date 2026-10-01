'use strict';

// Case-scoped chat route: forwards investigator questions to the AI service.

const express = require('express');
const aiService = require('../services/aiService');
const orchestratorService = require('../services/orchestratorService');

const router = express.Router({ mergeParams: true });

/**
 * POST /api/cases/:id/chat
 * Answer via RAG, then log the question to the mock tamper-evident chain (non-fatal).
 */
router.post('/', async (req, res) => {
  const caseId = req.params.id;
  const question = req.body?.question;
  if (!question) {
    return res.status(400).json({ error: 'question is required' });
  }
  try {
    const answer = await aiService.chat(caseId, question);
    // Blockchain audit of investigator questions — never fail the chat response
    const audit = await orchestratorService.logChatAction(caseId, question);
    return res.json({ ...answer, audit });
  } catch (err) {
    const status = err.response?.status || 500;
    return res.status(status).json({
      error: err.response?.data?.detail || err.message,
    });
  }
});

module.exports = router;

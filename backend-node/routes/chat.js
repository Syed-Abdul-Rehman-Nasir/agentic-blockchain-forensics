'use strict';

// Case-scoped chat route: forwards investigator questions to the AI service.

const express = require('express');
const aiService = require('../services/aiService');
const orchestratorService = require('../services/orchestratorService');
const { sendRouteError } = require('../utils/httpError');

const router = express.Router({ mergeParams: true });

const MAX_QUESTION_CHARS = 2000;

/**
 * POST /api/cases/:id/chat
 * Answer via RAG, then log the question to the mock tamper-evident chain (non-fatal).
 */
router.post('/', async (req, res) => {
  const caseId = req.params.id;
  const question = String(req.body?.question ?? '').trim();
  if (!question) {
    return res.status(400).json({ error: 'question is required' });
  }
  if (question.length > MAX_QUESTION_CHARS) {
    return res.status(400).json({
      error: `question must be at most ${MAX_QUESTION_CHARS} characters`,
    });
  }
  try {
    const answer = await aiService.chat(caseId, question);
    // Blockchain audit of investigator questions — never fail the chat response
    const audit = await orchestratorService.logChatAction(caseId, question);
    return res.json({ ...answer, audit });
  } catch (err) {
    return sendRouteError(res, err);
  }
});

module.exports = router;
module.exports.MAX_QUESTION_CHARS = MAX_QUESTION_CHARS;

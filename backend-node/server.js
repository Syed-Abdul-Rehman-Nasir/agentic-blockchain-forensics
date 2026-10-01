'use strict';

/**
 * Express entry point — single UI-facing API on port 3000.
 * UI → Node → (Python AI service OR Fabric SDK).
 */

require('dotenv').config();
// Port-fix endpoints written by scripts/start-fabric.sh (overrides PEER_ENDPOINT when present)
require('dotenv').config({ path: require('path').join(__dirname, '.fabric-endpoints.env'), override: true });

const express = require('express');
const cors = require('cors');
const { PORT, AI_SERVICE_URL } = require('./config/config');

const casesRouter = require('./routes/cases');
const chatRouter = require('./routes/chat');
const blockchainRouter = require('./routes/blockchain');
const reportsRouter = require('./routes/reports');
const configRouter = require('./routes/config');
const aiService = require('./services/aiService');
const fabricService = require('./services/chainRouter');
const { evidenceIdForCase } = require('./services/hashService');
const axios = require('axios');

const app = express();

app.use(cors());
app.use(express.json({ limit: '2mb' }));

app.get('/health', async (_req, res) => {
  const aiInfo = {
    model: null,
    temperature: null,
    embeddingModel: null,
    vectorDb: null,
  };
  try {
    const { data } = await axios.get(`${AI_SERVICE_URL}/health`, { timeout: 3000 });
    if (data && typeof data === 'object') {
      aiInfo.model = data.model || null;
      aiInfo.temperature = data.temperature ?? null;
      aiInfo.embeddingModel = data.embedding_model || null;
      aiInfo.vectorDb = data.vector_db || null;
    }
  } catch {
    /* Python AI service unavailable — leave aiInfo nulls */
  }
  res.json({
    status: 'ok',
    port: PORT,
    ai_service: AI_SERVICE_URL,
    aiInfo,
  });
});

/** Sealed-on-chain overview for all cases (no hash recompute). */
app.get('/api/blockchain/integrity-overview', async (_req, res) => {
  try {
    const casesResult = await aiService.listCases();
    const cases = casesResult.cases || [];

    const results = await Promise.allSettled(
      cases.map(async (c) => {
        const evidenceId = evidenceIdForCase(c.case_id);
        const evidence = await Promise.resolve(fabricService.getEvidence(evidenceId)).catch(
          () => null
        );
        return {
          case_id: c.case_id,
          name: c.name,
          status: c.status,
          sealed: evidence !== null,
          sealedAt: evidence ? evidence.timestamp : null,
          submittedBy: evidence ? evidence.submittedBy : null,
        };
      })
    );

    const overview = results
      .map((r) => (r.status === 'fulfilled' ? r.value : null))
      .filter(Boolean);
    return res.json({ overview });
  } catch (err) {
    return res.status(500).json({ error: err.message || String(err) });
  }
});

app.use('/api/config', configRouter);
app.use('/api/cases', casesRouter);
// Nested under /api/cases/:id/...
app.use('/api/cases/:id/chat', chatRouter);
app.use('/api/cases/:id', blockchainRouter);
app.use('/api/cases/:id/report', reportsRouter);

app.use((err, _req, res, _next) => {
  console.error('[server]', err);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Forensic backend listening on http://0.0.0.0:${PORT}`);
  console.log(`AI service URL: ${AI_SERVICE_URL}`);
});

module.exports = app;

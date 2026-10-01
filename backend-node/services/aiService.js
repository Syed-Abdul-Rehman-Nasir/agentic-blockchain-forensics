'use strict';

/**
 * HTTP client for the Python FastAPI AI service (port 8000).
 */

const axios = require('axios');
const { AI_SERVICE_URL } = require('../config/config');

const client = axios.create({
  baseURL: AI_SERVICE_URL,
  timeout: 600000, // verify_hash / report / chat can be slow
});

/** Surface FastAPI detail/error instead of opaque "Request failed with status code N". */
client.interceptors.response.use(
  (res) => res,
  (err) => {
    const status = err.response?.status;
    const data = err.response?.data;
    let detail = data?.detail ?? data?.error;
    if (Array.isArray(detail)) {
      detail = detail
        .map((d) => (typeof d === 'string' ? d : d.msg || JSON.stringify(d)))
        .join('; ');
    }
    const wrapped = new Error(
      detail || err.message || `AI service request failed (${status || 'unknown'})`
    );
    wrapped.status = status || 500;
    wrapped.data = data;
    return Promise.reject(wrapped);
  }
);

async function createCase(name, imagePath, caseId) {
  const body = { name, image_path: imagePath };
  if (caseId) body.case_id = caseId;
  const { data } = await client.post('/cases', body);
  return data;
}

async function listCases() {
  const { data } = await client.get('/cases');
  return data;
}

async function startAnalysis(caseId, imagePath) {
  const { data } = await client.post('/analyse', {
    case_id: caseId,
    image_path: imagePath,
  });
  return data;
}

async function getStatus(caseId) {
  const { data } = await client.get(`/status/${encodeURIComponent(caseId)}`);
  return data;
}

async function chat(caseId, question) {
  const { data } = await client.post('/chat', {
    case_id: caseId,
    question,
  });
  return data;
}

async function getArtifacts(caseId) {
  const { data } = await client.get(`/artifacts/${encodeURIComponent(caseId)}`);
  return data;
}

async function getThreats(caseId) {
  const { data } = await client.get(`/threats/${encodeURIComponent(caseId)}`);
  return data;
}

async function getReport(caseId) {
  const { data } = await client.get(`/report/${encodeURIComponent(caseId)}`);
  return data;
}

async function verifyHash(imagePath) {
  const { data } = await client.post('/verify_hash', { image_path: imagePath });
  return data;
}

async function getCase(caseId) {
  const { data } = await client.get(`/cases/${encodeURIComponent(caseId)}`);
  return data;
}

module.exports = {
  createCase,
  listCases,
  startAnalysis,
  getStatus,
  chat,
  getArtifacts,
  getThreats,
  getReport,
  verifyHash,
  getCase,
};

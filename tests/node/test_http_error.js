'use strict';

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');
const {
  statusFromError,
  messageFromError,
} = require('../../backend-node/utils/httpError');
const { MAX_QUESTION_CHARS } = require('../../backend-node/routes/chat');

describe('httpError helpers', () => {
  it('prefers aiService .status over Axios response.status', () => {
    const err = new Error('Case not found');
    err.status = 404;
    err.response = { status: 500, data: { detail: 'ignored' } };
    assert.equal(statusFromError(err), 404);
  });

  it('falls back to response.status then 500', () => {
    assert.equal(statusFromError({ response: { status: 400 } }), 400);
    assert.equal(statusFromError({}), 500);
  });

  it('surfaces FastAPI detail when present', () => {
    const err = new Error('wrapper');
    err.response = { data: { detail: 'missing case' } };
    assert.equal(messageFromError(err), 'missing case');
  });
});

describe('chat question limits', () => {
  it('exports a finite positive maximum length', () => {
    assert.equal(MAX_QUESTION_CHARS, 2000);
  });
});

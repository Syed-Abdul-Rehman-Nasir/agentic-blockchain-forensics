'use strict';

/**
 * Map errors from aiService / Axios into Express status + JSON body fields.
 * aiService attaches `.status` after intercepting FastAPI responses.
 */
function statusFromError(err, fallback = 500) {
  const status = err?.status || err?.response?.status;
  if (typeof status === 'number' && status >= 400 && status < 600) {
    return status;
  }
  return fallback;
}

function messageFromError(err, fallback = 'Internal server error') {
  const detail = err?.response?.data?.detail || err?.data?.detail;
  if (typeof detail === 'string' && detail.trim()) {
    return detail;
  }
  if (typeof err?.message === 'string' && err.message.trim()) {
    return err.message;
  }
  return fallback;
}

function sendRouteError(res, err, fallbackStatus = 500) {
  const status = statusFromError(err, fallbackStatus);
  return res.status(status).json({ error: messageFromError(err) });
}

module.exports = {
  statusFromError,
  messageFromError,
  sendRouteError,
};

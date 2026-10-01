'use strict';

/**
 * Preload bridge — expose a minimal safe API to the renderer.
 * Path translation ensures Windows-picked images become WSL paths for the backend.
 */

const { contextBridge, ipcRenderer } = require('electron');

const API_BASE = 'http://localhost:3000/api';
const HEALTH_URL = 'http://localhost:3000/health';

/**
 * Convert a Windows or UNC path to a WSL-readable path for Python/pytsk3.
 */
function toWslPath(input) {
  if (!input || typeof input !== 'string') return input;
  let p = input.trim();

  // Already a Linux path
  if (p.startsWith('/')) return p;

  // \\wsl$\Distro\home\... or \\wsl.localhost\Distro\home\...
  const wslUnc = p.match(/^\\\\wsl(?:\.localhost)?\\[^\\]+\\(.*)$/i);
  if (wslUnc) {
    return '/' + wslUnc[1].replace(/\\/g, '/');
  }

  // C:\Users\... → /mnt/c/Users/...
  const drive = p.match(/^([A-Za-z]):[\\/](.*)$/);
  if (drive) {
    return `/mnt/${drive[1].toLowerCase()}/${drive[2].replace(/\\/g, '/')}`;
  }

  return p.replace(/\\/g, '/');
}

async function fetchAPI(endpoint, options = {}) {
  const path = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  const url = endpoint.startsWith('http') ? endpoint : `${API_BASE}${path}`;
  const opts = {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
  };
  if (opts.body && typeof opts.body === 'object') {
    opts.body = JSON.stringify(opts.body);
  }
  const res = await fetch(url, opts);
  const text = await res.text();
  let data = null;
  try {
    data = text ? JSON.parse(text) : null;
  } catch {
    data = { raw: text };
  }
  if (!res.ok) {
    const err = new Error(
      (data && (data.error || data.detail)) || `HTTP ${res.status}`
    );
    err.status = res.status;
    err.data = data;
    throw err;
  }
  return data;
}

async function healthCheck() {
  try {
    const res = await fetch(HEALTH_URL, { method: 'GET' });
    if (!res.ok) return { status: 'down' };
    return await res.json();
  } catch {
    return { status: 'down' };
  }
}

contextBridge.exposeInMainWorld('api', {
  selectFile: () => ipcRenderer.invoke('dialog:openFile'),
  fetchAPI,
  healthCheck,
  toWslPath,
  openExternal: (url) => ipcRenderer.invoke('shell:openExternal', url),
  openReportHtml: (html, caseId) =>
    ipcRenderer.invoke('report:openHtml', html, caseId),
  saveReportHtml: (html, caseId) =>
    ipcRenderer.invoke('report:saveHtml', html, caseId),
  API_BASE,
});
